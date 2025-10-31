#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::convert::TryInto;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use blake3;
use crate::verify::CapsuleMetadata;
use crate::log::logger::{log_info, log_warn, log_error, log_debug};

#[cfg(feature = "ed25519")]
use ed25519_dalek::{Signature, VerifyingKey, SIGNATURE_LENGTH};

pub const PK_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub type KeyId = [u8; 32];

struct KeyEntry {
    id: KeyId,
    pk: VerifyingKey,
}

struct KeyStore {
    keys: Vec<KeyEntry>,
}

static INIT_DONE: AtomicBool = AtomicBool::new(false);
static KEYS: Mutex<Option<KeyStore>> = Mutex::new(None);

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    Bounds,
    MalformedSignature,
    KeyNotFound,
    InvalidSignature,
    NotInitialized,
}

pub enum SignatureResult {
    Valid(KeyId),
    Err(VerifyError),
}

pub struct SignatureVerifier;

impl SignatureVerifier {
    pub fn derive_keyid(pubkey: &[u8; PK_LEN]) -> KeyId {
        let mut h = blake3::Hasher::new_derive_key("NONOS:KEYID:ED25519:v1");
        h.update(pubkey);
        let out = h.finalize();
        let bytes = out.as_bytes();
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes[0..32]);
        id
    }

    pub fn init_with_keys(entries: &[(KeyId, &[u8; PK_LEN])]) -> Result<(), &'static str> {
        let mut ks_vec = Vec::with_capacity(entries.len());
        for (id, kbytes) in entries.iter() {
            let pk = VerifyingKey::from_bytes(kbytes).map_err(|_| "invalid public key bytes")?;
            ks_vec.push(KeyEntry { id: *id, pk });
        }
        let mut guard = KEYS.lock();
        *guard = Some(KeyStore { keys: ks_vec });
        INIT_DONE.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn init_noalloc(buffer: &mut [([u8; PK_LEN], [u8; PK_LEN])]) -> Result<(), &'static str> {
        let mut ks_vec = Vec::with_capacity(buffer.len());
        for &(id_src, pk_src) in buffer.iter() {
            let pk = VerifyingKey::from_bytes(&pk_src).map_err(|_| "invalid public key bytes")?;
            let id = Self::derive_keyid(&pk_src);
            ks_vec.push(KeyEntry { id, pk });
        }
        let mut guard = KEYS.lock();
        *guard = Some(KeyStore { keys: ks_vec });
        INIT_DONE.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn add_key(pubkey: &[u8; PK_LEN]) -> Result<KeyId, &'static str> {
        let pk = VerifyingKey::from_bytes(pubkey).map_err(|_| "invalid public key bytes")?;
        let id = Self::derive_keyid(pubkey);
        let mut guard = KEYS.lock();
        if guard.is_none() {
            *guard = Some(KeyStore { keys: Vec::new() });
        }
        let ks = guard.as_mut().unwrap();
        for e in ks.keys.iter() {
            if e.id == id {
                return Ok(id);
            }
        }
        ks.keys.push(KeyEntry { id, pk });
        INIT_DONE.store(true, Ordering::SeqCst);
        Ok(id)
    }

    pub fn remove_key(id: &KeyId) -> Result<(), &'static str> {
        let mut guard = KEYS.lock();
        let ks = guard.as_mut().ok_or("not initialized")?;
        ks.keys.retain(|e| &e.id != id);
        Ok(())
    }

    pub fn verify_with_claimed_key(data: &[u8], sig_bytes: &[u8], claimed_id: &KeyId) -> SignatureResult {
        if sig_bytes.len() != SIG_LEN { return SignatureResult::Err(VerifyError::MalformedSignature); }
        let sig = Signature::from_bytes(sig_bytes.try_into().unwrap()).map_err(|_| SignatureResult::Err(VerifyError::MalformedSignature));
        if let Err(e) = sig { return e; }
        let sig = sig.unwrap();
        if !INIT_DONE.load(Ordering::SeqCst) { return SignatureResult::Err(VerifyError::NotInitialized); }
        let guard = KEYS.lock();
        let ks = guard.as_ref().ok_or(SignatureResult::Err(VerifyError::NotInitialized)).map_err(|e| match e { SignatureResult::Err(err) => err, _ => VerifyError::NotInitialized }).unwrap_err();
        let ks = guard.as_ref().unwrap();
        for e in ks.keys.iter() {
            if &e.id == claimed_id {
                return if e.pk.verify(data, &sig).is_ok() { SignatureResult::Valid(e.id) } else { SignatureResult::Err(VerifyError::InvalidSignature) };
            }
        }
        SignatureResult::Err(VerifyError::KeyNotFound)
    }

    pub fn verify_against_all(data: &[u8], sig_bytes: &[u8]) -> SignatureResult {
        if sig_bytes.len() != SIG_LEN { return SignatureResult::Err(VerifyError::MalformedSignature); }
        let sig = Signature::from_bytes(sig_bytes.try_into().unwrap()).map_err(|_| SignatureResult::Err(VerifyError::MalformedSignature));
        if let Err(e) = sig { return e; }
        let sig = sig.unwrap();
        if !INIT_DONE.load(Ordering::SeqCst) { return SignatureResult::Err(VerifyError::NotInitialized); }
        let guard = KEYS.lock();
        let ks = guard.as_ref().ok_or(SignatureResult::Err(VerifyError::NotInitialized)).map_err(|e| match e { SignatureResult::Err(err) => err, _ => VerifyError::NotInitialized }).unwrap_err();
        let ks = guard.as_ref().unwrap();
        for e in ks.keys.iter() {
            if e.pk.verify(data, &sig).is_ok() {
                return SignatureResult::Valid(e.id);
            }
        }
        SignatureResult::Err(VerifyError::InvalidSignature)
    }
}

pub fn verify_signature_full(blob: &[u8], meta: &CapsuleMetadata) -> Result<KeyId, VerifyError> {
    let sig_start = meta.offset_sig;
    let sig_end = sig_start.checked_add(meta.len_sig).ok_or(VerifyError::Bounds)?;
    let pay_start = meta.offset_payload;
    let pay_end = pay_start.checked_add(meta.len_payload).ok_or(VerifyError::Bounds)?;
    if sig_end > blob.len() || pay_end > blob.len() { return Err(VerifyError::Bounds); }
    let signature_bytes = &blob[sig_start..sig_end];
    let payload_bytes = &blob[pay_start..pay_end];
    if signature_bytes.len() != SIG_LEN { return Err(VerifyError::MalformedSignature); }
    if signature_bytes.iter().all(|&b| b == 0) { return Err(VerifyError::MalformedSignature); }
    match SignatureVerifier::verify_against_all(payload_bytes, signature_bytes) {
        SignatureResult::Valid(id) => Ok(id),
        SignatureResult::Err(VerifyError::MalformedSignature) => Err(VerifyError::MalformedSignature),
        SignatureResult::Err(VerifyError::KeyNotFound) => Err(VerifyError::KeyNotFound),
        SignatureResult::Err(VerifyError::InvalidSignature) => Err(VerifyError::InvalidSignature),
        SignatureResult::Err(VerifyError::NotInitialized) => Err(VerifyError::NotInitialized),
        _ => Err(VerifyError::InvalidSignature),
    }
}

pub fn verify_signature(blob: &[u8], meta: &CapsuleMetadata) -> bool {
    match verify_signature_full(blob, meta) {
        Ok(id) => { log_info("crypto", "signature verified"); log_debug("crypto", "verifier key id available"); true }
        Err(e) => { log_warn("crypto", "signature verification failed"); log_debug("crypto", "verify error"); false }
    }
}

#[cfg(all(test, feature = "host-tests"))]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn rfc8032_test_vec() {
        let pk_bytes = hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sk_and_pk = hex!("9d61b19deffd5a60ba844af492ec2cc4
                              4449c5697b326919703bac031cae7f60
                              d75a980182b10ab7d54bfed3c964073a");
        let msg = b"";
        let sig_bytes = hex!("e5564300c360ac729086e2cc806e828a
                              84877f1eb8e5d974d873e06522490155
                              5fb8821590a33bacc61e39701cf9b46b
                              d25bf5f0595bbe24655141438e7a100b");
        let id = SignatureVerifier::derive_keyid(&pk_bytes.try_into().unwrap());
        SignatureVerifier::init_with_keys(&[(id, &pk_bytes.try_into().unwrap())]).unwrap();
        let res = SignatureVerifier::verify_against_all(msg, &sig_bytes);
        match res {
            SignatureResult::Valid(kid) => assert_eq!(kid, id),
            _ => panic!("rfc8032 vector failed"),
        }
    }

    #[test]
    fn malformed_signature_rejected() {
        let pk_bytes = hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let id = SignatureVerifier::derive_keyid(&pk_bytes.try_into().unwrap());
        SignatureVerifier::init_with_keys(&[(id, &pk_bytes.try_into().unwrap())]).unwrap();
        let bad_sig = [0u8; SIG_LEN];
        let res = SignatureVerifier::verify_against_all(b"hello", &bad_sig);
        match res {
            SignatureResult::Err(VerifyError::MalformedSignature) => (),
            _ => panic!("malformed signature not rejected"),
        }
    }
}
