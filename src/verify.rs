//! verification for NONOS bootloader capsules

#![allow(dead_code)]

use ed25519_dalek::{PublicKey, Signature, Verifier};
use crate::log::logger::{log_info, log_warn};
use blake3;
use sha2::{Digest, Sha256};

/// Domain separation labels for hashing
const DS_CAPSULE_COMMIT: &str = "NONOS:CAPSULE:COMMITMENT:v1";
const DS_PROGRAM_HASH: &str = "NONOS:ZK:PROGRAM:v1";

/// Trusted public key ring.
/// PUBLIC KEY WILL BE ADDED SOON.
const TRUSTED_PUBLIC_KEYS: &[&[u8; 32]] = &[
    // PUBLIC KEY SOON ADDED
    // Ed25519 public key as a `[u8; 32]`.
];

/// Ed25519 signature verification using ed25519-dalek
pub fn verify_ed25519_signature(message: &[u8], signature_bytes: &[u8]) -> Result<bool, &'static str> {
    if signature_bytes.len() != 64 { return Err("Signature must be 64 bytes"); }
    if message.is_empty() { return Err("Cannot verify signature of empty message"); }

    let signature = Signature::from_bytes(signature_bytes).map_err(|_| "Invalid signature format")?;
    for (idx, key_bytes) in TRUSTED_PUBLIC_KEYS.iter().enumerate() {
        let public_key = match PublicKey::from_bytes(key_bytes) {
            Ok(pk) => pk,
            Err(_) => {
                log_warn("verify", &format!("Invalid public key #{}", idx));
                continue;
            }
        };
        if public_key.verify(message, &signature).is_ok() {
            log_info("verify", &format!("Signature verified with key #{}", idx));
            return Ok(true);
        }
    }
    Err("Signature verification failed")
}

pub enum CapsuleVerification {
    StaticVerified,
    Failed(&'static str),
}

pub struct CapsuleMetadata {
    pub version: u8,
    pub flags: u8,
    pub offset_sig: usize,
    pub offset_payload: usize,
    pub len_sig: usize,
    pub len_payload: usize,
}

/// Verify capsule with static signature
pub fn verify_capsule(blob: &[u8], meta: &CapsuleMetadata) -> CapsuleVerification {
    if let Err(e) = validate_meta(blob, meta) {
        log_warn("verify", e);
        return CapsuleVerification::Failed(e);
    }

    if verify_signature(blob, meta) {
        log_info("verify", "Static signature accepted");
        CapsuleVerification::StaticVerified
    } else {
        CapsuleVerification::Failed("signature verification failed")
    }
}

/// Signature verification path for static capsules
fn verify_signature(blob: &[u8], meta: &CapsuleMetadata) -> bool {
    match slices_for(blob, meta) {
        Ok((sig_blob, payload)) => match verify_ed25519_signature(payload, sig_blob) {
            Ok(true) => true,
            Ok(false) | Err(_) => false,
        },
        Err(_) => false,
    }
}

/// Validate offsets and produce borrowed slices
fn slices_for<'a>(blob: &'a [u8], meta: &CapsuleMetadata) -> Result<(&'a [u8], &'a [u8]), &'static str> {
    let sig_start = meta.offset_sig;
    let sig_end = sig_start.checked_add(meta.len_sig).ok_or("sig len overflow")?;
    let pay_start = meta.offset_payload;
    let pay_end = pay_start.checked_add(meta.len_payload).ok_or("payload len overflow")?;
    if sig_end > blob.len() || pay_end > blob.len() { return Err("offsets out of bounds"); }
    if meta.len_sig == 0 || meta.len_payload == 0 { return Err("empty signature or payload"); }
    if ranges_overlap(sig_start, sig_end, pay_start, pay_end) && !(sig_start == pay_start && sig_end == pay_end) {
        return Err("signature/payload overlap");
    }
    Ok((&blob[sig_start..sig_end], &blob[pay_start..pay_end]))
}

/// Early metadata validation
fn validate_meta(blob: &[u8], meta: &CapsuleMetadata) -> Result<(), &'static str> {
    if blob.is_empty() { return Err("empty capsule blob"); }
    if meta.len_sig > blob.len() || meta.len_payload > blob.len() { return Err("declared lengths exceed blob"); }
    Ok(())
}

fn ranges_overlap(a0: usize, a1: usize, b0: usize, b1: usize) -> bool {
    a0 < b1 && b0 < a1
}

/// BLAKE3 commit (domain-separated)
pub fn blake3_commit(payload: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DS_CAPSULE_COMMIT);
    h.update(payload);
    *h.finalize().as_bytes()
}

/// SHA-256 (for compatibility)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Stable program hash for zkVM attestation (domain-separated BLAKE3)
pub fn known_program_hash() -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DS_PROGRAM_HASH);
    h.update(b"zkmod-attestation-program-v1");
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commit_is_32_bytes_and_changes() {
        let a = blake3_commit(b"hello");
        let b = blake3_commit(b"hello!");
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }
    #[test]
    fn meta_validation_catches_bounds() {
        let blob = [0u8; 64];
        let bad = CapsuleMetadata {
            version: 1,
            flags: 0,
            offset_sig: 60,
            len_sig: 8,
            offset_payload: 0,
            len_payload: 16,
        };
        assert!(validate_meta(&blob, &bad).is_err());
    }
}
