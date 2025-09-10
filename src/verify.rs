// NØNOS Capsule Verification Pipeline 

#![allow(dead_code)]

use alloc::vec::Vec;
use ed25519_dalek::{PublicKey, Signature, Verifier};

use crate::capsule::zkmeta::requires_zk;
use crate::crypto::sig::verify_signature;          // back with ed25519 
use crate::log::logger::{log_info, log_warn};
use crate::zk::{verify_proof, ZkProof, ZkVerifyResult};

use blake3;
use sha2::{Digest, Sha256}; // optional if need SHA-256 addition elsewhere

/// Domain separation labels
const DS_CAPSULE_COMMIT: &str = "NONOS:CAPSULE:COMMITMENT:v1";
const DS_PROGRAM_HASH:   &str = "NONOS:ZK:PROGRAM:v1";

/// Trusted public key ring - embedded at compile time
/// These keys are used to verify capsule signatures
const TRUSTED_PUBLIC_KEYS: &[&[u8; 32]] = &[
    // Production public key #0 - we replace later with actual deployment keys
    &[
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
    ],
    // Production public key #1 - for key rotation
    &[
        0xe5, 0x29, 0x4e, 0x18, 0x3e, 0x01, 0x73, 0xd9,
        0x46, 0xb4, 0xbd, 0x70, 0x87, 0x0b, 0x28, 0x62,
        0x0d, 0xe3, 0x13, 0xf0, 0x81, 0x2a, 0x3c, 0x1b,
        0x8f, 0x24, 0x9a, 0x43, 0xd1, 0x52, 0x0f, 0x6b
    ],
];

/// Real ed25519 signature verification using ed25519-dalek
/// This provides cryptographically secure verification against trusted keys
pub fn verify_ed25519_signature(message: &[u8], signature_bytes: &[u8]) -> Result<bool, &'static str> {
    if signature_bytes.len() != 64 {
        return Err("Ed25519 signature must be exactly 64 bytes");
    }
    
    if message.is_empty() {
        return Err("Cannot verify signature of empty message");
    }
    
    // Parse the signature
    let signature = Signature::from_bytes(signature_bytes)
        .map_err(|_| "Invalid signature format")?;
    
    // Try verification against each trusted public key
    for (key_index, &key_bytes) in TRUSTED_PUBLIC_KEYS.iter().enumerate() {
        match PublicKey::from_bytes(key_bytes) {
            Ok(public_key) => {
                if public_key.verify(message, &signature).is_ok() {
                    log_info("verify", &alloc::format!("Signature verified with trusted key #{}", key_index));
                    return Ok(true);
                }
            }
            Err(_) => {
                log_warn("verify", &alloc::format!("Invalid public key #{} in trusted ring", key_index));
                continue;
            }
        }
    }
    
    Err("Signature verification failed against all trusted keys")
}

pub enum CapsuleVerification {
    StaticVerified,
    ZkVerified,
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

/// Primary capsule verification entry point
pub fn verify_capsule(blob: &[u8], meta: &CapsuleMetadata) -> CapsuleVerification {
    if let Err(e) = validate_meta(blob, meta) {
        log_warn("verify", e);
        return CapsuleVerification::Failed(e);
    }

    if requires_zk(meta) {
        match extract_zk_proof(blob, meta) {
            Ok(proof) => match verify_proof(&proof) {
                ZkVerifyResult::Valid => {
                    log_info("verify", "ZK proof accepted");
                    CapsuleVerification::ZkVerified
                }
                ZkVerifyResult::Invalid(e)
                | ZkVerifyResult::Unsupported(e)
                | ZkVerifyResult::Error(e) => {
                    log_warn("verify", e);
                    CapsuleVerification::Failed(e)
                }
            },
            Err(e) => {
                log_warn("verify", e);
                CapsuleVerification::Failed(e)
            }
        }
    } else {
        if verify_signature(blob, meta) {
            log_info("verify", "Static signature accepted");
            CapsuleVerification::StaticVerified
        } else {
            CapsuleVerification::Failed("signature verification failed")
        }
    }
}

/// Construct ZkProof from metadata and blob
fn extract_zk_proof(blob: &[u8], meta: &CapsuleMetadata) -> Result<ZkProof, &'static str> {
    let (sig_blob, capsule_payload) = slices_for(blob, meta)?;

    let commitment = blake3_commit(capsule_payload);
    let prog_hash = known_program_hash();

    Ok(ZkProof {
        proof_blob: sig_blob.to_vec(),
        public_inputs: capsule_payload.to_vec(),
        program_hash: prog_hash,
        capsule_commitment: commitment,
    })
}

/// Compute capsule commitment (BLAKE3, domain-separated)
#[inline]
pub fn blake3_commit(payload: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DS_CAPSULE_COMMIT);
    h.update(payload);
    *h.finalize().as_bytes()
}

/// Decide if keep SHA-256 helper kept for compatibility
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Stable program hash for dev boot zkVM (domain-separated BLAKE3).
/// Replace with Halo2 circuit ID hash.
fn known_program_hash() -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DS_PROGRAM_HASH);
    h.update(b"zkmod-attestation-program-v1");
    *h.finalize().as_bytes()
}

/// Validate offsets and produce borrowed slices
#[inline]
fn slices_for<'a>(
    blob: &'a [u8],
    meta: &CapsuleMetadata,
) -> Result<(&'a [u8], &'a [u8]), &'static str> {
    let sig_start = meta.offset_sig;
    let sig_end = sig_start.checked_add(meta.len_sig).ok_or("sig len overflow")?;

    let pay_start = meta.offset_payload;
    let pay_end = pay_start
        .checked_add(meta.len_payload)
        .ok_or("payload len overflow")?;

    if sig_end > blob.len() || pay_end > blob.len() {
        return Err("offsets out of bounds");
    }
    if meta.len_sig == 0 || meta.len_payload == 0 {
        return Err("empty sig or payload");
    }

    // Disallow weird partial overlaps (allow equality if signature covers the whole payload)
    if ranges_overlap(sig_start, sig_end, pay_start, pay_end) && !(sig_start == pay_start && sig_end == pay_end) {
        return Err("sig/payload overlap");
    }

    Ok((&blob[sig_start..sig_end], &blob[pay_start..pay_end]))
}

/// Early metadata validation (lightweight)
#[inline]
fn validate_meta(blob: &[u8], meta: &CapsuleMetadata) -> Result<(), &'static str> {
    if blob.is_empty() {
        return Err("empty capsule blob");
    }
    if meta.len_sig > blob.len() || meta.len_payload > blob.len() {
        return Err("declared lengths exceed blob");
    }
    Ok(())
}

#[inline]
fn ranges_overlap(a0: usize, a1: usize, b0: usize, b1: usize) -> bool {
    a0 < b1 && b0 < a1
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
