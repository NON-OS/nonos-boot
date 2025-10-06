// NØNOS Capsule Verification Pipeline

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use blake3;
use sha2::{Digest, Sha256};
use ed25519_dalek::{PublicKey, Signature, Verifier};

use crate::log::logger::{log_info, log_warn};
use crate::zk::{verify_proof, ZkProof, ZkVerifyResult};

// Use the canonical metadata + helpers from capsule::zkmeta
use crate::capsule::zkmeta::{
    CapsuleMeta,
    requires_zk,
    validate_capsule_layout,
    extract_signature_and_payload,
};

// If other modules still refer to `CapsuleMetadata`, alias it to the canonical type:
pub type CapsuleMetadata = CapsuleMeta;

/// Domain separation labels
const DS_CAPSULE_COMMIT: &str = "NONOS:CAPSULE:COMMITMENT:v1";
const DS_PROGRAM_HASH:   &str = "NONOS:ZK:PROGRAM:v1";

/// Trusted public key ring - embedded at compile time
/// These keys are used to verify capsule signatures
const TRUSTED_PUBLIC_KEYS: &[&[u8; 32]] = &[
    // Production public key #0 - replace with actual deployment key
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

/// Real Ed25519 signature verification using ed25519-dalek.
/// Verifies `message` against the first matching key in `TRUSTED_PUBLIC_KEYS`.
pub fn verify_ed25519_signature(message: &[u8], signature_bytes: &[u8]) -> Result<bool, &'static str> {
    if signature_bytes.len() != 64 {
        return Err("Ed25519 signature must be exactly 64 bytes");
    }
    if message.is_empty() {
        return Err("Cannot verify signature of empty message");
    }

    let signature = Signature::from_bytes(signature_bytes).map_err(|_| "Invalid signature format")?;

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

/// Primary capsule verification entry point.
/// `meta` must be the parsed `CapsuleMeta` for `blob`. Bounds/layout are validated here.
pub fn verify_capsule(blob: &[u8], meta: &CapsuleMetadata) -> CapsuleVerification {
    // Strong bound/layout validation (header size, lengths, non-overlap, etc.)
    if let Err(e) = validate_capsule_layout(blob, meta) {
        log_warn("verify", e);
        return CapsuleVerification::Failed(e);
    }

    if requires_zk(meta) {
        // ZK path: proof is stored in the detached sig region by convention.
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
        // Static signature path: detached signature over payload.
        match extract_signature_and_payload(blob, meta) {
            Ok((sig_blob, payload)) => match verify_ed25519_signature(&payload, &sig_blob) {
                Ok(true) => {
                    log_info("verify", "Static signature accepted");
                    CapsuleVerification::StaticVerified
                }
                Ok(false) => CapsuleVerification::Failed("signature verification failed"),
                Err(e) => {
                    log_warn("verify", e);
                    CapsuleVerification::Failed(e)
                }
            },
            Err(e) => {
                log_warn("verify", e);
                CapsuleVerification::Failed(e)
            }
        }
    }
}

/// Build a `ZkProof` from the capsule blob + metadata.
/// Uses the capsule payload as public input, with a domain-separated BLAKE3 commitment.
fn extract_zk_proof(blob: &[u8], meta: &CapsuleMetadata) -> Result<ZkProof, &'static str> {
    let (sig_blob, capsule_payload) = extract_signature_and_payload(blob, meta)?;
    let commitment = blake3_commit(&capsule_payload);
    let prog_hash = known_program_hash();

    Ok(ZkProof {
        proof_blob: sig_blob,               // proof (or opaque proof-like blob)
        public_inputs: capsule_payload,     // payload committed-to
        program_hash: prog_hash,            // verifier program/circuit hash
        capsule_commitment: commitment,     // blake3 commitment of payload
    })
}

/// Compute capsule commitment (BLAKE3, domain-separated).
#[inline]
pub fn blake3_commit(payload: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DS_CAPSULE_COMMIT);
    h.update(payload);
    *h.finalize().as_bytes()
}

/// SHA-256 helper (e.g., for interop/testing).
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Stable program hash for dev boot zkVM (domain-separated BLAKE3).
/// Replace with circuit ID for your production prover/verifier.
fn known_program_hash() -> [u8; 32] {
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
}
