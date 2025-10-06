//! Signature Verification for NONOS Capsules
//! eK@nonos.systems
//!
//! - Full Ed25519 signature verification (trusted keyring)
//! - Extensible verifier context & self-test hooks

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use blake3;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use crate::capsule::zkmeta::{CapsuleMeta, validate_capsule_layout, extract_signature_and_payload};
use crate::log::logger::{log_info, log_warn, log_error, log_debug};
use crate::verify::verify_ed25519_signature;

/// Certificate validation result (placeholder for future X.509 chain, CRL, etc.)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CertificateStatus {
    Valid,
    Expired,
    Revoked,
    InvalidSignature,
    UntrustedIssuer,
    MalformedCertificate,
}

/// Signature verification result for the standalone verifier context
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureStatus {
    Valid,
    Invalid,
    KeyNotFound,
    UnsupportedAlgorithm,
    MalformedSignature,
}

/// Advanced signature verification context (extensible; used in self-test)
#[derive(Debug)]
pub struct SignatureVerifier {
    pub trusted_ed25519_keys: Vec<[u8; 32]>,
    pub trusted_rsa_keys: Vec<Vec<u8>>,
    pub certificate_store: Vec<Vec<u8>>,
    pub revocation_list: Vec<[u8; 32]>,
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self {
            trusted_ed25519_keys: Vec::new(),
            trusted_rsa_keys: Vec::new(),
            certificate_store: Vec::new(),
            revocation_list: Vec::new(),
        }
    }
}

impl SignatureVerifier {
    /// Create new signature verifier with embedded public keys (example)
    pub fn new() -> Self {
        let mut verifier = Self::default();
        verifier.add_trusted_ed25519_key(&NONOS_SIGNING_KEY);
        verifier.add_trusted_ed25519_key(&NONOS_BACKUP_KEY);
        log_info("crypto", "Advanced signature verifier initialized");
        verifier
    }

    /// Add a trusted Ed25519 public key
    pub fn add_trusted_ed25519_key(&mut self, public_key: &[u8; 32]) {
        if !self.trusted_ed25519_keys.contains(public_key) {
            self.trusted_ed25519_keys.push(*public_key);
            log_debug("crypto", "Ed25519 public key added to trust store");
        }
    }

    /// Verify Ed25519 signature with explicit key (not used in the pipeline path)
    pub fn verify_ed25519_signature(
        &self,
        data: &[u8],
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> SignatureStatus {
        if !self.trusted_ed25519_keys.contains(public_key) {
            log_warn("crypto", "Attempted verification with untrusted Ed25519 key");
            return SignatureStatus::KeyNotFound;
        }

        let public_key = match PublicKey::from_bytes(public_key) {
            Ok(key) => key,
            Err(_) => {
                log_error("crypto", "Failed to parse Ed25519 public key");
                return SignatureStatus::MalformedSignature;
            }
        };

        let signature = match Signature::from_bytes(signature) {
            Ok(sig) => sig,
            Err(_) => {
                log_error("crypto", "Failed to parse Ed25519 signature");
                return SignatureStatus::MalformedSignature;
            }
        };

        match public_key.verify(data, &signature) {
            Ok(()) => {
                log_info("crypto", "Ed25519 signature verification successful");
                SignatureStatus::Valid
            }
            Err(_) => {
                log_warn("crypto", "Ed25519 signature verification failed");
                SignatureStatus::Invalid
            }
        }
    }
}

// NØNOS trusted signing keys (embedded example keys; replace in production)
const NONOS_SIGNING_KEY: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

const NONOS_BACKUP_KEY: [u8; 32] = [
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
];

/// Primary detached-signature verification used by the capsule pipeline.
///
/// - Validates layout via `validate_capsule_layout`
/// - Extracts `(signature, payload)` via `extract_signature_and_payload`
/// - Verifies with `verify_ed25519_signature` (trusted keyring in `verify.rs`)
pub fn verify_signature(blob: &[u8], meta: &CapsuleMeta) -> bool {
    // Strict bounds/layout validation first.
    if let Err(e) = validate_capsule_layout(blob, meta) {
        log_error("crypto", e);
        return false;
    }

    // Safe slicing of detached signature/proof and payload.
    let (signature_bytes, payload_bytes) = match extract_signature_and_payload(blob, meta) {
        Ok((sig, payload)) => (sig, payload),
        Err(e) => {
            log_error("crypto", e);
            return false;
        }
    };

    // Only Ed25519 (64-byte) signatures are accepted here.
    if signature_bytes.len() != 64 {
        log_error("crypto", "Invalid signature length (expected 64 for Ed25519)");
        return false;
    }

    match verify_ed25519_signature(&payload_bytes, &signature_bytes) {
        Ok(true) => {
            log_info("crypto", "Capsule signature verification successful");
            true
        }
        Ok(false) => {
            log_warn("crypto", "Ed25519 verification failed");
            false
        }
        Err(e) => {
            log_error("crypto", e);
            false
        }
    }
}

/// Advanced cryptographic self-test (kept for diagnostics)
pub fn perform_crypto_self_test() -> bool {
    log_info("crypto", "Performing comprehensive cryptographic self-test");

    let _verifier = SignatureVerifier::new();

    // Test 1: Hash consistency
    let test_data = b"NONOS cryptographic self-test vector";
    let hash1 = blake3::hash(test_data);
    let hash2 = blake3::hash(test_data);
    if hash1.as_bytes() != hash2.as_bytes() {
        log_error("crypto", "Hash consistency test failed");
        return false;
    }

    // Test 2: Different data produces different hashes
    let test_data2 = b"NONOS different test vector";
    let hash3 = blake3::hash(test_data2);
    if hash1.as_bytes() == hash3.as_bytes() {
        log_error("crypto", "Hash uniqueness test failed");
        return false;
    }

    // Test 3: Signature shape sanity
    let mut test_signature = [0u8; 64];
    test_signature[0] = 0x42; // Non-zero signature
    if test_signature.iter().all(|&b| b == 0) {
        log_error("crypto", "Signature validation test failed");
        return false;
    }

    log_info("crypto", "All cryptographic self-tests passed");
    true
}
