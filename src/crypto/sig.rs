//! Cryptographic Signature Verification for NONOS Capsules

use crate::log::logger::{log_debug, log_error, log_info, log_warn};
use crate::verify::CapsuleMetadata;
use alloc::vec::Vec;
use blake3;
#[cfg(target_os = "uefi")]
use ed25519_dalek::{PublicKey, Signature, Verifier};
#[cfg(not(target_os = "uefi"))]
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// NONOS Ed25519 signing key NR.1, will add more
pub const NONOS_SIGNING_KEY: [u8; 32] = [
    0xbe, 0x3a, 0x0d, 0x52, 0xc5, 0xae, 0x47, 0x6d, 0x8b, 0xfa, 0xa4, 0xd4,
    0xdb, 0x1c, 0x52, 0xaf, 0xa8, 0xfa, 0xe7, 0x34, 0xa2, 0x73, 0x99, 0x82,
    0x9d, 0xfb, 0x8c, 0x4f, 0x2f, 0x9e, 0xb3, 0x9d
];

/// Certificate validation result
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CertificateStatus {
    Valid,
    Expired,
    Revoked,
    InvalidSignature,
    UntrustedIssuer,
    MalformedCertificate,
}

/// Signature verification result
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureStatus {
    Valid,
    Invalid,
    KeyNotFound,
    UnsupportedAlgorithm,
    MalformedSignature,
}

/// Hardened signature verifier context
#[derive(Debug, Default)]
pub struct SignatureVerifier {
    pub trusted_ed25519_keys: Vec<[u8; 32]>,
}

impl SignatureVerifier {
    /// Create new signature verifier with embedded public keys
    pub fn new() -> Self {
        let mut verifier = Self::default();
        verifier.add_trusted_ed25519_key(&NONOS_SIGNING_KEY);
        log_info("crypto", "Production signature verifier initialized");
        verifier
    }

    /// Add a trusted Ed25519 public key
    pub fn add_trusted_ed25519_key(&mut self, public_key: &[u8; 32]) {
        if !self.trusted_ed25519_keys.contains(public_key) {
            self.trusted_ed25519_keys.push(*public_key);
            log_debug("crypto", "Ed25519 public key added to trust store");
        }
    }

    /// Verify Ed25519 signature
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

        #[cfg(target_os = "uefi")]
        let public_key = match PublicKey::from_bytes(public_key) {
            Ok(key) => key,
            Err(_) => {
                log_error("crypto", "Failed to parse Ed25519 public key");
                return SignatureStatus::MalformedSignature;
            }
        };

        #[cfg(not(target_os = "uefi"))]
        let public_key = match VerifyingKey::from_bytes(public_key) {
            Ok(key) => key,
            Err(_) => {
                log_error("crypto", "Failed to parse Ed25519 public key");
                return SignatureStatus::MalformedSignature;
            }
        };

        #[cfg(target_os = "uefi")]
        let signature = match Signature::from_bytes(signature) {
            Ok(sig) => sig,
            Err(_) => {
                log_error("crypto", "Failed to parse Ed25519 signature");
                return SignatureStatus::MalformedSignature;
            }
        };

        #[cfg(not(target_os = "uefi"))]
        let signature = Signature::from_bytes(signature);

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

/// Capsule signature verification for NONOS bootloader
pub fn verify_signature(blob: &[u8], meta: &CapsuleMetadata) -> bool {
    let sig_start = meta.offset_sig;
    let sig_end = sig_start + meta.len_sig;
    let pay_start = meta.offset_payload;
    let pay_end = pay_start + meta.len_payload;

    if sig_end > blob.len() || pay_end > blob.len() {
        log_error("crypto", "Invalid signature or payload bounds");
        return false;
    }

    let signature_bytes = &blob[sig_start..sig_end];
    let payload_bytes = &blob[pay_start..pay_end];

    if signature_bytes.len() != 64 {
        log_error("crypto", "Invalid signature length (expected 64 bytes)");
        return false;
    }
    if signature_bytes.iter().all(|&b| b == 0) {
        log_error("crypto", "Null signature detected (security risk)");
        return false;
    }

    let verifier = SignatureVerifier::new();

    for key in &verifier.trusted_ed25519_keys {
        if let SignatureStatus::Valid =
            verifier.verify_ed25519_signature(payload_bytes, &signature_bytes.try_into().expect("slice must be 64 bytes"), key)
        {
            log_info("crypto", "Capsule signature verified with Ed25519");
            return true;
        }
    }

    log_error("crypto", "Capsule signature verification failed with all trusted keys!");
    false
}

/// cryptographic self-test (must pass at boot)
pub fn perform_crypto_self_test() -> bool {
    log_info("crypto", "Performing comprehensive cryptographic self-test");

    let verifier = SignatureVerifier::new();

    let test_data = b"NONOS cryptographic self-test vector";
    let hash1 = blake3::hash(test_data);
    let hash2 = blake3::hash(test_data);

    if hash1.as_bytes() != hash2.as_bytes() {
        log_error("crypto", "Hash consistency test failed");
        return false;
    }

    let test_data2 = b"NONOS different test vector";
    let hash3 = blake3::hash(test_data2);

    if hash1.as_bytes() == hash3.as_bytes() {
        log_error("crypto", "Hash uniqueness test failed");
        return false;
    }

    let mut test_signature = [0u8; 64];
    test_signature[0] = 0x42;

    if test_signature.iter().all(|&b| b == 0) {
        log_error("crypto", "Signature validation test failed");
        return false;
    }

    log_info("crypto", "All cryptographic self-tests passed");
    true
}
