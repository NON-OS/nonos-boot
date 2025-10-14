//! Capsule Validation for NONOS Secure Bootloader

use crate::log::logger::{log_debug, log_error, log_info};
use crate::crypto::sig::{verify_signature, NONOS_SIGNING_KEY};
use alloc::vec::Vec;

/// Capsule metadata
#[derive(Debug, Clone)]
pub struct CapsuleMetadata {
    pub offset_sig: usize,
    pub len_sig: usize,
    pub offset_payload: usize,
    pub len_payload: usize,
    // Extendable: pub version: u32, pub timestamp: u64, pub hash: [u8; 32]
}

/// Capsule validation result
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CapsuleStatus {
    Valid,
    InvalidSignature,
    InvalidFormat,
    IntegrityError,
    UnsupportedVersion,
    Expired,
}

/// Validate a capsule image and return status + metadata.
/// Capsule format: [header][payload][signature]
pub fn validate_capsule(capsule: &[u8]) -> (CapsuleStatus, Option<CapsuleMetadata>) {
    // Minimum capsule: 32 bytes header + payload + 64 bytes signature
    if capsule.len() < 128 {
        log_error("capsule", "Capsule too small for header+signature");
        return (CapsuleStatus::InvalidFormat, None);
    }

    // Example header parsing (first 32 bytes)
    let header = &capsule[0..32];
    // Header fields, first format version.
    // Here:
    // - [0..4]: version (u32 LE)
    // - [4..12]: timestamp (u64 LE)
    // - [12..44]: reserved
    // - [12..44]: hash (optionally, 32 bytes blake3 hash of payload)

    let version = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let timestamp = u64::from_le_bytes(header[4..12].try_into().unwrap());
    let hash = &header[12..44];

    // Enforce supported version
    const SUPPORTED_VERSION: u32 = 1;
    if version != SUPPORTED_VERSION {
        log_error("capsule", &format!("Unsupported capsule version: {}", version));
        return (CapsuleStatus::UnsupportedVersion, None);
    }

    // Check timestamp for expiration
    // let now = get_current_unix_time();
    // if timestamp < now - MAX_CAPSULE_AGE {
    //     log_error("capsule", "Capsule expired");
    //     return (CapsuleStatus::Expired, None);
    // }

    let offset_sig = capsule.len() - 64;
    let len_sig = 64;
    let offset_payload = 32;
    let len_payload = offset_sig.saturating_sub(offset_payload);

    if offset_payload + len_payload > capsule.len() || offset_sig + len_sig > capsule.len() {
        log_error("capsule", "Capsule offsets/lengths invalid");
        return (CapsuleStatus::InvalidFormat, None);
    }

    let payload = &capsule[offset_payload..offset_payload + len_payload];

    // Check hash for integrity
    let payload_hash = blake3::hash(payload);
    if hash != payload_hash.as_bytes() {
        log_error("capsule", "Capsule payload hash mismatch");
        return (CapsuleStatus::IntegrityError, Some(CapsuleMetadata {
            offset_sig,
            len_sig,
            offset_payload,
            len_payload,
        }));
    }

    let meta = CapsuleMetadata {
        offset_sig,
        len_sig,
        offset_payload,
        len_payload,
    };

    // Strict signature verification
    let signature_valid = verify_signature(capsule, &meta);
    if !signature_valid {
        log_error("capsule", "Capsule signature verification failed");
        return (CapsuleStatus::InvalidSignature, Some(meta));
    }

    log_info("capsule", "Capsule validated successfully");
    (CapsuleStatus::Valid, Some(meta))
}
