//! Capsule Loader for NONOS Secure Bootloader

use crate::verify::capsule::{validate_capsule, CapsuleStatus, CapsuleMetadata};
use crate::log::logger::{log_info, log_error};
use alloc::vec::Vec;

/// Load and validate a capsule from bytes, returning the payload if valid.
pub fn load_validated_capsule(capsule_bytes: &[u8]) -> Option<Vec<u8>> {
    let (status, meta_opt) = validate_capsule(capsule_bytes);

    match status {
        CapsuleStatus::Valid => {
            log_info("loader", "Capsule status: Valid, extracting payload");
            if let Some(meta) = meta_opt {
                let payload = &capsule_bytes[meta.offset_payload..meta.offset_payload + meta.len_payload];
                Some(payload.to_vec())
            } else {
                log_error("loader", "Capsule valid but metadata extraction failed");
                None
            }
        }
        CapsuleStatus::InvalidSignature => {
            log_error("loader", "Capsule signature is INVALID. Boot aborted.");
            None
        }
        CapsuleStatus::InvalidFormat => {
            log_error("loader", "Capsule format is INVALID. Boot aborted.");
            None
        }
        CapsuleStatus::IntegrityError => {
            log_error("loader", "Capsule integrity check FAILED. Boot aborted.");
            None
        }
        CapsuleStatus::UnsupportedVersion => {
            log_error("loader", "Capsule version unsupported. Boot aborted.");
            None
        }
        CapsuleStatus::Expired => {
            log_error("loader", "Capsule expired. Boot aborted.");
            None
        }
    }
}
