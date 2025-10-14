//! Signature verification for NONOS

use crate::verify::verify_ed25519_signature;
use crate::trusted_keys::TRUSTED_PUBLIC_KEYS;
use crate::log::logger::{log_info, log_error};

/// Verifies a downloaded kernel against all trusted public keys.
pub fn verify_downloaded_kernel(kernel: &[u8], signature: &[u8]) -> bool {
    for (idx, pubkey) in TRUSTED_PUBLIC_KEYS.iter().enumerate() {
        match verify_ed25519_signature(kernel, signature, pubkey) {
            Ok(true) => {
                log_info("verify", &format!("Kernel signature verified with key #{}", idx));
                return true;
            }
            Ok(false) | Err(_) => continue,
        }
    }
    log_error("verify", "Kernel signature verification failed with all trusted keys.");
    false
}
