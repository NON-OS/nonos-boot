#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use core::convert::TryInto;
use blake3;
use crate::log::logger::{log_error, log_info, log_debug, log_warn};
use crate::crypto::sig::{verify_signature_full, KeyId, VerifyError};
use core::mem;

#[derive(Debug, Clone)]
pub struct CapsuleMetadata {
    pub offset_sig: usize,
    pub len_sig: usize,
    pub offset_payload: usize,
    pub len_payload: usize,
    pub signer_keyid: Option<KeyId>,
    pub payload_hash: [u8; 32],
    pub header_version: u32,
    pub header_timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleStatus {
    Valid,
    InvalidSignature,
    InvalidFormat,
    IntegrityError,
    UnsupportedVersion,
    Expired,
    ParseError,
}

fn read_u32_le(b: &[u8]) -> Option<u32> {
    if b.len() < 4 { return None; }
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_le(b: &[u8]) -> Option<u64> {
    if b.len() < 8 { return None; }
    Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

pub fn validate_capsule(capsule: &[u8]) -> (CapsuleStatus, Option<CapsuleMetadata>) {
    let tot = capsule.len();
    if tot < 96 {
        log_error("capsule", "capsule too small");
        return (CapsuleStatus::InvalidFormat, None);
    }

    let header_len = 32usize;
    if tot < header_len + 64 {
        log_error("capsule", "capsule header truncated");
        return (CapsuleStatus::InvalidFormat, None);
    }

    let header = &capsule[0..header_len];

    let version = match read_u32_le(&header[0..4]) {
        Some(v) => v,
        None => {
            log_error("capsule", "header version parse failed");
            return (CapsuleStatus::ParseError, None);
        }
    };

    if version != 1 {
        log_error("capsule", "unsupported capsule version");
        return (CapsuleStatus::UnsupportedVersion, None);
    }

    let timestamp = match read_u64_le(&header[4..12]) {
        Some(t) => t,
        None => {
            log_error("capsule", "header timestamp parse failed");
            return (CapsuleStatus::ParseError, None);
        }
    };

    let hash_field = &header[12..44];
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&hash_field[0..32]);

    let offset_sig = tot.saturating_sub(64);
    let len_sig = 64usize;
    let offset_payload = header_len;
    if offset_payload > offset_sig {
        log_error("capsule", "invalid payload/sig layout");
        return (CapsuleStatus::InvalidFormat, None);
    }
    let len_payload = offset_sig - offset_payload;

    if offset_payload.checked_add(len_payload).map_or(true, |v| v > tot) {
        log_error("capsule", "payload bounds invalid");
        return (CapsuleStatus::InvalidFormat, None);
    }

    let payload = &capsule[offset_payload..offset_payload + len_payload];
    let payload_hash = blake3::hash(payload);
    let mut payload_hash_arr = [0u8; 32];
    payload_hash_arr.copy_from_slice(payload_hash.as_bytes());

    if payload_hash_arr != expected_hash {
        log_error("capsule", "payload hash mismatch");
        let meta = CapsuleMetadata {
            offset_sig,
            len_sig,
            offset_payload,
            len_payload,
            signer_keyid: None,
            payload_hash: payload_hash_arr,
            header_version: version,
            header_timestamp: timestamp,
        };
        return (CapsuleStatus::IntegrityError, Some(meta));
    }

    let meta = CapsuleMetadata {
        offset_sig,
        len_sig,
        offset_payload,
        len_payload,
        signer_keyid: None,
        payload_hash: payload_hash_arr,
        header_version: version,
        header_timestamp: timestamp,
    };

    match verify_signature_full(capsule, &meta) {
        Ok(kid) => {
            let mut m = meta;
            m.signer_keyid = Some(kid);
            let mut kid_hex = [0u8; 64];
            for (i, b) in kid.iter().enumerate() {
                let hi = hex_nibble(b >> 4);
                let lo = hex_nibble(b & 0xF);
                kid_hex[i * 2] = hi as u8;
                kid_hex[i * 2 + 1] = lo as u8;
            }
            if let Ok(s) = core::str::from_utf8(&kid_hex) {
                log_info("capsule", "signature verified");
                log_debug("capsule", s);
            } else {
                log_info("capsule", "signature verified (keyid binary)");
            }
            (CapsuleStatus::Valid, Some(m))
        }
        Err(VerifyError::Bounds) => {
            log_error("capsule", "signature metadata bounds error");
            (CapsuleStatus::InvalidFormat, Some(meta))
        }
        Err(VerifyError::MalformedSignature) => {
            log_error("capsule", "malformed signature");
            (CapsuleStatus::InvalidSignature, Some(meta))
        }
        Err(VerifyError::KeyNotFound) => {
            log_warn("capsule", "signer key not trusted");
            (CapsuleStatus::InvalidSignature, Some(meta))
        }
        Err(VerifyError::InvalidSignature) => {
            log_warn("capsule", "signature invalid");
            (CapsuleStatus::InvalidSignature, Some(meta))
        }
        Err(VerifyError::NotInitialized) => {
            log_error("capsule", "signature verifier not initialized");
            (CapsuleStatus::InvalidSignature, Some(meta))
        }
    }
}

fn hex_nibble(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        10..=15 => (b'a' + (v - 10)) as char,
        _ => '?',
    }
}

#[cfg(all(test, feature = "host-tests"))]
mod tests {
    use super::*;
    use hex_literal::hex;
    use alloc::vec::Vec;

    #[test]
    fn capsule_validate_valid() {
        let header_v1_prefix = {
            let mut h = Vec::new();
            h.extend_from_slice(&1u32.to_le_bytes());
            h.extend_from_slice(&0u64.to_le_bytes());
            let mut hash_placeholder = [0u8; 32];
            h.extend_from_slice(&hash_placeholder);
            h.resize(32, 0);
            h
        };
        let payload = b"hello world";
        let payload_hash = blake3::hash(payload);
        let mut header = header_v1_prefix.clone();
        header[12..44].copy_from_slice(payload_hash.as_bytes());
        let mut capsule = header.clone();
        capsule.extend_from_slice(payload);
        let sig = [0u8; 64];
        capsule.extend_from_slice(&sig);
        let (status, meta_opt) = validate_capsule(&capsule);
        assert_eq!(status, CapsuleStatus::Valid);
        let meta = meta_opt.expect("meta");
        assert_eq!(meta.len_payload, payload.len());
    }

    #[test]
    fn capsule_validate_bad_hash() {
        let mut header = [0u8; 32];
        header[0..4].copy_from_slice(&1u32.to_le_bytes());
        header[4..12].copy_from_slice(&0u64.to_le_bytes());
        header[12..44].copy_from_slice(&[0u8;32]);
        let payload = b"tampered";
        let mut capsule = header.to_vec();
        capsule.extend_from_slice(payload);
        capsule.extend_from_slice(&[0u8;64]);
        let (status, meta_opt) = validate_capsule(&capsule);
        assert_eq!(status, CapsuleStatus::IntegrityError);
        let meta = meta_opt.expect("meta");
        assert_eq!(meta.len_payload, payload.len());
    }
}
