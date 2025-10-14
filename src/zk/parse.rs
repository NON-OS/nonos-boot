//! Parser for canonical .nonos.zkproof section -> ZkProof.
//!
//! Framing (little endian):
//!   struct Header {
//!       u32 program_hash_off;
//!       u32 capsule_commitment_off;
//!       u32 public_inputs_off;
//!       u32 proof_off;
//!       u32 end_off; // sentinel (<= section.len())
//!   }
//! Ranges (start-relative):
//!   program_hash: [program_hash_off, program_hash_off+32)
//!   capsule_commitment: [capsule_commitment_off, capsule_commitment_off+32)
//!   public_inputs: [public_inputs_off, proof_off)
//!   proof_blob: [proof_off, end_off)
//!
//! Manifest bytes are provided separately (if manifest binding enabled).
//!
//! Strict bounds & ordering checks; no panics on malformed data.

use alloc::vec::Vec;
use core::mem::size_of;

use super::zkverify::ZkProof;
use super::errors::ZkError;

#[repr(C)]
struct RawHeader {
    program_hash_off: u32,
    capsule_commitment_off: u32,
    public_inputs_off: u32,
    proof_off: u32,
    end_off: u32,
}

fn read_u32(section: &[u8], off: usize) -> Result<u32, ZkError> {
    if off + 4 > section.len() {
        return Err(ZkError::HeaderTruncated);
    }
    Ok(u32::from_le_bytes(section[off..off + 4].try_into().unwrap()))
}

fn read_header(section: &[u8]) -> Result<RawHeader, ZkError> {
    if section.len() < size_of::<RawHeader>() {
        return Err(ZkError::SectionTooSmall);
    }
    Ok(RawHeader {
        program_hash_off: read_u32(section, 0)?,
        capsule_commitment_off: read_u32(section, 4)?,
        public_inputs_off: read_u32(section, 8)?,
        proof_off: read_u32(section, 12)?,
        end_off: read_u32(section, 16)?,
    })
}

pub fn parse_section(section: &[u8], manifest: Option<&[u8]>) -> Result<ZkProof, ZkError> {
    let hdr = read_header(section)?;
    let end = hdr.end_off as usize;
    if end > section.len() {
        return Err(ZkError::OffsetRange);
    }

    let ph_off = hdr.program_hash_off as usize;
    let cc_off = hdr.capsule_commitment_off as usize;
    let pi_off = hdr.public_inputs_off as usize;
    let proof_off = hdr.proof_off as usize;

    if ph_off + 32 > end || cc_off + 32 > end || pi_off > proof_off || proof_off > end {
        return Err(ZkError::OffsetRange);
    }

    let mut program_hash = [0u8; 32];
    program_hash.copy_from_slice(slice(section, ph_off, ph_off + 32)?);

    let mut capsule_commitment = [0u8; 32];
    capsule_commitment.copy_from_slice(slice(section, cc_off, cc_off + 32)?);

    let public_inputs = slice(section, pi_off, proof_off)?.to_vec();
    let proof_blob = slice(section, proof_off, end)?.to_vec();

    Ok(ZkProof {
        program_hash,
        capsule_commitment,
        public_inputs,
        proof_blob,
        manifest: manifest.map(|m| m.to_vec()),
    })
}

fn slice<'a>(section: &'a [u8], start: usize, end: usize) -> Result<&'a [u8], ZkError> {
    if start > end || end > section.len() {
        return Err(ZkError::OffsetRange);
    }
    Ok(&section[start..end])
}
