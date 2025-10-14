//! Groth16 verifier wrapper
//! Author: eK (team@nonos.systems) — https://nonos.systems
//!
//! -----------------------------------------------------------------------------
//! HARDENING SUMMARY
//! -----------------------------------------------------------------------------
//! - Proof length enforcement (Groth16 compressed A(48)+B(96)+C(48)=192 bytes)
//! - Public input count must equal vk.ic.len() - 1
//! - Domain‑separated program hash (derive_program_hash helper)
//! - Constant‑time commitment & program hash comparisons
//! - Optional zeroization of buffers (feature `zk-zeroize`)
//! - Size caps (proof ≤ 2 MiB defensive cap, inputs ≤ 256 KiB, alignment checked)
//! - Clear error taxonomy (ZkError) mapped to stable & terse strings
//! - Compile‑time assertion on input cap alignment
//!
//! -----------------------------------------------------------------------------
//! HOW TO EMBED A CIRCUIT / VERIFYING KEY (MANDATORY FOR REAL ZK BUILD)
//! -----------------------------------------------------------------------------
//! Verifying keys and their PROGRAM_HASH values are NOT defined in this file.
//! They live in `src/zk/registry.rs`. This verifier calls `registry::lookup()`
//! which must return the canonical compressed VK bytes for the given program hash.
//!
//! Steps (per circuit):
//! 1. Decide a stable program ID string (e.g. "zkmod-attest-v1").
//! 2. Run the host tool (from repo root):
//!
//!    cargo run --release -p zk-embed -- \
//!      --program-id-str "zkmod-attest-v1" \
//!      --vk path/to/verifying_key.bin \
//!      --const-prefix ATTEST_V1 > vk_snippet.rs
//!
//!    (Alternatively use --program-id-hex / --program-id-file as needed.)
//!
//! 3. Open the generated `vk_snippet.rs`. It will contain something like:
//!
//!    pub const PROGRAM_HASH_ATTEST_V1: [u8; 32] = [ 0x12, 0x34, ... ];
//!    pub const VK_ATTEST_V1_BLS12_381_GROTH16: &[u8] = &[ 0xab, 0xcd, ... ];
//!
//!    And a `program_vk_lookup` mapping example (ignore if using the modular registry).
//!
//! 4. Edit `src/zk/registry.rs`:
//!    - Paste the two constants near the top (after placeholders or replacing them).
//!    - Add them to the ENTRIES slice. Example:
//!
//!        static ENTRIES: &[(&[u8;32], &[u8])] = &[
//!            (&PROGRAM_HASH_ATTEST_V1, VK_ATTEST_V1_BLS12_381_GROTH16),
//!            // ... more entries ...
//!        ];
//!
//!    - REMOVE the placeholder entry once at least one real entry is present.
//!
//! 5. Enable features when building the bootloader:
//!
//!    cargo build --release --features zk-groth16,zk-vk-provisioned
//!
//!    (Add `zk-bind-manifest` if you want commitment binding to the *manifest*
//!    instead of the public inputs; in that case ensure you pass manifest bytes
//!    when constructing ZkProof.)
//!
//! 6. For additional circuits, repeat steps with a NEW unique program ID and
//!    append new constants + entry to ENTRIES (never reuse program IDs).
//!
//! 7. (Optional) Record each program in `docs/PROGRAMS.md` with:
//!    - Program ID
//!    - PROGRAM_HASH (hex)
//!    - VK fingerprint (BLAKE3 of canonical compressed VK bytes)
//!    - Binding mode
//!    - Status (active/deprecated/revoked)
//!
//! IMPORTANT: Do *not* enable `zk-vk-provisioned` until placeholder constants are gone,
//! or the build will intentionally panic at compile-time.
//!
//! -----------------------------------------------------------------------------
//! RUNTIME BINDING POLICY
//! -----------------------------------------------------------------------------
//! - Default: commitment = BLAKE3(derive_key="NONOS:CAPSULE:COMMITMENT:v1", public_inputs)
//! - Feature `zk-bind-manifest`: commitment = BLAKE3(..., manifest_bytes)
//!   (Requires providing manifest bytes in ZkProof.manifest)
//!
//! The value stored in the capsule (capsule_commitment) must match this recomputed value.
//!
//! -----------------------------------------------------------------------------
//! ZEROIZATION (OPTIONAL)
//! -----------------------------------------------------------------------------
//! If `zk-zeroize` feature is active, proof bytes, public inputs, and manifest
//! buffer are zeroized after a verification attempt. Groth16 proofs are public
//! in most models but zeroization is a defense-in-depth measure.
//!
//! -----------------------------------------------------------------------------
//! EXTENDING
//! -----------------------------------------------------------------------------
//! - Additional proving systems: replicate pattern behind new feature gate.
//! - Aggregated proofs: introduce length variants or a different backend module.
//! - Remote attestation: include program_hash + capsule_commitment in BootInfo.
//!
//! -----------------------------------------------------------------------------
//! DISCLAIMER
//! -----------------------------------------------------------------------------
//! This module *only* verifies proofs. It does not:
//! - Validate the semantics of the circuit (auditor must review circuit source).
//! - Handle replay / freshness (layer on top if required).
//! - Provide circuit versioning (must be done via new program IDs).
//!
//! Replace registry placeholder constants prior to enabling zk-vk-provisioned.

#![allow(dead_code)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use super::binding::{select_binding, compute_commit};
use super::registry;
use super::errors::ZkError;

#[cfg(feature = "zk-zeroize")]
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct ZkProof {
    pub program_hash: [u8; 32],
    pub capsule_commitment: [u8; 32],
    pub public_inputs: Vec<u8>,
    pub proof_blob: Vec<u8>,
    pub manifest: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ZkVerifyResult {
    Valid,
    Invalid(&'static str),
    Unsupported(&'static str),
    Error(&'static str),
}

const DS_PROGRAM_HASH: &str = "NONOS:ZK:PROGRAM:v1";
const MAX_PROOF_SIZE: usize = 2 * 1024 * 1024;
const MAX_INPUT_SIZE: usize = 256 * 1024;

// Groth16 (BLS12-381 compressed): A(G1 48) + B(G2 96) + C(G1 48) = 192 bytes
#[cfg(feature = "zk-groth16")]
const GROTH16_PROOF_LEN: usize = 48 + 96 + 48;

const _: () = assert!(MAX_INPUT_SIZE % 32 == 0, "MAX_INPUT_SIZE must align to 32-byte field elements");

#[inline]
pub(crate) fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut x = 0u8;
    for i in 0..32 {
        x |= a[i] ^ b[i];
    }
    x == 0
}

pub fn verify_proof(p: &mut ZkProof) -> ZkVerifyResult {
    if p.proof_blob.len() > MAX_PROOF_SIZE {
        return ZkVerifyResult::Unsupported(ZkError::ProofTooLarge.as_str());
    }
    if p.public_inputs.len() > MAX_INPUT_SIZE {
        return ZkVerifyResult::Unsupported(ZkError::InputsTooLarge.as_str());
    }
    if p.public_inputs.len() % 32 != 0 {
        return ZkVerifyResult::Invalid(ZkError::InputsMisaligned.as_str());
    }

    #[cfg(feature = "zk-groth16")]
    {
        if p.proof_blob.len() != GROTH16_PROOF_LEN {
            return ZkVerifyResult::Invalid(ZkError::ProofSizeInvalid.as_str());
        }
    }

    // Commitment binding
    let binding = match select_binding(&p.public_inputs, p.manifest.as_deref()) {
        Ok(b) => b,
        Err(e) => return ZkVerifyResult::Invalid(e),
    };
    let local_commit = compute_commit(binding);
    if !ct_eq32(&local_commit, &p.capsule_commitment) {
        return ZkVerifyResult::Invalid(ZkError::CommitmentMismatch.as_str());
    }

    #[cfg(feature = "zk-groth16")]
    {
        let vk_bytes = match registry::lookup(&p.program_hash) {
            Some(v) if !v.is_empty() => v,
            Some(_) => return ZkVerifyResult::Error(ZkError::VerifyingKeyEmpty.as_str()),
            None => return ZkVerifyResult::Unsupported(ZkError::UnknownProgramHash.as_str()),
        };
        match groth16_verify(vk_bytes, &p.proof_blob, &p.public_inputs) {
            Ok(true)  => {
                zeroize_if(p);
                ZkVerifyResult::Valid
            }
            Ok(false) => {
                zeroize_if(p);
                ZkVerifyResult::Invalid(ZkError::BackendVerifyFailed.as_str())
            }
            Err(e)    => {
                zeroize_if(p);
                ZkVerifyResult::Error(e.as_str())
            }
        }
    }

    #[cfg(not(feature = "zk-groth16"))]
    {
        zeroize_if(p);
        ZkVerifyResult::Unsupported(ZkError::BackendUnsupported.as_str())
    }
}

#[cfg(feature = "zk-zeroize")]
fn zeroize_if(p: &mut ZkProof) {
    p.proof_blob.zeroize();
    p.public_inputs.zeroize();
    if let Some(m) = &mut p.manifest {
        m.zeroize();
    }
}

#[cfg(not(feature = "zk-zeroize"))]
fn zeroize_if(_p: &mut ZkProof) {}

#[cfg(feature = "zk-groth16")]
#[derive(Debug)]
enum GrothErr {
    VkDeserialize,
    ADeserialize,
    BDeserialize,
    CDeserialize,
    InputsMisaligned,
    InputsCountMismatch,
    Internal,
}

#[cfg(feature = "zk-groth16")]
impl GrothErr {
    fn as_str(&self) -> &'static str {
        use GrothErr::*;
        match self {
            VkDeserialize => ZkError::VerifyingKeyDeserialize.as_str(),
            ADeserialize => ZkError::ProofDeserializeA.as_str(),
            BDeserialize => ZkError::ProofDeserializeB.as_str(),
            CDeserialize => ZkError::ProofDeserializeC.as_str(),
            InputsMisaligned => ZkError::InputsMisaligned.as_str(),
            InputsCountMismatch => ZkError::InputsCountMismatch.as_str(),
            Internal => ZkError::Internal.as_str(),
        }
    }
}

#[cfg(feature = "zk-groth16")]
fn groth16_verify(
    vk_bytes: &[u8],
    proof_blob: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<bool, GrothErr> {
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
    use ark_ff::PrimeField;
    use ark_groth16::{prepare_verifying_key, verify_proof, Proof, VerifyingKey};
    use ark_serialize::{CanonicalDeserialize, Compress, Validate};
    use ark_std::io::Cursor;

    let vk = VerifyingKey::<Bls12_381>::deserialize_with_mode(
        &mut Cursor::new(vk_bytes),
        Compress::Yes,
        Validate::Yes,
    ).map_err(|_| GrothErr::VkDeserialize)?;

    if public_inputs_bytes.len() % 32 != 0 {
        return Err(GrothErr::InputsMisaligned);
    }
    let inputs_count = public_inputs_bytes.len() / 32;
    let expected = vk.ic.len().saturating_sub(1);
    if inputs_count != expected {
        return Err(GrothErr::InputsCountMismatch);
    }

    let mut cur = Cursor::new(proof_blob);
    let a = G1Affine::deserialize_with_mode(&mut cur, Compress::Yes, Validate::Yes)
        .map_err(|_| GrothErr::ADeserialize)?;
    let b = G2Affine::deserialize_with_mode(&mut cur, Compress::Yes, Validate::Yes)
        .map_err(|_| GrothErr::BDeserialize)?;
    let c = G1Affine::deserialize_with_mode(&mut cur, Compress::Yes, Validate::Yes)
        .map_err(|_| GrothErr::CDeserialize)?;
    let proof = Proof::<Bls12_381> { a, b, c };

    let mut inputs = alloc::vec::Vec::with_capacity(inputs_count);
    for chunk in public_inputs_bytes.chunks_exact(32) {
        inputs.push(Fr::from_be_bytes_mod_order(chunk));
    }

    let pvk = prepare_verifying_key(&vk);
    match verify_proof(&pvk, &proof, &inputs) {
        Ok(v) => Ok(v),
        Err(_) => Ok(false),
    }
}

pub fn derive_program_hash(program_id_bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DS_PROGRAM_HASH);
    h.update(program_id_bytes);
    *h.finalize().as_bytes()
}

/* ---------------- Tests (logic only, backend-less) ---------------- */
#[cfg(test)]
mod tests {
    use super::*;

    fn mk_base_proof() -> ZkProof {
        ZkProof {
            program_hash: [0u8;32],
            capsule_commitment: [0u8;32],
            public_inputs: vec![0u8; 32],
            proof_blob: vec![0u8; 0], // backend disabled here
            manifest: None,
        }
    }

    #[test]
    fn size_cap_inputs() {
        let mut p = mk_base_proof();
        p.public_inputs = vec![0u8; super::MAX_INPUT_SIZE + 32];
        let r = verify_proof(&mut p);
        assert!(matches!(r, ZkVerifyResult::Unsupported(_)));
    }

    #[test]
    fn misaligned_inputs() {
        let mut p = mk_base_proof();
        p.public_inputs = vec![0u8; 31];
        let r = verify_proof(&mut p);
        assert!(matches!(r, ZkVerifyResult::Invalid(_)));
    }

    #[test]
    fn commitment_mismatch() {
        let mut p = mk_base_proof();
        p.capsule_commitment[0] = 1;
        let r = verify_proof(&mut p);
        assert!(matches!(r, ZkVerifyResult::Invalid(_)));
    }
}
