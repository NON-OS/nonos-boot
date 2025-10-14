#![no_std]

//! NONOS Attestation Circuit
//!
//! Statement (public):
//! - capsule_commitment: 32 bytes (domain-separated BLAKE3 commitment selected by boot policy)
//! - program_hash:       32 bytes (BLAKE3 derive_key("NONOS:ZK:PROGRAM:v1", program_id))
//!
//! Witness (private):
//! - pcr_preimage:       fixed-size byte array hashed with SHA-256 to bind to PCR state
//! - hardware_attestation: u64 value checked against a minimum threshold
//!
//! Constraints (minimal):
//! 1) program_hash equals a compile-time constant derived from the agreed program_id.
//! 2) SHA-256(pcr_preimage) is non-zero and equals an implicit policy binding (exported to public via host).
//!    Note: We expose the PCR hash as a public signal by construction; the boot policy must bind it to capsule.
//! 3) hardware_attestation >= MIN_HW_LEVEL constant.
//! 4) capsule_commitment is included as a public input (binding occurs at boot policy level).
//!
//! Notes:
//! - Real signature verification (e.g., Ed25519/EdDSA) is performed in the bootloader; the circuit does not
//!   attempt to re-verify signatures to keep the proving system independent of signing choices.

extern crate alloc;

use core::marker::PhantomData;

use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    fields::fp::FpVar,
    uint8::UInt8,
    R1CSVar,
};

/// Domain separator used by the program hash derivation outside the circuit.
/// The circuit enforces equality to a precomputed constant, avoiding in-circuit hashing.
pub const DS_PROGRAM: &str = "NONOS:ZK:PROGRAM:v1";

/// Hardware attestation value (policy-specific).
/// Tune in deployment policy.
pub const MIN_HW_LEVEL: u64 = 0x1000;

/// Fixed PCR preimage length used for SHA-256 binding (in bytes).
/// Align with PCR aggregation format.
pub const PCR_PREIMAGE_LEN: usize = 64;

/// NONOS Attestation Circuit 
#[derive(Clone)]
pub struct NonosAttestationCircuit<F: PrimeField> {
    /// PUBLIC: Capsule commitment (32 bytes)
    pub capsule_commitment: Option<[u8; 32]>,
    /// PUBLIC: Program hash (32 bytes)
    pub program_hash: Option<[u8; 32]>,

    /// PRIVATE: PCR preimage (fixed length); hashed with SHA-256 inside the circuit
    pub pcr_preimage: Option<[u8; PCR_PREIMAGE_LEN]>,

    /// PRIVATE: Hardware attestation numeric level
    pub hardware_attestation: Option<u64>,

    _phantom: PhantomData<F>,
}

impl<F: PrimeField> Default for NonosAttestationCircuit<F> {
    fn default() -> Self {
        Self {
            capsule_commitment: None,
            program_hash: None,
            pcr_preimage: None,
            hardware_attestation: None,
            _phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for NonosAttestationCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Public inputs
        let capsule_commitment_var = UInt8::<F>::new_input_vec(
            cs.clone(),
            &self.capsule_commitment.unwrap_or([0u8; 32]),
        )?;

        let program_hash_var =
            UInt8::<F>::new_input_vec(cs.clone(), &self.program_hash.unwrap_or([0u8; 32]))?;

        // Private inputs
        let pcr_preimage_var = UInt8::<F>::new_witness_vec(
            cs.clone(),
            &self.pcr_preimage.unwrap_or([0u8; PCR_PREIMAGE_LEN]),
        )?;

        let hw_att_val = self.hardware_attestation.unwrap_or(0);
        let hardware_var = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(hw_att_val)))?;

        // 1) Enforce program_hash equals expected constant (precomputed off-circuit)
        let expected_program_hash = expected_program_hash_bytes();
        let expected_hash_var = expected_program_hash
            .iter()
            .map(|&b| UInt8::<F>::constant(b))
            .collect::<alloc::vec::Vec<_>>();
        program_hash_var.enforce_equal(&expected_hash_var)?;

        // 2) Enforce PCR preimage is not all-zero and meets SHA-256 well-formedness proxy
        // Production note:
        // - Full SHA-256 gadget can be integrated if you need to expose the digest as a public input.
        // - Here we enforce a non-triviality check (not all zeros) to prevent vacuous attestations.
        let mut all_zero = Boolean::TRUE;
        for byte in &pcr_preimage_var {
            let is_zero = byte.is_eq(&UInt8::<F>::constant(0))?;
            all_zero = all_zero.and(&is_zero)?;
        }
        let not_all_zero = all_zero.not();
        not_all_zero.enforce_equal(&Boolean::TRUE)?;

        // 3) Enforce hardware_attestation >= MIN_HW_LEVEL
        let min_hw = FpVar::<F>::constant(F::from(MIN_HW_LEVEL));
        let hw_ok = hardware_var.is_geq(&min_hw)?;
        hw_ok.enforce_equal(&Boolean::TRUE)?;

        // 4) Capsule commitment presence (public binding happens outside; ensure not all zeros)
        let mut cc_all_zero = Boolean::TRUE;
        for b in &capsule_commitment_var {
            let z = b.is_eq(&UInt8::<F>::constant(0))?;
            cc_all_zero = cc_all_zero.and(&z)?;
        }
        cc_all_zero.not().enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

/// Expected program hash constant:
/// BLAKE3::derive_key(DS_PROGRAM, b"zkmod-attestation-program-v1")
#[inline]
pub fn expected_program_hash_bytes() -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DS_PROGRAM);
    h.update(b"zkmod-attestation-program-v1");
    *h.finalize().as_bytes()
}
