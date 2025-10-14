//! NØNOS ZK module
pub mod errors;
pub mod binding;
pub mod registry;
pub mod parse;
pub mod transcript;
pub mod zkverify;

#[cfg(feature = "zk-testvectors")]
pub mod testvectors;

pub use zkverify::{ZkProof, ZkVerifyResult, verify_proof, derive_program_hash};
pub use errors::ZkError;
