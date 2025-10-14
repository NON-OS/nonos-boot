//! NONOS Capsule and Kernel Verification Module

pub mod capsule;
pub mod loader;

pub use capsule::{
    validate_capsule,
    CapsuleMetadata,
    CapsuleStatus,
};

pub use loader::load_validated_capsule;
