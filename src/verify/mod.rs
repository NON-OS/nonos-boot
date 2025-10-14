//! NONOS Capsule and Kernel Verification Module

pub mod capsule;

pub use capsule::{
    validate_capsule,
    CapsuleMetadata,
    CapsuleStatus,
};
