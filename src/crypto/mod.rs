pub mod sig;

pub use sig::{
    NONOS_SIGNING_KEY,
    SignatureVerifier, CertificateStatus, SignatureStatus,
    verify_signature, perform_crypto_self_test,
};
