#![no_std]
#![no_main]

extern crate alloc;

// Core bootloader modules
pub mod capsule;
pub mod config;
pub mod entropy;
pub mod handoff;
pub mod hardware;
pub mod loader;
pub mod multiboot;
pub mod network;
pub mod security;
pub mod testing;
pub mod ui;
pub mod verify;

// Crypto & logging (use file-based module trees under src/crypto and src/log)
pub mod crypto;
pub mod log;

// ZK verifier (concrete impl lives in src/zkverify.rs)
pub mod zkverify;

// Back-compat, keep the public path `crate::zkmeta` but point it to capsule::zkmeta.
// (This avoids duplicate implementations/files.)
pub use crate::capsule::zkmeta;

// Optional convenience namespace: `crate::zk::*` re-exports zkverify symbols.
pub mod zk {
    pub use crate::zkverify::*;
}
