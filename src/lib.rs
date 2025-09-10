#![no_std]
#![no_main]

extern crate alloc;

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
pub mod zkmeta;
pub mod zkverify;

// Crypto modules
pub mod crypto {
    pub mod sig;
}
// ZK modules
pub mod zk {
    pub use crate::zkverify::*;
}
// Logging modules
pub mod log {
    pub mod logger;
}
