// build.rs - Advanced NØNOS Boot Compilation Script
// Production-grade build configuration for UEFI bootloader

use std::env;

fn main() {
    // Emit cargo rerun directives for build dependencies
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=Cargo.toml");
    
    // Set target-specific compilation flags
    configure_uefi_target();
    
    // Configure optimization flags
    configure_optimization();
    
    // Set up cryptographic compilation features
    configure_crypto_features();
    
    // Configure memory layout and security
    configure_security_features();
    
    // Embed version and build information
    embed_build_info();
}

fn configure_uefi_target() {
    // UEFI-specific compilation flags
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=-zmax-page-size=0x1000");
    println!("cargo:rustc-link-arg=-static");
    println!("cargo:rustc-link-arg=--gc-sections");
    
    // UEFI subsystem configuration
    if cfg!(target_os = "uefi") {
        println!("cargo:rustc-link-arg=/SUBSYSTEM:EFI_APPLICATION");
        println!("cargo:rustc-link-arg=/ENTRY:efi_main");
        println!("cargo:rustc-link-arg=/MERGE:.rdata=.data");
    }
}

fn configure_optimization() {
    // Advanced optimization for production builds
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    
    if profile == "release" {
        // Enable link-time optimization
        println!("cargo:rustc-env=CARGO_CFG_LTO=fat");
        
        // Size optimization flags
        println!("cargo:rustc-link-arg=-Os");
        println!("cargo:rustc-link-arg=--strip-all");
        
        // Security hardening
        println!("cargo:rustc-link-arg=-z,relro");
        println!("cargo:rustc-link-arg=-z,now");
        println!("cargo:rustc-link-arg=-z,noexecstack");
    }
}

fn configure_crypto_features() {
    // Compile-time crypto feature detection
    if cfg!(feature = "zk-snark") {
        println!("cargo:rustc-cfg=feature=\"zk_proofs\"");
        println!("cargo:rustc-env=NONOS_ZK_ENABLED=1");
    }
    
    if cfg!(feature = "efi-rng") {
        println!("cargo:rustc-cfg=feature=\"hardware_rng\"");
        println!("cargo:rustc-env=NONOS_HW_RNG=1");
    }
    
    // Blake3 optimization
    println!("cargo:rustc-cfg=blake3_no_sse2");
    println!("cargo:rustc-cfg=blake3_no_sse41");
    println!("cargo:rustc-cfg=blake3_no_avx2");
    println!("cargo:rustc-cfg=blake3_no_avx512");
}

fn configure_security_features() {
    // Control Flow Integrity
    if cfg!(feature = "nonos-cet") {
        println!("cargo:rustc-link-arg=-fcf-protection=full");
        println!("cargo:rustc-env=NONOS_CET_ENABLED=1");
    }
    
    // Stack protection
    println!("cargo:rustc-link-arg=-fstack-protector-strong");
    
    // Position Independent Executable
    println!("cargo:rustc-link-arg=-fpie");
    
    // ASLR support
    println!("cargo:rustc-link-arg=/DYNAMICBASE");
    println!("cargo:rustc-link-arg=/HIGHENTROPYVA");
    
    // NX bit support
    println!("cargo:rustc-link-arg=/NXCOMPAT");
}

fn embed_build_info() {
    // Embed build timestamp
    let build_time = std::process::Command::new("date")
        .arg("+%Y-%m-%d %H:%M:%S UTC")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    println!("cargo:rustc-env=NONOS_BUILD_TIME={build_time}");
    
    // Embed Git commit hash if available
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output() {
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("cargo:rustc-env=NONOS_GIT_COMMIT={commit}");
    } else {
        println!("cargo:rustc-env=NONOS_GIT_COMMIT=unknown");
    }
    
    // Embed compiler version
    let rustc_version = env::var("RUSTC_VERSION")
        .or_else(|_| {
            std::process::Command::new("rustc")
                .arg("--version")
                .output()
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        })
        .unwrap_or_else(|_| "unknown".to_string());
    
    println!("cargo:rustc-env=NONOS_RUSTC_VERSION={rustc_version}");
    
    // Set bootloader identification
    println!("cargo:rustc-env=NONOS_BOOTLOADER_NAME=NØNOS UEFI Capsule Bootloader");
    println!("cargo:rustc-env=NONOS_BOOTLOADER_VERSION=0.1.0");
}