//! Hardware Discovery and ACPI Support for NØNOS
//! 
//! This module provides comprehensive hardware detection including:
//! - ACPI table discovery and parsing
//! - PCI device enumeration
//! - CPU feature detection
//! - Memory topology analysis
//! - Advanced storage and network device discovery

#![allow(dead_code)]

use uefi::prelude::*;
use uefi::{cstr16, CStr16};
use crate::log::logger::{log_info, log_warn, log_debug};

/// ACPI Root System Description Pointer structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RsdpDescriptor {
    pub signature: [u8; 8],     // "RSD PTR "
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,
    
    // ACPI 2.0+ fields
    pub length: u32,
    pub xsdt_address: u64,
    pub extended_checksum: u8,
    pub reserved: [u8; 3],
}

/// Hardware discovery results
#[derive(Debug)]
pub struct HardwareInfo {
    pub acpi_available: bool,
    pub rsdp_address: Option<u64>,
    pub cpu_count: usize,
    pub memory_size: u64,
    pub pci_devices: usize,
    pub storage_devices: usize,
    pub network_interfaces: usize,
    pub graphics_devices: usize,
}

impl Default for HardwareInfo {
    fn default() -> Self {
        Self {
            acpi_available: false,
            rsdp_address: None,
            cpu_count: 1,
            memory_size: 0,
            pci_devices: 0,
            storage_devices: 0,
            network_interfaces: 0,
            graphics_devices: 0,
        }
    }
}

/// Comprehensive hardware discovery
pub fn discover_system_hardware(system_table: &mut SystemTable<Boot>) -> HardwareInfo {
    let mut hardware = HardwareInfo::default();
    
    system_table.stdout().output_string(cstr16!("=== Advanced Hardware Discovery ===\r\n")).unwrap_or(());
    
    // ACPI Discovery
    if let Some(rsdp_addr) = discover_acpi_tables(system_table) {
        hardware.acpi_available = true;
        hardware.rsdp_address = Some(rsdp_addr);
        system_table.stdout().output_string(cstr16!("   [SUCCESS] ACPI tables found\r\n")).unwrap_or(());
        log_info("acpi", "ACPI support available");
        
        // Parse CPU information from ACPI
        hardware.cpu_count = get_cpu_count_from_acpi(rsdp_addr);
    } else {
        system_table.stdout().output_string(cstr16!("   [WARN] ACPI tables not found\r\n")).unwrap_or(());
        log_warn("acpi", "ACPI tables not available");
    }
    
    // Memory discovery
    hardware.memory_size = discover_memory_topology(system_table);
    
    // Device enumeration
    hardware.storage_devices = enumerate_storage_devices(system_table);
    hardware.network_interfaces = enumerate_network_devices(system_table);
    hardware.graphics_devices = enumerate_graphics_devices(system_table);
    hardware.pci_devices = enumerate_pci_devices(system_table);
    
    // CPU features detection
    detect_cpu_features(system_table);
    
    // Display summary
    display_hardware_summary(&hardware, system_table);
    
    log_info("hardware", "Comprehensive hardware discovery completed");
    hardware
}

/// Discover ACPI tables by searching for RSDP
fn discover_acpi_tables(system_table: &mut SystemTable<Boot>) -> Option<u64> {
    let config_table = system_table.config_table();
    
    // Look for ACPI 2.0 table first
    for entry in config_table {
        if entry.guid == uefi::table::cfg::ACPI2_GUID {
            let rsdp_ptr = entry.address as u64;
            if validate_rsdp(rsdp_ptr) {
                log_info("acpi", "ACPI 2.0 RSDP found");
                return Some(rsdp_ptr);
            }
        }
    }
    
    // Fall back to ACPI 1.0
    for entry in config_table {
        if entry.guid == uefi::table::cfg::ACPI_GUID {
            let rsdp_ptr = entry.address as u64;
            if validate_rsdp(rsdp_ptr) {
                log_info("acpi", "ACPI 1.0 RSDP found");
                return Some(rsdp_ptr);
            }
        }
    }
    
    None
}

/// Validate RSDP checksum and signature
fn validate_rsdp(rsdp_address: u64) -> bool {
    unsafe {
        let rsdp = &*(rsdp_address as *const RsdpDescriptor);
        
        // Check signature
        if &rsdp.signature != b"RSD PTR " {
            return false;
        }
        
        // Basic checksum validation for ACPI 1.0 part
        let bytes = core::slice::from_raw_parts(rsdp_address as *const u8, 20);
        let sum: u8 = bytes.iter().fold(0, |acc, &b| acc.wrapping_add(b));
        
        sum == 0
    }
}

/// Extract CPU count from ACPI tables
fn get_cpu_count_from_acpi(rsdp_address: u64) -> usize {
    // This would require full ACPI parsing - simplified for now
    // In a real implementation, we'd parse the MADT (APIC) table
    log_debug("acpi", "CPU count extraction not yet implemented");
    1 // Default to 1 CPU
}

/// Discover memory topology and size
fn discover_memory_topology(system_table: &mut SystemTable<Boot>) -> u64 {
    let bs = system_table.boot_services();
    let memory_map_size = bs.memory_map_size();
    let buffer_size = memory_map_size.map_size + (memory_map_size.entry_size * 8);
    
    if let Ok(buffer_ptr) = bs.allocate_pages(
        uefi::table::boot::AllocateType::AnyPages, 
        uefi::table::boot::MemoryType::LOADER_DATA, 
        (buffer_size + 4095) / 4096
    ) {
        let buffer = unsafe { 
            core::slice::from_raw_parts_mut(buffer_ptr as *mut u8, buffer_size) 
        };
        
        if let Ok(memory_map) = bs.memory_map(buffer) {
            let mut total_memory = 0u64;
            
            for desc in memory_map.entries() {
                total_memory += desc.page_count * 4096;
            }
            
            let _ = bs.free_pages(buffer_ptr, (buffer_size + 4095) / 4096);
            system_table.stdout().output_string(cstr16!("   [SUCCESS] Memory topology analyzed\r\n")).unwrap_or(());
            
            return total_memory;
        }
        
        let _ = bs.free_pages(buffer_ptr, (buffer_size + 4095) / 4096);
    }
    
    system_table.stdout().output_string(cstr16!("   [WARN] Memory topology analysis failed\r\n")).unwrap_or(());
    0
}

/// Enumerate storage devices
fn enumerate_storage_devices(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let mut count = 0;
    
    // Block I/O devices
    if let Ok(handles) = bs.find_handles::<uefi::proto::media::block::BlockIO>() {
        count += handles.len();
    }
    
    // File system devices
    if let Ok(handles) = bs.find_handles::<uefi::proto::media::fs::SimpleFileSystem>() {
        // We don't double count - these might overlap with BlockIO
        for _handle in handles {
            // Additional file system specific detection could go here maybe 
        }
    }
    
    if count > 0 {
        system_table.stdout().output_string(cstr16!("   [SUCCESS] Storage devices enumerated\r\n")).unwrap_or(());
        log_info("storage", "Storage devices detected");
    }
    
    count
}

/// Enumerate network devices
fn enumerate_network_devices(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let mut count = 0;
    
    // Simple Network Protocol
    if let Ok(handles) = bs.find_handles::<uefi::proto::network::snp::SimpleNetwork>() {
        count += handles.len();
    }
    
    // Additional network protocols would be checked here in a full implementation
    
    if count > 0 {
        system_table.stdout().output_string(cstr16!("   [SUCCESS] Network interfaces enumerated\r\n")).unwrap_or(());
        log_info("network", "Network interfaces detected");
    }
    
    count
}

/// Enumerate graphics devices
fn enumerate_graphics_devices(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let mut count = 0;
    
    if let Ok(handles) = bs.find_handles::<uefi::proto::console::gop::GraphicsOutput>() {
        count += handles.len();
    }
    
    if count > 0 {
        system_table.stdout().output_string(cstr16!("   [SUCCESS] Graphics devices enumerated\r\n")).unwrap_or(());
        log_info("graphics", "Graphics devices detected");
    }
    
    count
}

/// Enumerate PCI devices (simplified)
fn enumerate_pci_devices(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let mut count = 0;
    
    // PCI Root Bridge I/O Protocol
    if let Ok(handles) = bs.find_handles::<uefi::proto::device_path::DevicePath>() {
        // This is a simplified count - real PCI enumeration would require parsing the device paths and looking for PCI-specific ones
        count = handles.len();
    }
    
    if count > 0 {
        system_table.stdout().output_string(cstr16!("   [SUCCESS] PCI devices enumerated\r\n")).unwrap_or(());
        log_info("pci", "PCI devices detected");
    }
    
    count
}

/// Detect CPU features using CPUID instruction
fn detect_cpu_features(system_table: &mut SystemTable<Boot>) {
    system_table.stdout().output_string(cstr16!("   [INFO] CPU feature detection\r\n")).unwrap_or(());
    
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Check for basic CPUID support
        if has_cpuid() {
            let (eax, ebx, ecx, edx) = cpuid(0);
            
            // Check various CPU features
            if ecx & (1 << 0) != 0 { // SSE3
                log_debug("cpu", "SSE3 supported");
            }
            if ecx & (1 << 9) != 0 { // SSSE3
                log_debug("cpu", "SSSE3 supported");
            }
            if ecx & (1 << 19) != 0 { // SSE4.1
                log_debug("cpu", "SSE4.1 supported");
            }
            if ecx & (1 << 20) != 0 { // SSE4.2
                log_debug("cpu", "SSE4.2 supported");
            }
            if ecx & (1 << 28) != 0 { // AVX
                log_debug("cpu", "AVX supported");
            }
            
            // Check for security features
            let (_, _, ecx_ext, edx_ext) = cpuid(0x80000001);
            if edx_ext & (1 << 20) != 0 { // NX bit
                log_debug("cpu", "NX bit supported");
            }
        }
    }
    
    system_table.stdout().output_string(cstr16!("   [SUCCESS] CPU features analyzed\r\n")).unwrap_or(());
    log_info("cpu", "CPU feature detection completed");
}

/// Check if CPUID instruction is available
#[cfg(target_arch = "x86_64")]
unsafe fn has_cpuid() -> bool {
    // This is a simplified check - production implementation would test EFLAGS.ID
    true
}

/// Execute CPUID instruction
#[cfg(target_arch = "x86_64")]
unsafe fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32 = 0; // Initialize ECX to 0
    let mut edx: u32;
    
    // Save and restore rbx since it's used internally by LLVM
    core::arch::asm!(
        "push rbx",
        "cpuid",
        "mov {ebx_out:e}, ebx",
        "pop rbx",
        ebx_out = out(reg) ebx,
        inout("eax") leaf => eax,
        inout("ecx") ecx,
        out("edx") edx,
        options(preserves_flags)
    );
    
    (eax, ebx, ecx, edx)
}

/// Display comprehensive hardware summary
fn display_hardware_summary(hardware: &HardwareInfo, system_table: &mut SystemTable<Boot>) {
    system_table.stdout().output_string(cstr16!("\r\n=== Hardware Summary ===\r\n")).unwrap_or(());
    
    if hardware.acpi_available {
        system_table.stdout().output_string(cstr16!("ACPI:              Available\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("ACPI:              Not Available\r\n")).unwrap_or(());
    }
    
    // Memory size in MB
    let memory_mb = hardware.memory_size / (1024 * 1024);
    if memory_mb > 0 {
        // For now, we just show that memory was detected - proper formatting would require string manipulation
        system_table.stdout().output_string(cstr16!("Memory:            Detected\r\n")).unwrap_or(());
    }
    
    if hardware.cpu_count > 0 {
        system_table.stdout().output_string(cstr16!("CPUs:              Detected\r\n")).unwrap_or(());
    }
    
    if hardware.storage_devices > 0 {
        system_table.stdout().output_string(cstr16!("Storage:           Available\r\n")).unwrap_or(());
    }
    
    if hardware.network_interfaces > 0 {
        system_table.stdout().output_string(cstr16!("Network:           Available\r\n")).unwrap_or(());
    }
    
    if hardware.graphics_devices > 0 {
        system_table.stdout().output_string(cstr16!("Graphics:          Available\r\n")).unwrap_or(());
    }
    
    system_table.stdout().output_string(cstr16!("========================\r\n\r\n")).unwrap_or(());
}
