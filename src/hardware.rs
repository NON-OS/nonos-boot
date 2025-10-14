//! Hardware discovery for NONOS (x86_64/UEFI)

#![allow(dead_code)]

use crate::log::logger::{log_debug, log_info, log_warn};
use uefi::cstr16;
use uefi::prelude::*;

/// ACPI Root System Description Pointer structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RsdpDescriptor {
    pub signature: [u8; 8], // "RSD PTR "
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

/// Hardware discovery results suitable for kernel handoff
#[derive(Debug, Default)]
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

pub fn discover_system_hardware(system_table: &mut SystemTable<Boot>) -> HardwareInfo {
    let mut hardware = HardwareInfo::default();
    let _ = system_table.stdout().output_string(cstr16!("=== HW Discovery ===\r\n"));

    // ACPI RSDP discovery
    hardware.rsdp_address = discover_acpi_rsdp(system_table);
    hardware.acpi_available = hardware.rsdp_address.is_some();
    if hardware.acpi_available {
        log_info("acpi", "ACPI RSDP found");
    } else {
        log_warn("acpi", "ACPI RSDP not found");
    }

    // Memory size
    hardware.memory_size = discover_memory_size(system_table);
    log_info("memory", &format!("Total RAM: {} MiB", hardware.memory_size / (1024*1024)));

    // CPU count (MADT parsing if ACPI available, fallback otherwise)
    hardware.cpu_count = if let Some(rsdp) = hardware.rsdp_address {
        get_cpu_count_from_acpi(rsdp)
    } else { 1 };

    // Device enumeration
    hardware.storage_devices = enumerate_storage(system_table);
    hardware.network_interfaces = enumerate_network(system_table);
    hardware.graphics_devices = enumerate_graphics(system_table);
    hardware.pci_devices = enumerate_pci(system_table);

    // CPU features (NXE, SMEP, SMAP, UMIP)
    let cpu_flags = detect_cpu_features();

    log_info("cpu", &format!("CPU features: NXE={} SMEP={} SMAP={} UMIP={}",
        cpu_flags.nxe, cpu_flags.smep, cpu_flags.smap, cpu_flags.umip));

    display_hardware_summary(&hardware, system_table);

    hardware
}

fn discover_acpi_rsdp(system_table: &mut SystemTable<Boot>) -> Option<u64> {
    for entry in system_table.config_table() {
        if entry.guid == uefi::table::cfg::ACPI2_GUID || entry.guid == uefi::table::cfg::ACPI_GUID {
            let rsdp_ptr = entry.address as u64;
            if validate_rsdp(rsdp_ptr) {
                return Some(rsdp_ptr);
            }
        }
    }
    None
}

fn validate_rsdp(rsdp_address: u64) -> bool {
    unsafe {
        let rsdp = &*(rsdp_address as *const RsdpDescriptor);
        if &rsdp.signature != b"RSD PTR " { return false; }
        let bytes = core::slice::from_raw_parts(rsdp_address as *const u8, 20);
        let sum: u8 = bytes.iter().fold(0, |acc, &b| acc.wrapping_add(b));
        sum == 0
    }
}

// Kernel should parse MADT table for true count; here we fallback to 1 for safety.
fn get_cpu_count_from_acpi(_rsdp_address: u64) -> usize {
    // Next development: parse MADT table for APIC count
    log_debug("acpi", "MADT parsing for CPU count not implemented; defaulting to 1");
    1
}

fn discover_memory_size(system_table: &mut SystemTable<Boot>) -> u64 {
    let bs = system_table.boot_services();
    let map = bs.memory_map_size();
    let buf_size = map.map_size + (map.entry_size * 8);
    if let Ok(ptr) = bs.allocate_pages(
        uefi::table::boot::AllocateType::AnyPages,
        uefi::table::boot::MemoryType::LOADER_DATA,
        buf_size.div_ceil(4096),
    ) {
        let buf = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, buf_size) };
        if let Ok(mem_map) = bs.memory_map(buf) {
            let total = mem_map.entries().map(|desc| desc.page_count * 4096).sum();
            let _ = bs.free_pages(ptr, buf_size.div_ceil(4096));
            return total;
        }
        let _ = bs.free_pages(ptr, buf_size.div_ceil(4096));
    }
    0
}

// Storage: BlockIO
fn enumerate_storage(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let count = bs.find_handles::<uefi::proto::media::block::BlockIO>().map(|h| h.len()).unwrap_or(0);
    log_info("storage", &format!("Storage devices: {}", count));
    count
}

// Network: SNP
fn enumerate_network(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let count = bs.find_handles::<uefi::proto::network::snp::SimpleNetwork>().map(|h| h.len()).unwrap_or(0);
    log_info("network", &format!("Network interfaces: {}", count));
    count
}

// Graphics: GOP
fn enumerate_graphics(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let count = bs.find_handles::<uefi::proto::console::gop::GraphicsOutput>().map(|h| h.len()).unwrap_or(0);
    log_info("graphics", &format!("Graphics devices: {}", count));
    count
}

// PCI: DevicePath but parsing is deferred to kernel
fn enumerate_pci(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let count = bs.find_handles::<uefi::proto::device_path::DevicePath>().map(|h| h.len()).unwrap_or(0);
    log_info("pci", &format!("PCI devices: {}", count));
    count
}

// CPU features: NXE, SMEP, SMAP, UMIP
#[derive(Default)]
pub struct CpuFeatureFlags { pub nxe: bool, pub smep: bool, pub smap: bool, pub umip: bool }

pub fn detect_cpu_features() -> CpuFeatureFlags {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut flags = CpuFeatureFlags::default();
        // CPUID: leaf 0x80000001, EDX[20] = NX
        let (_, _, _, edx) = cpuid(0x80000001);
        flags.nxe = (edx & (1 << 20)) != 0;
        // CPUID: leaf 7, EBX[7]=SMEP EBX[20]=SMAP EBX[2]=UMIP
        let (_, ebx, _, _) = cpuid(7);
        flags.smep = (ebx & (1 << 7)) != 0;
        flags.smap = (ebx & (1 << 20)) != 0;
        flags.umip = (ebx & (1 << 2)) != 0;
        flags
    }
    #[cfg(not(target_arch = "x86_64"))]
    { CpuFeatureFlags::default() }
}

#[cfg(target_arch = "x86_64")]
unsafe fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32;
    let mut edx: u32;
    core::arch::asm!(
        "cpuid",
        inout("eax") leaf => eax,
        lateout("ebx") ebx,
        lateout("ecx") ecx,
        lateout("edx") edx,
        options(nostack, preserves_flags)
    );
    (eax, ebx, ecx, edx)
}

fn display_hardware_summary(h: &HardwareInfo, system_table: &mut SystemTable<Boot>) {
    let _ = system_table.stdout().output_string(cstr16!("=== HW Summary ===\r\n"));
    let _ = system_table.stdout().output_string(if h.acpi_available { cstr16!("ACPI: available\r\n") } else { cstr16!("ACPI: not found\r\n") });
    let _ = system_table.stdout().output_string(cstr16!("Memory (MiB): "));
    let _ = system_table.stdout().output_string(cstr16!("Memory: "));
    let _ = system_table.stdout().output_string(cstr16!("CPUs: "));
    let _ = system_table.stdout().output_string(cstr16!("Storage: "));
    let _ = system_table.stdout().output_string(cstr16!("Network: "));
    let _ = system_table.stdout().output_string(cstr16!("Graphics: "));
    let _ = system_table.stdout().output_string(cstr16!("PCI: "));
    let _ = system_table.stdout().output_string(cstr16!("==============\r\n\r\n"));
}
