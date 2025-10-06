//! Hardware Discovery and ACPI Support for NØNOS
//! 
//! - ACPI RSDP discovery via UEFI config table (ACPI2 then ACPI1).
//! - Minimal XSDT/RSDT walk to locate MADT and count Processor Local APIC entries (type 0).
//! - Memory topology summary using UEFI memory map.
//! - Device enumeration counts (BlockIO, SimpleFileSystem, SNP, GOP).
//! - CPU feature detection (best-effort).
//!
//! This file is conservative and no_std-compatible: no heap, minimal formatting.
//! MADT parsing is minimal (just counts type 0 entries) and is intended only to estimate CPU count.

#![allow(dead_code)]

use core::{mem};

use uefi::prelude::*;
use uefi::{cstr16};
use uefi::proto::media::fs::SimpleFileSystem;
use crate::log::logger::{log_info, log_warn, log_debug};

/// ACPI RSDP (20-byte area + ACPI2 extension fields are read when present).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RsdpDescriptor20 {
    signature: [u8; 8],     // "RSD PTR "
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

/// Generic ACPI table header
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct AcpiTableHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// Minimal MADT header (immediately follows AcpiTableHeader)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MadtHeader {
    local_apic_address: u32,
    flags: u32,
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

/// Top-level discovery
pub fn discover_system_hardware(system_table: &mut SystemTable<Boot>) -> HardwareInfo {
    let mut hw = HardwareInfo::default();

    system_table.stdout().output_string(cstr16!("=== Advanced Hardware Discovery ===\r\n")).unwrap_or(());

    // ACPI discovery
    if let Some(rsdp_addr) = discover_acpi_tables(system_table) {
        hw.acpi_available = true;
        hw.rsdp_address = Some(rsdp_addr);
        system_table.stdout().output_string(cstr16!("   [SUCCESS] ACPI tables found\r\n")).unwrap_or(());
        log_info("acpi", "ACPI support available");

        let cpu_count = get_cpu_count_from_acpi(rsdp_addr);
        if cpu_count > 0 {
            hw.cpu_count = cpu_count;
        }
    } else {
        system_table.stdout().output_string(cstr16!("   [WARN] ACPI tables not found\r\n")).unwrap_or(());
        log_warn("acpi", "ACPI tables not available");
    }

    // Memory
    hw.memory_size = discover_memory_topology(system_table);

    // Devices
    hw.storage_devices = enumerate_storage_devices(system_table);
    hw.network_interfaces = enumerate_network_devices(system_table);
    hw.graphics_devices = enumerate_graphics_devices(system_table);
    hw.pci_devices = enumerate_pci_devices(system_table);

    // CPU features (best-effort)
    detect_cpu_features(system_table);

    display_hardware_summary(&hw, system_table);

    log_info("hardware", "Hardware discovery completed");
    hw
}

/* ---------------- ACPI discovery & parsing (minimal) ---------------- */

fn discover_acpi_tables(system_table: &SystemTable<Boot>) -> Option<u64> {
    // Look for ACPI 2.0 first
    for entry in system_table.config_table() {
        if entry.guid == uefi::table::cfg::ACPI2_GUID {
            let addr = entry.address as u64;
            if validate_rsdp(addr) {
                log_debug("acpi", "Found ACPI2 RSDP in config table");
                return Some(addr);
            }
        }
    }

    // Fallback ACPI 1.0
    for entry in system_table.config_table() {
        if entry.guid == uefi::table::cfg::ACPI_GUID {
            let addr = entry.address as u64;
            if validate_rsdp(addr) {
                log_debug("acpi", "Found ACPI1 RSDP in config table");
                return Some(addr);
            }
        }
    }

    None
}

/// Basic RSDP validation (signature + first checksum).
fn validate_rsdp(rsdp_address: u64) -> bool {
    if rsdp_address == 0 {
        return false;
    }

    unsafe {
        // signature at offset 0, 8 bytes
        let sig_ptr = rsdp_address as *const u8;
        let sig = core::slice::from_raw_parts(sig_ptr, 8);
        if sig != b"RSD PTR " {
            return false;
        }

        // checksum over first 20 bytes (ACPI 1.0)
        let b0 = core::slice::from_raw_parts(sig_ptr, 20);
        let sum: u8 = b0.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if sum != 0 {
            return false;
        }

        // optional: if revision >=2, basic extended check attempt (not fatal)
        let revision = *sig_ptr.add(15);
        if revision >= 2 {
            // ensure there are at least 36 bytes available (best-effort check)
            let ext = core::slice::from_raw_parts(sig_ptr, 36);
            let sum2: u8 = ext.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
            if sum2 != 0 {
                log_debug("acpi", "RSDP extended checksum failed (continuing)");
            }
        }
    }

    true
}

/// Attempt to derive CPU count from ACPI (MADT)
fn get_cpu_count_from_acpi(rsdp_address: u64) -> usize {
    unsafe {
        // get revision at offset 15
        let rev = *(rsdp_address as *const u8).add(15);
        if rev >= 2 {
            // XSDT address at offset 24 (u64)
            let xsdt_ptr = (rsdp_address + 24) as *const u64;
            let xsdt_addr = xsdt_ptr.read_unaligned();
            if xsdt_addr != 0 {
                if let Some(c) = parse_xsdt_for_madt(xsdt_addr) {
                    return c;
                }
            }
        } else {
            // RSDT address at offset 16 (u32)
            let rsdt_ptr = (rsdp_address + 16) as *const u32;
            let rsdt_addr = rsdt_ptr.read_unaligned() as u64;
            if rsdt_addr != 0 {
                if let Some(c) = parse_rsdt_for_madt(rsdt_addr) {
                    return c;
                }
            }
        }
    }
    0
}

fn parse_xsdt_for_madt(xsdt_addr: u64) -> Option<usize> {
    unsafe {
        if xsdt_addr == 0 { return None; }
        let hdr = &*(xsdt_addr as *const AcpiTableHeader);
        if hdr.signature != *b"XSDT" { return None; }
        let total_len = hdr.length as usize;
        let header_size = mem::size_of::<AcpiTableHeader>();
        if total_len <= header_size { return None; }
        let entries_bytes = total_len - header_size;
        let entry_count = entries_bytes / 8;
        let entries_ptr = (xsdt_addr + header_size as u64) as *const u64;

        for i in 0..entry_count {
            let table_addr = entries_ptr.add(i).read_unaligned() as u64;
            if table_addr == 0 { continue; }
            if let Some(cnt) = try_parse_madt(table_addr) {
                return Some(cnt);
            }
        }
    }
    None
}

fn parse_rsdt_for_madt(rsdt_addr: u64) -> Option<usize> {
    unsafe {
        if rsdt_addr == 0 { return None; }
        let hdr = &*(rsdt_addr as *const AcpiTableHeader);
        if hdr.signature != *b"RSDT" { return None; }
        let total_len = hdr.length as usize;
        let header_size = mem::size_of::<AcpiTableHeader>();
        if total_len <= header_size { return None; }
        let entries_bytes = total_len - header_size;
        let entry_count = entries_bytes / 4;
        let entries_ptr = (rsdt_addr + header_size as u64) as *const u32;

        for i in 0..entry_count {
            let table_addr = entries_ptr.add(i).read_unaligned() as u64;
            if table_addr == 0 { continue; }
            if let Some(cnt) = try_parse_madt(table_addr) {
                return Some(cnt);
            }
        }
    }
    None
}

/// Minimal MADT parser: returns Some(processor_count) if table parsed and had processor entries.
fn try_parse_madt(table_addr: u64) -> Option<usize> {
    unsafe {
        if table_addr == 0 { return None; }
        let hdr = &*(table_addr as *const AcpiTableHeader);
        if hdr.signature != *b"APIC" { return None; } // MADT signature == "APIC"
        let tbl_len = hdr.length as usize;
        let header_size = mem::size_of::<AcpiTableHeader>();
        if tbl_len <= header_size + mem::size_of::<MadtHeader>() { return None; }

        // entries start after AcpiTableHeader + MadtHeader
        let entries_offset = header_size + mem::size_of::<MadtHeader>();
        let entries_len = tbl_len - entries_offset;
        let entries_ptr = (table_addr + entries_offset as u64) as *const u8;

        let mut off = 0usize;
        let mut lapic_count = 0usize;

        while off + 2 <= entries_len {
            let entry_type = *entries_ptr.add(off);
            let entry_len = *entries_ptr.add(off + 1) as usize;
            if entry_len < 2 { break; }
            if off + entry_len > entries_len { break; }

            if entry_type == 0 {
                // Processor Local APIC (type 0) -> count as CPU
                lapic_count = lapic_count.wrapping_add(1);
            }

            off += entry_len;
        }

        if lapic_count > 0 {
            log_debug("acpi", "MADT parsed, found local APIC entries");
            return Some(lapic_count);
        }
    }
    None
}

/* ---------------- Memory topology ---------------- */

fn discover_memory_topology(system_table: &mut SystemTable<Boot>) -> u64 {
    let bs = system_table.boot_services();
    let mm_size = bs.memory_map_size();
    let buf_size = mm_size.map_size + (mm_size.entry_size * 8);
    let pages = (buf_size + 4095) / 4096;

    if let Ok(buf_ptr) = bs.allocate_pages(uefi::table::boot::AllocateType::AnyPages, uefi::table::boot::MemoryType::LOADER_DATA, pages) {
        let buffer = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_size) };
        if let Ok(memory_map) = bs.memory_map(buffer) {
            let mut total = 0u64;
            let mut found_usable = 0u64;
            for desc in memory_map.entries() {
                let bytes = (desc.page_count as u64) * 4096u64;
                total = total.wrapping_add(bytes);
                if found_usable == 0 && desc.ty == uefi::table::boot::MemoryType::CONVENTIONAL && bytes >= 16 * 1024 * 1024 && desc.phys_start >= 0x100000 {
                    found_usable = desc.phys_start;
                }
            }
            let _ = bs.free_pages(buf_ptr, pages);
            if found_usable != 0 {
                log_info("memory", "Memory topology analyzed (usable region found)");
            } else {
                log_debug("memory", "Memory topology analyzed (no clear large conventional region)");
            }
            return total;
        } else {
            let _ = bs.free_pages(buf_ptr, pages);
        }
    }

    system_table.stdout().output_string(cstr16!("   [WARN] Memory topology analysis failed\r\n")).unwrap_or(());
    0
}

/* ---------------- Device enumeration ---------------- */

fn enumerate_storage_devices(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let mut count = 0usize;

    if let Ok(block_handles) = bs.find_handles::<uefi::proto::media::block::BlockIO>() {
        count = count.wrapping_add(block_handles.len());
    }

    // Count filesystems (not added to count to avoid duplication; keep as diagnostics)
    if let Ok(_fs_handles) = bs.find_handles::<SimpleFileSystem>() {
        // intentionally not double-counting
    }

    if count > 0 {
        system_table.stdout().output_string(cstr16!("   [SUCCESS] Storage devices enumerated\r\n")).unwrap_or(());
        log_info("storage", "Storage devices detected");
    }

    count
}

fn enumerate_network_devices(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let mut count = 0usize;
    if let Ok(snp_handles) = bs.find_handles::<uefi::proto::network::snp::SimpleNetwork>() {
        count = count.wrapping_add(snp_handles.len());
    }
    if count > 0 {
        system_table.stdout().output_string(cstr16!("   [SUCCESS] Network interfaces enumerated\r\n")).unwrap_or(());
        log_info("network", "Network interfaces detected");
    }
    count
}

fn enumerate_graphics_devices(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let mut count = 0usize;
    if let Ok(gop_handles) = bs.find_handles::<uefi::proto::console::gop::GraphicsOutput>() {
        count = count.wrapping_add(gop_handles.len());
    }
    if count > 0 {
        system_table.stdout().output_string(cstr16!("   [SUCCESS] Graphics devices enumerated\r\n")).unwrap_or(());
        log_info("graphics", "Graphics devices detected");
    }
    count
}

fn enumerate_pci_devices(system_table: &mut SystemTable<Boot>) -> usize {
    // Conservative: count device-path handles as a rough proxy (proper PCI enumeration is more involved).
    let bs = system_table.boot_services();
    if let Ok(handles) = bs.find_handles::<uefi::proto::device_path::DevicePath>() {
        if !handles.is_empty() {
            log_info("pci", "Device-path handles found (approximate PCI count)");
        }
        handles.len()
    } else {
        0
    }
}

/* ---------------- CPU features (best-effort) ---------------- */

fn detect_cpu_features(system_table: &mut SystemTable<Boot>) {
    system_table.stdout().output_string(cstr16!("   [INFO] CPU feature detection\r\n")).unwrap_or(());

    #[cfg(target_arch = "x86_64")]
    unsafe {
        if has_cpuid() {
            let (_a, _b, ecx, _d) = cpuid(1);
            if ecx & (1 << 0) != 0 { log_debug("cpu", "SSE3 supported"); }
            if ecx & (1 << 9) != 0 { log_debug("cpu", "SSSE3 supported"); }
            if ecx & (1 << 19) != 0 { log_debug("cpu", "SSE4.1 supported"); }
            if ecx & (1 << 20) != 0 { log_debug("cpu", "SSE4.2 supported"); }
            if ecx & (1 << 28) != 0 { log_debug("cpu", "AVX supported"); }

            let (_a, _b, _ecx_ext, edx_ext) = cpuid(0x80000001);
            if edx_ext & (1 << 20) != 0 { log_debug("cpu", "NX bit supported"); }
        }
    }

    system_table.stdout().output_string(cstr16!("   [SUCCESS] CPU features analyzed\r\n")).unwrap_or(());
    log_info("cpu", "CPU feature detection completed");
}

#[cfg(target_arch = "x86_64")]
unsafe fn has_cpuid() -> bool {
    // Conservative assumption for modern x86_64 systems
    true
}

/// CPUID using inline asm that saves/restores RBX to avoid LLVM complaints.
/// Returns (eax, ebx, ecx, edx)
#[cfg(target_arch = "x86_64")]
unsafe fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let mut eax: u32 = 0;
    let mut ebx: u32 = 0;
    let mut ecx: u32 = 0;
    let mut edx: u32 = 0;

    core::arch::asm!(
        "push rbx",
        "cpuid",
        "mov {ebx_out:e}, ebx",
        "pop rbx",
        ebx_out = out(reg) ebx,
        inout("eax") leaf => eax,
        inout("ecx") 0 => ecx,
        out("edx") edx,
        options(nostack, preserves_flags),
    );

    (eax, ebx, ecx, edx)
}

/* ---------------- Summary UI ---------------- */

fn display_hardware_summary(hardware: &HardwareInfo, system_table: &mut SystemTable<Boot>) {
    system_table.stdout().output_string(cstr16!("\r\n=== Hardware Summary ===\r\n")).unwrap_or(());

    if hardware.acpi_available {
        system_table.stdout().output_string(cstr16!("ACPI:              Available\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("ACPI:              Not Available\r\n")).unwrap_or(());
    }

    let memory_mb = hardware.memory_size / (1024 * 1024);
    if memory_mb > 0 {
        system_table.stdout().output_string(cstr16!("Memory:            Detected\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("Memory:            Unknown\r\n")).unwrap_or(());
    }

    system_table.stdout().output_string(cstr16!("CPUs:              ")).unwrap_or(());
    if hardware.cpu_count == 1 {
        system_table.stdout().output_string(cstr16!("1\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("Multiple\r\n")).unwrap_or(());
    }

    if hardware.storage_devices > 0 {
        system_table.stdout().output_string(cstr16!("Storage:           Available\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("Storage:           None\r\n")).unwrap_or(());
    }

    if hardware.network_interfaces > 0 {
        system_table.stdout().output_string(cstr16!("Network:           Available\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("Network:           None\r\n")).unwrap_or(());
    }

    if hardware.graphics_devices > 0 {
        system_table.stdout().output_string(cstr16!("Graphics:          Available\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("Graphics:          None\r\n")).unwrap_or(());
    }

    system_table.stdout().output_string(cstr16!("========================\r\n\r\n")).unwrap_or(());
}
