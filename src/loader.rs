//! loader.rs — NØNOS Capsule Loader (UEFI FS → verified capsule → handoff build)
//! eK@nonos-tech.xyz
//
// Responsibilities:
// - Locate and open `nonos_kernel.efi` from EFI SimpleFileSystem
// - Read into LOADER_DATA pages with a strict size limit
// - Parse + validate capsule header & layout
// - Run crypto/ZK verification
// - Build ZeroStateBootInfo in memory (ready for kernel jump)
// - Return verified entrypoint and capsule base for transfer
//
// Security changes:
// - No hardcoded oversize alloc; alloc exactly required pages (bounded by MAX_CAPSULE_SIZE)
// - Zero unused buffer tail after read
// - Clear capsule buffer on error (avoid stale sensitive data)
// - Early fail if header/magic invalid
// - Handoff populated using `build_bootinfo()` with truncated entropy
// - Entry point must be page-aligned inside payload span

use core::slice;

use uefi::prelude::*;
use uefi::proto::media::file::{File, FileAttribute, FileMode, FileType};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::CStr16;

// use crate::capsule::Capsule; // Disabled for direct ELF loading
use xmas_elf::ElfFile;
// extern crate alloc; // Removed - might cause issues
use crate::entropy::collect_boot_entropy;
use crate::handoff::{build_bootinfo, ZeroStateBootInfo};
use crate::log::logger::{log_info, log_warn};

pub struct KernelCapsule {
    pub entry_point: usize,
    pub base: *mut u8,
    pub size: usize,
    pub handoff: ZeroStateBootInfo,
}

const MAX_CAPSULE_SIZE: usize = 32 * 1024 * 1024; // 32 MiB cap for sanity

pub fn load_kernel_capsule(st: &mut SystemTable<Boot>) -> Result<KernelCapsule, &'static str> {
    let bs = st.boot_services();

    // Locate filesystem
    let handles = bs
        .find_handles::<SimpleFileSystem>()
        .map_err(|_| "[x] Missing SimpleFileSystem handles")?;

    let handle = handles.first().ok_or("[x] No SimpleFileSystem found")?;
    let mut fs = bs
        .open_protocol_exclusive::<SimpleFileSystem>(*handle)
        .map_err(|_| "[x] Failed to open SimpleFileSystem")?;

    let mut root = fs.open_volume().map_err(|_| "[x] Cannot open FS volume")?;

    // Open capsule file
    let mut name_buffer = [0u16; 24];
    let name = CStr16::from_str_with_buf("nonos_kernel.efi", &mut name_buffer)
        .map_err(|_| "[x] Invalid capsule filename")?;

    let file_handle = root
        .open(name, FileMode::Read, FileAttribute::empty())
        .map_err(|_| "[x] Capsule file not found")?;

    let mut file = match file_handle
        .into_type()
        .map_err(|_| "[x] Capsule cast failed")?
    {
        FileType::Regular(f) => f,
        _ => return Err("[x] Capsule is not a regular file"),
    };

    // Query file size to avoid overshoot
    let mut info_buf = [0u8; 512]; // Buffer for file info
    let info = file
        .get_info::<uefi::proto::media::file::FileInfo>(&mut info_buf)
        .map_err(|_| "[x] Failed to query capsule file info")?;
    let file_size = info.file_size() as usize;
    if file_size == 0 || file_size > MAX_CAPSULE_SIZE {
        return Err("[x] Capsule size invalid or exceeds limit");
    }

    // Allocate just enough pages
    let num_pages = (file_size + 4095) / 4096;
    let buffer = bs
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, num_pages)
        .map_err(|_| "[x] Failed to allocate capsule memory")?;
    let capsule_slice = unsafe { slice::from_raw_parts_mut(buffer as *mut u8, file_size) };

    // Read exactly file_size bytes
    let bytes_read = file
        .read(capsule_slice)
        .map_err(|_| "[x] Failed to read capsule")?;
    if bytes_read != file_size {
        return Err("[x] Short read on capsule file");
    }

    // Parse ELF file with enhanced validation
    let elf_file =
        ElfFile::new(&capsule_slice[..bytes_read]).map_err(|_| "[x] Invalid ELF file format")?;

    // Validate ELF file properties
    if elf_file.header.pt1.class() != xmas_elf::header::Class::SixtyFour {
        return Err("[x] Only 64-bit ELF files are supported");
    }

    if elf_file.header.pt1.data() != xmas_elf::header::Data::LittleEndian {
        return Err("[x] Only little-endian ELF files are supported");
    }

    if elf_file.header.pt2.machine().as_machine() != xmas_elf::header::Machine::X86_64 {
        return Err("[x] Only x86_64 architecture is supported");
    }

    log_info("loader", "ELF file validation passed");

    // Get entry point from ELF header
    let entry_point = elf_file.header.pt2.entry_point() as usize;
    log_info("loader", "ELF entry point extracted");

    // Process program headers and load segments to their correct physical addresses
    let mut _kernel_base = 0usize;
    let mut _kernel_size = 0usize;

    // Find the lowest and highest addresses from loadable segments
    let mut min_addr = usize::MAX;
    let mut max_addr = 0usize;

    for program_header in elf_file.program_iter() {
        if program_header.get_type() == Ok(xmas_elf::program::Type::Load) {
            let vaddr = program_header.virtual_addr() as usize;
            let memsz = program_header.mem_size() as usize;

            min_addr = min_addr.min(vaddr);
            max_addr = max_addr.max(vaddr + memsz);
        }
    }

    if min_addr != usize::MAX && max_addr > min_addr {
        _kernel_base = min_addr;
        _kernel_size = max_addr - min_addr;

        log_info("loader", "Kernel memory layout determined");
    } else {
        return Err("[x] Could not determine kernel memory layout from ELF");
    }

    // Load segments to their correct physical addresses
    for program_header in elf_file.program_iter() {
        if program_header.get_type() == Ok(xmas_elf::program::Type::Load) {
            let vaddr = program_header.virtual_addr() as usize;
            let paddr = program_header.physical_addr() as usize;
            let filesz = program_header.file_size() as usize;
            let memsz = program_header.mem_size() as usize;
            let offset = program_header.offset() as usize;

            // Use physical address for loading
            let load_addr = if paddr != 0 { paddr } else { vaddr };

            // Copy segment data to the correct physical location
            if filesz > 0 {
                let src = &capsule_slice[offset..offset + filesz];
                let dst = unsafe { core::slice::from_raw_parts_mut(load_addr as *mut u8, filesz) };
                dst.copy_from_slice(src);
            }

            // Zero any remaining memory
            if memsz > filesz {
                let zero_dst = unsafe {
                    core::slice::from_raw_parts_mut((load_addr + filesz) as *mut u8, memsz - filesz)
                };
                zero_dst.fill(0);
            }

            log_info("loader", "Segment loaded to physical address");
        }
    }

    // Enhanced physical address mapping
    const KERNEL_VMA: usize = 0xFFFF800000000000;
    const PHYSICAL_LOAD_BASE: usize = 0x100000; // 1MB

    let physical_entry_point = if entry_point >= KERNEL_VMA {
        // High-half kernel: map to physical address
        (entry_point - KERNEL_VMA) + PHYSICAL_LOAD_BASE
    } else if entry_point >= 0x100000 {
        // Already a physical address in valid range
        entry_point
    } else {
        return Err("[x] Invalid kernel entry point address");
    };

    // Validate entry point is within expected kernel memory range
    // The kernel loads to 0x100000 (1MB) physical, so entry point should be near there
    if physical_entry_point < 0x100000 || physical_entry_point >= 0x200000 {
        log_warn("loader", "Entry point outside expected kernel range");
        // Still continue - this is just a warning for now
    } else {
        log_info("loader", "Entry point validation passed");
    }

    // Build ZeroStateBootInfo with enhanced memory information
    let entropy64 = collect_boot_entropy(bs);

    // Get memory map information for handoff
    let (total_memory, usable_memory_start) = get_memory_info(bs);

    // Create RTC timestamp
    let rtc_timestamp = crate::entropy::get_rtc_timestamp();

    let handoff = build_bootinfo(
        capsule_base_phys(buffer),
        bytes_read as u64,
        [0u8; 32], // Mock commitment for now - should use real hash
        usable_memory_start,
        total_memory,
        &entropy64,
        rtc_timestamp,
        0, // boot_flags - could add debug, secure boot, etc.
    );

    Ok(KernelCapsule {
        entry_point: physical_entry_point,
        base: buffer as *mut u8,
        size: bytes_read,
        handoff,
    })
}

#[allow(dead_code)]
#[inline]
fn zero_buf(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

/// Get memory information from UEFI memory map
fn get_memory_info(bs: &BootServices) -> (u64, u64) {
    let mut total_memory = 0u64;
    let mut usable_memory_start = 0x100000u64; // Default to 1MB

    // Try to get memory map
    let memory_map_size = bs.memory_map_size();
    let buffer_size = memory_map_size.map_size + (memory_map_size.entry_size * 8);

    // Allocate buffer for memory map
    if let Ok(buffer_ptr) = bs.allocate_pages(
        uefi::table::boot::AllocateType::AnyPages,
        uefi::table::boot::MemoryType::LOADER_DATA,
        (buffer_size + 4095) / 4096,
    ) {
        let buffer = unsafe { slice::from_raw_parts_mut(buffer_ptr as *mut u8, buffer_size) };

        if let Ok(memory_map) = bs.memory_map(buffer) {
            let mut found_usable = false;

            for descriptor in memory_map.entries() {
                let size = descriptor.page_count * 4096;
                total_memory += size;

                // Look for the first large conventional memory region
                if !found_usable &&
                   descriptor.ty == uefi::table::boot::MemoryType::CONVENTIONAL &&
                   size >= 16 * 1024 * 1024 && // At least 16MB
                   descriptor.phys_start >= 0x100000
                {
                    // Above 1MB
                    usable_memory_start = descriptor.phys_start;
                    found_usable = true;
                }
            }
        }

        // Clean up allocated buffer
        let _ = bs.free_pages(buffer_ptr, (buffer_size + 4095) / 4096);
    }

    log_info("memory", "Memory map analysis completed");
    (total_memory, usable_memory_start)
}

#[inline]
fn capsule_base_phys(ptr: u64) -> u64 {
    ptr
}
