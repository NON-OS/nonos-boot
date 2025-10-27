//! UEFI-ELF Loader for our NONOS micro-kernel.
//! We will add docs with specifications for contributors.

#![no_std]

// Logger functions.
use crate::log::logger::{log_error, log_info};
use crate::verify::{load_validated_capsule, CapsuleMetadata};
use core::fmt;
use goblin::elf::{header, program_header, Elf};
use uefi::prelude::*;
use uefi::table::boot::{AllocateType, MemoryType, PhysicalAddress};

const PAGE_SIZE: usize = 0x1000;
const MAX_LOADS: usize = 32;
const MAX_ALLOCS: usize = 64;

/// Loader-side errors with explicit variants for easy logging/diagnosis.
#[derive(Debug)]
pub enum LoaderError {
    CapsuleInvalid,
    ElfParseError(&'static str),
    UnsupportedElf(&'static str),
    SegmentOutOfBounds,
    AllocationFailed { addr: u64, pages: usize, status: Status },
    UefiError { desc: &'static str, status: Status },
    NoLoadableSegments,
    EntryNotInRange,
    AllocationTableFull,
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderError::CapsuleInvalid => write!(f, "capsule validation failed"),
            LoaderError::ElfParseError(s) => write!(f, "ELF parse failed: {}", s),
            LoaderError::UnsupportedElf(s) => write!(f, "unsupported ELF: {}", s),
            LoaderError::SegmentOutOfBounds => write!(f, "ELF program header out-of-bounds"),
            LoaderError::AllocationFailed { addr, pages, status } =>
                write!(f, "Allocation failed at 0x{:x} ({} pages): {:?}", addr, pages, status),
            LoaderError::UefiError { desc, status } =>
                write!(f, "{}: {:?}", desc, status),
            LoaderError::NoLoadableSegments => write!(f, "no PT_LOAD segments found"),
            LoaderError::EntryNotInRange => write!(f, "ELF entry not inside loaded image range"),
            LoaderError::AllocationTableFull => write!(f, "allocation bookkeeping table full"),
        }
    }
}

/// KernelImage: returned to the caller so handoff can ExitBootServices and jump.
#[derive(Debug, Clone)]
pub struct KernelImage {
    pub address: usize,
    pub size: usize,
    pub entry_point: usize,
    pub metadata: CapsuleMetadata,
    pub allocations: [(u64, usize); MAX_ALLOCS],
    pub alloc_count: usize,
}

pub type LoaderResult<T> = core::result::Result<T, LoaderError>;

/// Record an allocation in the fixed bookkeeping table.
fn record_alloc(table: &mut [(u64, usize); MAX_ALLOCS], count: &mut usize, addr: u64, pages: usize) -> LoaderResult<()> {
    if *count >= MAX_ALLOCS {
        return Err(LoaderError::AllocationTableFull);
    }
    table[*count] = (addr, pages);
    *count += 1;
    Ok(())
}

// Now accepts system table boot for logging so we can emit audit logs.
fn free_all(st: &mut SystemTable<Boot>, bs: &uefi::table::boot::BootServices, table: &[(u64, usize); MAX_ALLOCS], count: usize) {
    for i in 0..count {
        let (addr, pages) = table[i];
        if addr == 0 || pages == 0 { continue; }
        match bs.free_pages(addr, pages) {
            Ok(_) => log_info(st, "loader", &format!("Freed pages at 0x{:x} ({} pages)", addr, pages)),
            Err(e) => log_error(st, "loader", &format!("free_pages failed for 0x{:x} ({}): {:?}", addr, pages, e.status())),
        }
    }
}

// load_kernel: main loader entry point.
pub fn load_kernel(system_table: &mut SystemTable<Boot>, capsule_bytes: &[u8]) -> LoaderResult<KernelImage> {
    // 1. Log start.
    log_info(system_table, "loader", "Starting kernel load operation.");

    // 2. Validate the capsule with payload slice.
    let payload = load_validated_capsule(capsule_bytes).ok_or_else(|| {
        log_error(system_table, "loader", "Capsule validation failed.");
        LoaderError::CapsuleInvalid
    })?;

    // 3. Parse the ELF using goblin.
    let elf = Elf::parse(&payload).map_err(|e| {
        log_error(system_table, "loader", &format!("ELF parse failed: {:?}", e));
        LoaderError::ElfParseError("goblin parse error")
    })?;

    // 4. Header check sanity.
    if !elf.is_64 {
        log_error(system_table, "loader", "ELF is not 64-bit.");
        return Err(LoaderError::UnsupportedElf("not 64-bit"));
    }
    if elf.header.e_machine != header::EM_X86_64 {
        log_error(system_table, "loader", "ELF machine is not x86_64.");
        return Err(LoaderError::UnsupportedElf("non-x86_64"));
    }

    // 5. Image type (for us ET_EXEC (fixed addresses).
    // ET_DYN (Position independent).
    let is_exec = elf.header.e_type == header::ET_EXEC;
    let is_dyn = elf.header.e_type == header::ET_DYN;
    if !is_exec && !is_dyn {
        log_error(system_table, "loader", "Unsupported ELF type.");
        return Err(LoaderError::UnsupportedElf("unsupported e_type"));
    }

    // 6. BootService.
    let bs = system_table.boot_services();

    // 7. Fixed size load table.
    let mut loads: [(usize, usize, usize, u64, usize, u32); MAX_LOADS] = [(0,0,0,0,0,0); MAX_LOADS];
    let mut load_count: usize = 0;

    // 8. Compute union bounds
    let mut min_addr: Option<u64> = None;
    let mut max_addr: Option<u64> = None;

    // 9. Iterate program headers.
    for ph in &elf.program_headers {
        if ph.p_type != program_header::PT_LOAD { continue; }
        if load_count >= MAX_LOADS {
            log_error(system_table, "loader", "too many PT_LOADs for fixed table");
            return Err(LoaderError::AllocationTableFull);
        }

        // copy.
        let p_offset = ph.p_offset as usize; // to segment data
        let p_filesz = ph.p_filesz as usize; // bytes in file
        let p_memsz = ph.p_memsz as usize;   // bytes in memory

        // Bounds checks.
        if p_offset.checked_add(p_filesz).map_or(true, |end| end > payload.len()) {
            log_error(system_table, "loader", "ELF program header indicates file data outside payload bounds.");
            return Err(LoaderError::SegmentOutOfBounds);
        }

        // Physical address target: prefer p_paddr else p_vaddr
        let target = if ph.p_paddr != 0 { ph.p_paddr } else { ph.p_vaddr } as u64;
        if target == 0 {
            log_error(system_table, "loader", "PT_LOAD has no placement address.");
            return Err(LoaderError::UnsupportedElf("no placement address"));
        }

        // Compute page-aligned extents
        let base_page = target & !((PAGE_SIZE as u64) - 1);
        let offset_into_page = (target - base_page) as usize;
        let seg_start = base_page + (offset_into_page as u64);
        let seg_end = seg_start + (p_memsz as u64);

        // Expand union
        min_addr = Some(min_addr.map_or(seg_start, |m| m.min(seg_start)));
        max_addr = Some(max_addr.map_or(seg_end, |m| m.max(seg_end)));

        loads[load_count] = (p_offset, p_filesz, p_memsz, target, ph.p_align as usize, ph.p_flags);
        load_count += 1;
    }

    if load_count == 0 {
        log_error(system_table, "loader", "No PT_LOAD segments found in ELF payload.");
        return Err(LoaderError::NoLoadableSegments);
    }

    // Compute union region
    let base = min_addr.unwrap();
    let end = max_addr.unwrap();
    let total_bytes = end.checked_sub(base).ok_or(LoaderError::UefiError { desc: "size underflow", status: Status::OUT_OF_RESOURCES })? as usize;
    let pages_needed = (total_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    let mut allocations: [(u64, usize); MAX_ALLOCS] = [(0,0); MAX_ALLOCS];
    let mut alloc_count: usize = 0;

    //------------------ET_EXEC: allocate at linked base------------------
    if is_exec {
        let mut alloc_addr: PhysicalAddress = base;
        match bs.allocate_pages(AllocateType::Address, MemoryType::LOADER_DATA, pages_needed, &mut alloc_addr) {
            Ok(_) => {
                record_alloc(&mut allocations, &mut alloc_count, alloc_addr, pages_needed)?;
                log_info(system_table, "loader", &format!("Allocated {} pages at 0x{:x} for kernel (ET_EXEC)", pages_needed, alloc_addr));
            }
            Err(e) => {
                log_error(system_table, "loader", &format!("Failed to allocate {} pages at 0x{:x}: {:?}", pages_needed, base, e.status()));
                return Err(LoaderError::AllocationFailed { addr: base, pages: pages_needed, status: e.status() });
            }
        }

        for i in 0..load_count {
            let (p_offset, p_filesz, p_memsz, target, _align, _flags) = loads[i];
            let dst_phys = target as usize;
            if p_filesz > 0 {
                unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr().add(p_offset), dst_phys as *mut u8, p_filesz); }
                log_info(system_table, "loader", &format!("Copied {} bytes to 0x{:x}", p_filesz, dst_phys));
            }

            if p_memsz > p_filesz {
                unsafe { core::ptr::write_bytes((dst_phys + p_filesz) as *mut u8, 0, p_memsz - p_filesz); }
                log_info(system_table, "loader", &format!("Zeroed {} bytes at 0x{:x}", p_memsz - p_filesz, dst_phys + p_filesz));
            }
        }

        let entry = elf.header.e_entry as usize;
        if !(entry >= base as usize && entry < base as usize + total_bytes) {
            free_all(system_table, bs, &allocations, alloc_count);
            log_error(system_table, "loader", "ELF entry not contained within loaded segments.");
            return Err(LoaderError::EntryNotInRange);
        }

        // Build KernelImage
        let k = KernelImage {
            address: base as usize,
            size: total_bytes,
            entry_point: entry,
            metadata: CapsuleMetadata { offset_sig: 0, len_sig: 0, offset_payload: 0, len_payload: payload.len() },
            allocations,
            alloc_count,
        };
        log_info(system_table, "loader", &format!("Kernel loaded: base=0x{:x} size=0x{:x} entry=0x{:x}", k.address, k.size, k.entry_point));
        return Ok(k);
    }

    // -------------------ET_DYN path: allocate AnyPages, relocate segments---------------------
    {
        let mut alloc_addr: PhysicalAddress = 0;
        match bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages_needed, &mut alloc_addr) {
            Ok(_) => {
                record_alloc(&mut allocations, &mut alloc_count, alloc_addr, pages_needed)?;
                log_info(system_table, "loader", &format!("Allocated {} pages at 0x{:x} for ET_DYN image", pages_needed, alloc_addr));
            }
            Err(e) => {
                log_error(system_table, "loader", &format!("ET_DYN allocation failed: {:?}", e.status()));
                return Err(LoaderError::AllocationFailed { addr: 0, pages: pages_needed, status: e.status() });
            }
        }

        let base_phys = alloc_addr as u64;

        for i in 0..load_count {
            let (p_offset, p_filesz, p_memsz, target, _align, _flags) = loads[i];
            let rel = (target as u64).wrapping_sub(base);
            let dst = (base_phys + rel) as usize;
            if p_filesz > 0 {
                unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr().add(p_offset), dst as *mut u8, p_filesz); }
            }
            if p_memsz > p_filesz {
                unsafe { core::ptr::write_bytes((dst + p_filesz) as *mut u8, 0, p_memsz - p_filesz); }
            }
        }

        // End, Compute relocated entry.
        let entry_rel = elf.header.e_entry as u64;
        let entry_phys = (base_phys as usize).checked_add(entry_rel as usize).ok_or(LoaderError::UefiError { desc: "entry overflow", status: Status::OUT_OF_RESOURCES })?;

        let image = KernelImage {
            address: base_phys as usize,
            size: pages_needed * PAGE_SIZE,
            entry_point: entry_phys,
            metadata: CapsuleMetadata { offset_sig: 0, len_sig: 0, offset_payload: 0, len_payload: payload.len() },
            allocations,
            alloc_count,
        };
        log_info(system_table, "loader", &format!("ET_DYN kernel loaded at 0x{:x} size=0x{:x} entry=0x{:x}", image.address, image.size, image.entry_point));
        return Ok(image);
    }
}
