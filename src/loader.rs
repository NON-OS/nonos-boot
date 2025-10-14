//! ELF loader for NONOS (UEFI)

#![allow(dead_code)]

use core::mem::{size_of, MaybeUninit};
use core::slice;

use crate::log::logger::{log_error, log_info, log_warn};
use crate::verify::sha256;

use uefi::prelude::*;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode, FileType};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, BootServices, MemoryType};
use uefi::CStr16;

// ------------------------------- Limits --------------------------------

const MAX_KERNEL_FILE_SIZE: usize = 64 * 1024 * 1024; // 64 MiB
const MAX_LOAD_SEGMENTS: usize = 32;                  // sane cap for PT_LOAD segments
const PAGE_SIZE: usize = 4096;

// ------------------------------- ELF types -----------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

// ------------------------------- Output model --------------------------

#[derive(Clone, Copy, Debug, Default)]
pub struct LoadedSegment {
    /// Physical address returned by AllocatePages (LOADER_DATA), page-aligned
    pub phys: u64,
    /// Virtual address requested by ELF (for mapping policy)
    pub vaddr: u64,
    /// File-backed bytes copied into phys
    pub filesz: u64,
    /// Total in-memory size (BSS zeroed for tail)
    pub memsz: u64,
    /// ELF flags (PF_R/PF_W/PF_X)
    pub flags: u32,
    /// Alignment request (power-of-two, or 0/1 for none)
    pub align: u64,
}

#[derive(Debug)]
pub struct LoadedKernel {
    /// Kernel entry virtual address from ELF header
    pub entry_va: u64,
    /// Per-segment allocations (LOADER_DATA)
    pub segments: [LoadedSegment; MAX_LOAD_SEGMENTS],
    pub seg_count: usize,
    /// Raw file size (bytes)
    pub image_size: usize,
    /// SHA-256 of the raw ELF for measurement
    pub image_sha256: [u8; 32],
}

impl Default for LoadedKernel {
    fn default() -> Self {
        Self {
            entry_va: 0,
            segments: [LoadedSegment::default(); MAX_LOAD_SEGMENTS],
            seg_count: 0,
            image_size: 0,
            image_sha256: [0u8; 32],
        }
    }
}

// ------------------------------- Public API ----------------------------

/// Load and stage the kernel ELF into LOADER_DATA pages, returning a LoadedKernel descriptor.
/// The returned buffers must be freed or transitioned by the caller before ExitBootServices if needed.
pub fn load_kernel(bs: &BootServices) -> Result<LoadedKernel, &'static str> {
    let mut root = open_root_fs(bs).map_err(|e| e)?;
    let mut file = open_kernel_file(bs, &mut root).map_err(|e| e)?;

    // Read FileInfo to get size
    let info = file_info(&mut file).map_err(|_| "[x] Failed to query kernel file info")?;
    let file_size = info.file_size() as usize;
    if file_size == 0 || file_size > MAX_KERNEL_FILE_SIZE {
        return Err("[x] Kernel size invalid or exceeds limit");
    }

    // Allocate pages for a temporary read buffer
    let tmp_pages = pages_for(file_size);
    let tmp_phys = bs
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, tmp_pages)
        .map_err(|_| "[x] Failed to allocate read buffer")?;

    let tmp_slice = unsafe { slice::from_raw_parts_mut(tmp_phys as *mut u8, file_size) };
    // Read the file fully
    let n = file.read(tmp_slice).map_err(|_| "[x] Failed to read kernel file")?;
    if n != file_size {
        // Zero on short read and free
        zero_slice(tmp_slice);
        let _ = bs.free_pages(tmp_phys, tmp_pages);
        return Err("[x] Short read on kernel file");
    }

    // Compute measurement early
    let image_sha256 = sha256(tmp_slice);

    // Parse ELF header
    let eh: Elf64Ehdr = read_pod(tmp_slice, 0).ok_or("[x] ELF header truncated")?;
    if &eh.e_ident[0..4] != b"\x7FELF" {
        cleanup_and_err(bs, tmp_phys, tmp_pages, "[x] Bad ELF magic");
        return Err("[x] Bad ELF magic");
    }
    if eh.e_ident[4] != 2 /* 64-bit */ || eh.e_ident[5] != 1 /* little-endian */ {
        cleanup_and_err(bs, tmp_phys, tmp_pages, "[x] Unsupported ELF class/endianness");
        return Err("[x] Unsupported ELF class/endianness");
    }
    if eh.e_machine != 0x3E /* x86_64 */ {
        cleanup_and_err(bs, tmp_phys, tmp_pages, "[x] Unsupported ELF machine");
        return Err("[x] Unsupported ELF machine");
    }
    if eh.e_phentsize as usize != size_of::<Elf64Phdr>() {
        cleanup_and_err(bs, tmp_phys, tmp_pages, "[x] Unexpected program header size");
        return Err("[x] Unexpected program header size");
    }
    if eh.e_phnum == 0 {
        cleanup_and_err(bs, tmp_phys, tmp_pages, "[x] No program headers");
        return Err("[x] No program headers");
    }
    if eh.e_phnum as usize > MAX_LOAD_SEGMENTS {
        cleanup_and_err(
            bs,
            tmp_phys,
            tmp_pages,
            "[x] Too many loadable segments (cap exceeded)",
        );
        return Err("[x] Too many loadable segments (cap exceeded)");
    }

    let mut kernel = LoadedKernel::default();
    kernel.entry_va = eh.e_entry;
    kernel.image_size = file_size;
    kernel.image_sha256 = image_sha256;

    let mut seg_count = 0usize;

    // Iterate PT_LOAD segments
    for i in 0..(eh.e_phnum as usize) {
        let off = eh.e_phoff as usize + i * eh.e_phentsize as usize;
        let ph: Elf64Phdr = match read_pod(tmp_slice, off) {
            Some(v) => v,
            None => {
                cleanup_and_err(bs, tmp_phys, tmp_pages, "[x] Truncated program header");
                return Err("[x] Truncated program header");
            }
        };

        if ph.p_type != PT_LOAD {
            continue;
        }
        if ph.p_memsz == 0 {
            continue;
        }

        // Bounds check the file-backed part
        let filesz = ph.p_filesz as usize;
        let memsz = ph.p_memsz as usize;
        let off = ph.p_offset as usize;

        if filesz > 0 {
            if off.checked_add(filesz).is_none() || off + filesz > tmp_slice.len() {
                cleanup_and_err(bs, tmp_phys, tmp_pages, "[x] Segment exceeds file size");
                return Err("[x] Segment exceeds file size");
            }
        }

        // Enforce no RWX
        if (ph.p_flags & PF_X) != 0 && (ph.p_flags & PF_W) != 0 {
            cleanup_and_err(bs, tmp_phys, tmp_pages, "[x] Refusing RWX segment");
            return Err("[x] Refusing RWX segment");
        }

        // Allocate pages for this segment
        let seg_pages = pages_for(memsz);
        let seg_phys = match bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, seg_pages) {
            Ok(p) => p,
            Err(_) => {
                // Free previous segment allocations before returning
                free_loaded_segments(bs, &kernel.segments, seg_count);
                cleanup_and_err(bs, tmp_phys, tmp_pages, "[x] Out of memory for segment");
                return Err("[x] Out of memory for segment");
            }
        };

        // Copy file-backed bytes
        let dst = unsafe { slice::from_raw_parts_mut(seg_phys as *mut u8, memsz) };
        if filesz > 0 {
            let src = &tmp_slice[off..off + filesz];
            dst[..filesz].copy_from_slice(src);
        }
        // Zero BSS tail
        if memsz > filesz {
            dst[filesz..].fill(0);
        }

        kernel.segments[seg_count] = LoadedSegment {
            phys: seg_phys,
            vaddr: ph.p_vaddr,
            filesz: ph.p_filesz,
            memsz: ph.p_memsz,
            flags: ph.p_flags,
            align: ph.p_align,
        };
        seg_count += 1;
    }

    kernel.seg_count = seg_count;

    // Free the temporary file buffer; segments remain allocated
    zero_slice(tmp_slice); // avoid leaving code/data in free pool
    let _ = bs.free_pages(tmp_phys, tmp_pages);

    log_info("loader", "Kernel ELF validated and staged into LOADER_DATA");
    if seg_count == 0 {
        // Should not happen for a valid kernel
        log_warn("loader", "No PT_LOAD segments found");
    }

    Ok(kernel)
}

// ------------------------------- Helpers --------------------------------

fn open_root_fs(bs: &BootServices) -> Result<uefi::proto::media::file::Directory, &'static str> {
    let handles = bs
        .find_handles::<SimpleFileSystem>()
        .map_err(|_| "[x] SimpleFileSystem handles not found")?;
    let handle = handles.first().ok_or("[x] No SimpleFileSystem available")?;
    let mut fs = bs
        .open_protocol_exclusive::<SimpleFileSystem>(*handle)
        .map_err(|_| "[x] Failed to open SimpleFileSystem")?;
    fs.open_volume().map_err(|_| "[x] Cannot open filesystem volume")
}

fn open_kernel_file<'a>(
    _bs: &BootServices,
    root: &'a mut uefi::proto::media::file::Directory,
) -> Result<uefi::proto::media::file::RegularFile, &'static str> {
    // Keep filename stable for now; configurable via config.rs later.
    let mut name_buffer = [0u16; 64];
    let name = CStr16::from_str_with_buf("nonos_kernel.elf", &mut name_buffer)
        .map_err(|_| "[x] Invalid kernel filename")?;

    let fh = root
        .open(name, FileMode::Read, FileAttribute::empty())
        .map_err(|_| "[x] Kernel file not found")?;

    match fh.into_type().map_err(|_| "[x] File type resolution failed")? {
        FileType::Regular(f) => Ok(f),
        _ => Err("[x] Kernel path is not a regular file"),
    }
}

fn file_info(file: &mut uefi::proto::media::file::RegularFile) -> uefi::Result<FileInfo> {
    // Query into a fixed stack buffer, retry with a pool if too small
    let mut info_buf = [0u8; 512];
    match file.get_info::<FileInfo>(&mut info_buf) {
        Ok(i) => Ok(i),
        Err(e) if e.status() == uefi::Status::BUFFER_TOO_SMALL => {
            // Fall back to a dynamically sized pool buffer
            let needed = e.data().map(|d| d.0).unwrap_or(1024usize);
            let mut dyn_buf = alloc::vec![0u8; needed];
            file.get_info::<FileInfo>(&mut dyn_buf)
        }
        Err(e) => Err(e),
    }
}

#[inline]
fn read_pod<T: Copy>(buf: &[u8], off: usize) -> Option<T> {
    if off.checked_add(size_of::<T>())? > buf.len() {
        return None;
    }
    let mut tmp = MaybeUninit::<T>::uninit();
    unsafe {
        core::ptr::copy_nonoverlapping(
            buf.as_ptr().add(off),
            tmp.as_mut_ptr() as *mut u8,
            size_of::<T>(),
        );
        Some(tmp.assume_init())
    }
}

#[inline]
fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

#[inline]
fn pages_for(bytes: usize) -> usize {
    align_up(bytes.max(1), PAGE_SIZE) / PAGE_SIZE
}

#[inline]
fn zero_slice(s: &mut [u8]) {
    for b in s.iter_mut() {
        *b = 0;
    }
}

fn cleanup_and_err(bs: &BootServices, phys: u64, pages: usize, _msg: &str) {
    // Zero before free to avoid leaking image content in pool
    let s = unsafe { slice::from_raw_parts_mut(phys as *mut u8, pages * PAGE_SIZE) };
    zero_slice(s);
    let _ = bs.free_pages(phys, pages);
}

fn free_loaded_segments(bs: &BootServices, segs: &[LoadedSegment; MAX_LOAD_SEGMENTS], count: usize) {
    for i in 0..count {
        // Safe to free even if caller will drop after
        let pages = pages_for(segs[i].memsz as usize);
        let _ = bs.free_pages(segs[i].phys, pages);
    }
}
