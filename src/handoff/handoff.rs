#![allow(dead_code)]
#![no_std]

use core::mem::size_of;
use uefi::prelude::*;
use uefi::table::boot::{AllocateType, MemoryType, MemoryMapKey, MemoryDescriptor};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FramebufferInfo {
    pub ptr: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: u32
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MemoryMap {
    pub ptr: u64,
    pub entry_size: u32,
    pub entry_count: u32,
    pub desc_version: u32
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AcpiInfo {
    pub rsdp: u64
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SmbiosInfo {
    pub entry: u64
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Module {
    pub base: u64,
    pub size: u64,
    pub kind: u32,
    pub reserved: u32
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Modules {
    pub ptr: u64,
    pub count: u32,
    pub reserved: u32
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Timing {
    pub tsc_hz: u64,
    pub unix_epoch_ms: u64
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Measurements {
    pub kernel_sha256: [u8; 32],
    pub kernel_sig_ok: u8,
    pub secure_boot: u8,
    pub reserved: [u8; 6]
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RngSeed {
    pub seed32: [u8; 32]
}

pub const HANDOFF_MAGIC: u32 = 0x4E_4F_4E_4F;
pub const HANDOFF_VERSION: u16 = 1;

pub mod flags {
    pub const WX: u64 = 1 << 0;
    pub const NXE: u64 = 1 << 1;
    pub const SMEP: u64 = 1 << 2;
    pub const SMAP: u64 = 1 << 3;
    pub const UMIP: u64 = 1 << 4;
    pub const IDMAP_PRESERVED: u64 = 1 << 5;
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BootHandoffV1 {
    pub magic: u32,
    pub version: u16,
    pub size: u16,
    pub flags: u64,
    pub entry_point: u64,
    pub fb: FramebufferInfo,
    pub mmap: MemoryMap,
    pub acpi: AcpiInfo,
    pub smbios: SmbiosInfo,
    pub modules: Modules,
    pub timing: Timing,
    pub meas: Measurements,
    pub rng: RngSeed,
    pub cmdline_ptr: u64,
    pub reserved0: u64
}

impl BootHandoffV1 {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == HANDOFF_MAGIC
            && self.version == HANDOFF_VERSION
            && self.size as usize == core::mem::size_of::<Self>()
    }
}

use crate::log::logger::{log_error, log_info};
use crate::loader::{KernelImage, LoaderError};

pub type KernelEntry = extern "C" fn(u64) -> !;

pub fn exit_and_jump(image_handle: Handle, st: &mut SystemTable<Boot>, kernel: &KernelImage, cmdline: Option<&str>) -> Result<! , LoaderError> {
    log_info(st, "handoff", "Preparing memory map and ExitBootServices.");

    let bs = st.boot_services();
    let mut pages_for_map: usize = 8;
    let map_len = |p: usize| p * 0x1000usize;
    let mut map_addr: uefi::table::boot::PhysicalAddress = 0;
    let memory_map_key: MemoryMapKey;

    loop {
        if let Err(e) = bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages_for_map, &mut map_addr) {
            log_error(st, "handoff", &format!("alloc memmap buffer failed: {:?}", e.status()));
            return Err(LoaderError::UefiError { desc: "alloc memory map failed", status: e.status() });
        }

        let map_slice = unsafe { core::slice::from_raw_parts_mut(map_addr as *mut u8, map_len(pages_for_map)) };

        match bs.memory_map(map_slice) {
            Ok((key, _iter)) => {
                memory_map_key = key;
                break;
            }
            Err(_) => {
                let _ = bs.free_pages(map_addr, pages_for_map);
                pages_for_map = (pages_for_map * 2).min(256);
                continue;
            }
        }
    }

    let map_slice = unsafe { core::slice::from_raw_parts_mut(map_addr as *mut u8, map_len(pages_for_map)) };
    if let Err(status) = st.exit_boot_services(image_handle, memory_map_key) {
        let _ = bs.free_pages(map_addr, pages_for_map);
        log_error(st, "handoff", &format!("ExitBootServices failed: {:?}", status));
        return Err(LoaderError::UefiError { desc: "ExitBootServices failed", status });
    }

    let mut bh_addr: uefi::table::boot::PhysicalAddress = 0;
    if let Err(e) = bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1, &mut bh_addr) {
        log_error(st, "handoff", &format!("BootHandoff alloc failed: {:?}", e.status()));
        return Err(LoaderError::UefiError { desc: "BootHandoff alloc failed", status: e.status() });
    }

    let bh_ptr = bh_addr as *mut BootHandoffV1;
    unsafe {
        core::ptr::write_bytes(bh_ptr as *mut u8, 0, size_of::<BootHandoffV1>());

        (*bh_ptr).magic = HANDOFF_MAGIC;
        (*bh_ptr).version = HANDOFF_VERSION;
        (*bh_ptr).size = size_of::<BootHandoffV1>() as u16;
        (*bh_ptr).flags = 0;
        (*bh_ptr).entry_point = kernel.entry_point as u64;

        (*bh_ptr).fb = FramebufferInfo { ptr: 0, size: 0, width: 0, height: 0, stride: 0, pixel_format: 0 };

        let entry_size = core::mem::size_of::<MemoryDescriptor>() as u32;
        let entry_count = ((pages_for_map * 0x1000) / (entry_size as usize)) as u32;
        (*bh_ptr).mmap.ptr = map_addr as u64;
        (*bh_ptr).mmap.entry_size = entry_size;
        (*bh_ptr).mmap.entry_count = entry_count;
        (*bh_ptr).mmap.desc_version = 0;

        (*bh_ptr).acpi.rsdp = 0;
        (*bh_ptr).smbios.entry = 0;
        (*bh_ptr).modules.ptr = 0;
        (*bh_ptr).modules.count = 0;
        (*bh_ptr).timing.tsc_hz = 0;
        (*bh_ptr).timing.unix_epoch_ms = 0;
        (*bh_ptr).meas = Measurements { kernel_sha256: [0u8;32], kernel_sig_ok: 0, secure_boot: 0, reserved: [0u8;6] };
        (*bh_ptr).rng = RngSeed { seed32: [0u8;32] };

        (*bh_ptr).cmdline_ptr = 0;
        (*bh_ptr).reserved0 = 0;
    }

    if let Some(s) = cmdline {
        let cmd_bytes = s.as_bytes();
        let cmd_len = cmd_bytes.len() + 1;
        let cmd_pages = (cmd_len + 0xFFF) / 0x1000;
        let mut cmd_addr: uefi::table::boot::PhysicalAddress = 0;
        if bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, cmd_pages, &mut cmd_addr).is_ok() {
            unsafe {
                let ptr = cmd_addr as *mut u8;
                core::ptr::copy_nonoverlapping(cmd_bytes.as_ptr(), ptr, cmd_bytes.len());
                core::ptr::write_volatile(ptr.add(cmd_bytes.len()), 0u8);
                (*bh_ptr).cmdline_ptr = cmd_addr as u64;
            }
        }
    }

    let stack_pages: usize = 8;
    let mut stack_addr: uefi::table::boot::PhysicalAddress = 0;
    if let Err(e) = bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, stack_pages, &mut stack_addr) {
        log_error(st, "handoff", &format!("stack alloc failed: {:?}", e.status()));
        return Err(LoaderError::UefiError { desc: "stack alloc failed", status: e.status() });
    }
    let stack_top = (stack_addr as usize).checked_add(stack_pages * 0x1000).expect("stack overflow");

    let boothandoff_ptr = bh_addr as u64;
    log_info(st, "handoff", &format!("Transferring control to kernel 0x{:x} with handoff @ 0x{:x}", kernel.entry_point, bh_addr));

    unsafe {
        let kernel_fn: KernelEntry = core::mem::transmute(kernel.entry_point as usize);
        core::arch::asm!(
            "mov rdi, {0}",
            "mov rsp, {1}",
            "xor rbp, rbp",
            "jmp {2}",
            in(reg) boothandoff_ptr as usize,
            in(reg) stack_top,
            in(reg) kernel_fn as usize,
            options(noreturn)
        );
    }

    core::hint::unreachable_unchecked()
}
