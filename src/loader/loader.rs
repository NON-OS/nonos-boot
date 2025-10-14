//! NONOS Bootloader Loader Module

use crate::log::logger::{log_info, log_error};
use crate::verify::{load_validated_capsule, CapsuleMetadata};
use uefi::prelude::*;
use uefi::table::boot::{AllocateType, MemoryType};

/// Result of a successful load: memory address, size, metadata
#[derive(Debug, Clone)]
pub struct KernelImage {
    pub address: usize,
    pub size: usize,
    pub metadata: CapsuleMetadata,
}

/// Load, allocate, and prepare kernel image for boot
pub fn load_kernel(system_table: &mut SystemTable<Boot>, capsule_bytes: &[u8]) -> Option<KernelImage> {
    log_info("loader", "Starting kernel load operation...");

    // Validate capsule and extract payload
    let payload_opt = load_validated_capsule(capsule_bytes);
    if payload_opt.is_none() {
        log_error("loader", "Capsule validation failed, cannot load kernel.");
        return None;
    }
    let payload = payload_opt.unwrap();
    let payload_size = payload.len();

    // Allocate memory for the payload
    let bs = system_table.boot_services();
    let alloc_pages = ((payload_size + 0xFFF) & !0xFFF) / 0x1000; // round up to page size (4K)
    let mut address: uefi::table::boot::PhysicalAddress = 0;

    match bs.allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        alloc_pages,
        &mut address,
    ) {
        Ok(_) => {
            log_info("loader", &format!("Allocated {} pages for kernel at {:x}", alloc_pages, address));
        }
        Err(e) => {
            log_error("loader", &format!("Failed to allocate memory for kernel: {:?}", e.status()));
            return None;
        }
    }

    // Copy payload to allocated memory
    let dst_ptr = address as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(payload.as_ptr(), dst_ptr, payload_size);
    }

    // Retrieve metadata 
    let meta = CapsuleMetadata {
        offset_sig: 0, // Not used after load
        len_sig: 0,
        offset_payload: 0,
        len_payload: payload_size,
    };

    log_info("loader", "Kernel load successful, ready for handoff.");

    Some(KernelImage {
        address: address as usize,
        size: payload_size,
        metadata: meta,
    })
}
