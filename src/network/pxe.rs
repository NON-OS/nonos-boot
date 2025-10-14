//! PXE/TFTP kernel fetch for NONOS

use uefi::prelude::*;
use uefi::proto::network::pxe::BaseCode;
use crate::log::logger::{log_info, log_error};
use alloc::vec::Vec;

/// Maximum kernel size allowed (64 MB)
const MAX_KERNEL_SIZE: usize = 64 * 1024 * 1024;

/// Attempts to fetch a kernel file via PXE TFTP.
pub fn fetch_kernel_via_pxe(
    system_table: &mut SystemTable<Boot>,
    filename: &str,
) -> Result<Vec<u8>, &'static str> {
    let bs = system_table.boot_services();

    // Discover PXE BaseCode handles
    let handles = match bs.find_handles::<BaseCode>() {
        Ok(h) if !h.is_empty() => h,
        _ => {
            log_error("pxe", "No PXE BaseCode handles found");
            return Err("PXE not available");
        }
    };

    for handle in handles {
        // Open PXE BaseCode protocol on this handle
        let mut pxe = match bs.open_protocol_exclusive::<BaseCode>(handle) {
            Ok(p) => p,
            Err(e) => {
                log_error("pxe", &format!("Failed to open PXE BaseCode: {:?}", e.status()));
                continue;
            }
        };

        // Check if PXE is started
        if !pxe.mode().started() {
            match pxe.start() {
                Ok(_) => log_info("pxe", "PXE started"),
                Err(e) => {
                    log_error("pxe", &format!("Failed to start PXE: {:?}", e.status()));
                    continue;
                }
            }
        }

        // Allocate buffer for kernel
        let mut buffer = vec![0u8; MAX_KERNEL_SIZE];

        // Attempt TFTP download
        match pxe.mtftp_read(filename, &mut buffer) {
            Ok(bytes_read) => {
                log_info("pxe", &format!("TFTP download succeeded: {} bytes", bytes_read));
                buffer.truncate(bytes_read);
                return Ok(buffer);
            }
            Err(e) => {
                log_error("pxe", &format!("TFTP download failed: {:?}", e.status()));
                continue;
            }
        }
    }

    log_error("pxe", "PXE/TFTP kernel fetch failed on all handles.");
    Err("PXE/TFTP fetch failed")
}
