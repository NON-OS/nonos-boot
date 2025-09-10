//! UEFI logging utilities for the bootloader

#![allow(dead_code)]

extern crate alloc;

use alloc::{format, vec::Vec};
use spin::Once;
use uefi::prelude::*;
use uefi::CStr16;

/// Wrapper to mark a raw UEFI SystemTable pointer as Sync.
/// UEFI boot services are not multi-threaded at this stage,
/// so this is safe as long as we only use it in the boot phase.
struct SystemTablePtr(*mut SystemTable<Boot>);
unsafe impl Send for SystemTablePtr {}
unsafe impl Sync for SystemTablePtr {}

/// Global storage for UEFI SystemTable pointer
static SYSTEM_TABLE: Once<SystemTablePtr> = Once::new();

/// Initialize the logger with the UEFI SystemTable.
/// Must be called once in `efi_main`.
pub fn init_logger(st: &mut SystemTable<Boot>) {
    SYSTEM_TABLE.call_once(|| SystemTablePtr(st as *mut _));
}

/// Internal function: write a log line to UEFI stdout
fn write_log(level: &str, category: &str, message: &str) {
    if let Some(SystemTablePtr(st_ptr)) = SYSTEM_TABLE.get() {
        unsafe {
            if let Some(st) = st_ptr.as_mut() {
                // Format log line
                let formatted = format!("[{}][{}] {}\r\n", level, category, message);

                // Convert to UTF-16 with nul terminator
                let mut utf16: Vec<u16> = formatted.encode_utf16().collect();
                utf16.push(0);

                if let Ok(cstr) = CStr16::from_u16_with_nul(&utf16) {
                    let _ = st.stdout().output_string(cstr);
                }
            }
        }
    }
}

// Public log API

pub fn log_info(category: &str, message: &str) {
    write_log("INFO", category, message);
}

pub fn log_warn(category: &str, message: &str) {
    write_log("WARN", category, message);
}

pub fn log_critical(category: &str, message: &str) {
    write_log("CRIT", category, message);
}

pub fn log_debug(category: &str, message: &str) {
    write_log("DEBUG", category, message);
}

pub fn log_error(category: &str,message: &str)
{
    write_log("Error", category, message);
}


