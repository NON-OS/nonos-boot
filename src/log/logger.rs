//! UEFI logging utilities for the bootloader

#![allow(dead_code)]

extern crate alloc;

use alloc::{format, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
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

/// Global log level filter
/// 0 = TRACE, 1 = DEBUG, 2 = INFO, 3 = WARN, 4 = ERROR, 5 = CRIT/FATAL
static LOG_LEVEL: AtomicUsize = AtomicUsize::new(2); // Default = INFO

/// Initialize the logger with the UEFI SystemTable.
/// Must be called once in `efi_main`.
pub fn init_logger(st: &mut SystemTable<Boot>) {
    SYSTEM_TABLE.call_once(|| SystemTablePtr(st as *mut _));
}

/// Change the current log level filter.
pub fn set_log_level(level: usize) {
    LOG_LEVEL.store(level, Ordering::Relaxed);
}

/// Internal function: write a log line to UEFI stdout
fn write_log(level: &str, category: &str, message: &str, level_num: usize) {
    if level_num < LOG_LEVEL.load(Ordering::Relaxed) {
        return; // Skip logs below the current level
    }

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

pub fn log(level: &str, category: &str, message: &str, level_num: usize) {
    write_log(level, category, message, level_num);
}

pub fn log_trace(category: &str, message: &str) {
    log("TRACE", category, message, 0);
}

pub fn log_debug(category: &str, message: &str) {
    log("DEBUG", category, message, 1);
}

pub fn log_info(category: &str, message: &str) {
    log("INFO", category, message, 2);
}

pub fn log_warn(category: &str, message: &str) {
    log("WARN", category, message, 3);
}

pub fn log_error(category: &str, message: &str) {
    log("ERROR", category, message, 4);
}

pub fn log_critical(category: &str, message: &str) {
    log("CRIT", category, message, 5);
}

/// Fatal error log: halts after logging
pub fn log_fatal(category: &str, message: &str) -> ! {
    log("FATAL", category, message, 5);
    loop {} // Halt the system (or could use uefi::Status::ABORTED)
}
