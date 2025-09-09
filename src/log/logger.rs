//! UEFI logging utilities for the bootloader

use uefi::{CStr16, cstr16};

/// Write a log message - simplified stub version for now
/// In practice, this would need a way to access the mutable system table
fn write_log(_level: &str, _category: &str, _message: &str) {
    // Stub implementation - would need system table access to work properly
    // For now, this just acts as a no-op to avoid compilation errors
}

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
