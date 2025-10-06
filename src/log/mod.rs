//! Logging module
//!
//! Provides a unified logging API with different log levels.
//! The backend implementation is in `logger.rs`.

pub mod logger;

/// Logging levels
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Critical,
    Debug,
}

/// Initialize the logger with UEFI SystemTable.
/// This must be called once early in `efi_main`.
pub fn init_logger(st: &mut uefi::table::SystemTable<uefi::table::Boot>) {
    logger::init_logger(st);
}

/// Generic logging function
pub fn log(level: LogLevel, category: &str, message: &str) {
    match level {
        LogLevel::Info => logger::log_info(category, message),
        LogLevel::Warn => logger::log_warn(category, message),
        LogLevel::Error => logger::log_error(category, message),
        LogLevel::Critical => logger::log_critical(category, message),
        LogLevel::Debug => logger::log_debug(category, message),
    }
}

/// Convenience wrappers
pub fn info(category: &str, message: &str) {
    log(LogLevel::Info, category, message);
}

pub fn warn(category: &str, message: &str) {
    log(LogLevel::Warn, category, message);
}

pub fn error(category: &str, message: &str) {
    log(LogLevel::Error, category, message);
}

pub fn critical(category: &str, message: &str) {
    log(LogLevel::Critical, category, message);
}

pub fn debug(category: &str, message: &str) {
    log(LogLevel::Debug, category, message);
}
