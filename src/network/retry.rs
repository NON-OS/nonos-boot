//! Network retries, timeouts, and diagnostics for NONOS 

use crate::log::logger::{log_info, log_warn, log_error};
use alloc::vec::Vec;
use uefi::prelude::*;

/// Maximum retries for network fetch
pub const NET_MAX_RETRIES: usize = 3;
/// Timeout for each network fetch (seconds)
pub const NET_TIMEOUT_SECS: u64 = 10;

/// Wrapper for kernel fetch functions with retries and timeout.
pub fn fetch_with_retries(
    fetch_fn: impl Fn() -> Result<Vec<u8>, &'static str>,
) -> Result<Vec<u8>, &'static str> {
    for attempt in 0..NET_MAX_RETRIES {
        log_info("network", &format!("Network fetch attempt {}", attempt + 1));
        // Next phase development: Implementation of real timeout (use UEFI timer or other mechanism)
        match fetch_fn() {
            Ok(data) => return Ok(data),
            Err(e) => {
                log_warn("network", &format!("Attempt {} failed: {}", attempt + 1, e));
                // Next phase development; Sleep/backoff before retry, if needed
            }
        }
    }
    log_error("network", "All network fetch attempts failed");
    Err("Network fetch failed after retries")
}

/// Run network diagnostics and display/log results.
pub fn perform_network_diagnostics(system_table: &mut SystemTable<Boot>, interfaces_available: usize, network_configured: bool) -> bool {
    let mut diagnostics_passed = true;
    system_table.stdout().output_string(uefi::cstr16!("=== Network Diagnostics ===\r\n")).unwrap_or(());

    // Interface availability
    if interfaces_available == 0 {
        system_table.stdout().output_string(uefi::cstr16!("   [FAIL] No network interfaces found\r\n")).unwrap_or(());
        log_error("diagnostics", "No network interfaces available");
        diagnostics_passed = false;
    } else {
        system_table.stdout().output_string(uefi::cstr16!("   [PASS] Network interfaces detected\r\n")).unwrap_or(());
        log_info("diagnostics", "Network interface availability test passed");
    }

    // Network configuration
    if !network_configured {
        system_table.stdout().output_string(uefi::cstr16!("   [FAIL] Network configuration failed\r\n")).unwrap_or(());
        log_error("diagnostics", "Network configuration test failed");
        diagnostics_passed = false;
    } else {
        system_table.stdout().output_string(uefi::cstr16!("   [PASS] Network successfully configured\r\n")).unwrap_or(());
        log_info("diagnostics", "Network configuration test passed");
    }

    // Next phase development; Add additional diagnostics 

    system_table.stdout().output_string(uefi::cstr16!("============================\r\n")).unwrap_or(());

    if diagnostics_passed {
        log_info("diagnostics", "All network diagnostics passed");
    } else {
        log_warn("diagnostics", "Network diagnostics revealed issues");
    }

    diagnostics_passed
}
