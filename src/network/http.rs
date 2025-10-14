//! HTTP/HTTPS kernel fetch for NONOS 

use uefi::prelude::*;
use uefi::proto::network::http::{Http, RequestData, ResponseData, HTTP_METHOD_GET};
use crate::log::logger::{log_info, log_error};
use alloc::vec::Vec;

/// Maximum kernel size allowed (64 MB)
const MAX_KERNEL_SIZE: usize = 64 * 1024 * 1024;

/// Attempts to fetch a kernel file via HTTP/HTTPS GET request.
pub fn fetch_kernel_via_http(
    system_table: &mut SystemTable<Boot>,
    url: &str,
) -> Result<Vec<u8>, &'static str> {
    let bs = system_table.boot_services();

    // Discover HTTP handles
    let handles = match bs.find_handles::<Http>() {
        Ok(h) if !h.is_empty() => h,
        _ => {
            log_error("http", "No HTTP protocol handles found");
            return Err("HTTP/HTTPS not available");
        }
    };

    for handle in handles {
        // Open HTTP protocol on this handle
        let mut http = match bs.open_protocol_exclusive::<Http>(handle) {
            Ok(p) => p,
            Err(e) => {
                log_error("http", &format!("Failed to open HTTP protocol: {:?}", e.status()));
                continue;
            }
        };

        // Build GET request
        let request = RequestData {
            method: HTTP_METHOD_GET,
            url: url.into(),
            headers: Vec::new(), // Add headers if needed 
            body: Vec::new(),
        };

        let mut response = ResponseData::default();

        // Perform request
        match http.request(&request, &mut response) {
            Ok(_) => {
                log_info("http", &format!("HTTP GET succeeded: {} bytes", response.body.len()));
                if response.body.len() > MAX_KERNEL_SIZE {
                    log_error("http", "Downloaded kernel too large");
                    return Err("Kernel too large");
                }

                // Could also validate HTTPS certificate here 

                return Ok(response.body);
            }
            Err(e) => {
                log_error("http", &format!("HTTP GET failed: {:?}", e.status()));
                continue;
            }
        }
    }

    log_error("http", "HTTP/HTTPS kernel fetch failed on all handles.");
    Err("HTTP/HTTPS fetch failed")
}
