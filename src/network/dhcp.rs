//! DHCP configuration for NONOS network bootloader.

use uefi::prelude::*;
use uefi::proto::network::snp::SimpleNetwork;
use uefi::proto::network::dhcp4::Dhcp4;
use crate::log::logger::{log_info, log_error};
use alloc::vec::Vec;

/// Attempts DHCP negotiation on the first available network handle.
/// Returns assigned IP address on success, otherwise None.
pub fn configure_dhcp(system_table: &mut SystemTable<Boot>) -> Option<[u8; 4]> {
    let bs = system_table.boot_services();

    // Discover SimpleNetwork handles
    let handles = match bs.find_handles::<SimpleNetwork>() {
        Ok(h) if !h.is_empty() => h,
        _ => {
            log_error("dhcp", "No SimpleNetwork handles found");
            return None;
        }
    };

    for handle in handles {
        // Try to open Dhcp4 protocol on this handle
        let dhcp4 = match bs.open_protocol_exclusive::<Dhcp4>(handle) {
            Ok(dhcp4) => dhcp4,
            Err(e) => {
                log_error("dhcp", &format!("Failed to open Dhcp4: {:?}", e.status()));
                continue;
            }
        };

        // Start DHCP negotiation
        match dhcp4.start(&[]) {
            Ok(_) => {
                log_info("dhcp", "DHCP negotiation started.");

                // Wait for completion 
              
                // Retrieve DHCP ACK and assigned IP
                match dhcp4.config_data() {
                    Ok(cfg) => {
                        log_info(
                            "dhcp",
                            &format!(
                                "DHCP assigned IP: {}.{}.{}.{}",
                                cfg.client_address[0],
                                cfg.client_address[1],
                                cfg.client_address[2],
                                cfg.client_address[3]
                            ),
                        );
                        return Some(cfg.client_address);
                    }
                    Err(e) => {
                        log_error("dhcp", &format!("Failed to retrieve DHCP config: {:?}", e.status()));
                        continue;
                    }
                }
            }
            Err(e) => {
                log_error("dhcp", &format!("DHCP negotiation failed: {:?}", e.status()));
                continue;
            }
        }
    }

    log_error("dhcp", "DHCP failed on all network handles.");
    None
}
