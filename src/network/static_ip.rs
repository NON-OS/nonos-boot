//! Static IP configuration for NONOS 

use uefi::prelude::*;
use uefi::proto::network::snp::SimpleNetwork;
use uefi::proto::network::ip4::{Ip4Config, Ip4ConfigData};
use crate::log::logger::{log_info, log_error};

/// Attempts static IP configuration on the first available network handle.
pub fn configure_static_ip(
    system_table: &mut SystemTable<Boot>,
    ip: [u8; 4],
    gateway: Option<[u8; 4]>,
) -> bool {
    let bs = system_table.boot_services();

    // Discover SimpleNetwork handles
    let handles = match bs.find_handles::<SimpleNetwork>() {
        Ok(h) if !h.is_empty() => h,
        _ => {
            log_error("static_ip", "No SimpleNetwork handles found");
            return false;
        }
    };

    for handle in handles {
        // Try to open Ip4Config protocol on this handle
        let mut ip4_config = match bs.open_protocol_exclusive::<Ip4Config>(handle) {
            Ok(ip4) => ip4,
            Err(e) => {
                log_error("static_ip", &format!("Failed to open Ip4Config: {:?}", e.status()));
                continue;
            }
        };

        let config_data = Ip4ConfigData {
            ip_address: ip,
            subnet_mask: [255, 255, 255, 0], // Example: /24
            gateway_address: gateway.unwrap_or([0, 0, 0, 0]),
        };

        match ip4_config.set_data(&config_data) {
            Ok(_) => {
                log_info(
                    "static_ip",
                    &format!(
                        "Static IP set: {}.{}.{}.{} / Gateway: {}.{}.{}.{}",
                        ip[0], ip[1], ip[2], ip[3],
                        config_data.gateway_address[0], config_data.gateway_address[1],
                        config_data.gateway_address[2], config_data.gateway_address[3],
                    ),
                );
                return true;
            }
            Err(e) => {
                log_error("static_ip", &format!("Failed to set static IP: {:?}", e.status()));
                continue;
            }
        }
    }

    log_error("static_ip", "Static IP configuration failed on all network handles.");
    false
}
