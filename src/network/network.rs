//! Network Boot for NONOS

use crate::log::logger::*;
use crate::verify::{verify_ed25519_signature};
use crate::trusted_keys::TRUSTED_PUBLIC_KEYS;
use alloc::string::String;
use alloc::vec::Vec;
use uefi::prelude::*;
use uefi::proto::network::snp::SimpleNetwork;
use uefi::proto::network::dhcp4::Dhcp4;
use uefi::proto::network::ip4::{Ip4Config, Ip4ConfigData};
use uefi::proto::network::pxe::BaseCode;
use uefi::proto::network::http::{Http, RequestData, ResponseData, HTTP_METHOD_GET};

/// Maximum kernel size allowed (64 MB)
const MAX_KERNEL_SIZE: usize = 64 * 1024 * 1024;
/// Maximum retries for network fetch
const NET_MAX_RETRIES: usize = 3;

/// Network boot configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub dhcp_enabled: bool,
    pub static_ip: Option<[u8; 4]>,
    pub gateway: Option<[u8; 4]>,
    pub dns_server: Option<[u8; 4]>,
    pub boot_server_ip: Option<[u8; 4]>,
    pub boot_filename: Option<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            dhcp_enabled: true,
            static_ip: None,
            gateway: None,
            dns_server: None,
            boot_server_ip: None,
            boot_filename: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct NetworkBootContext {
    pub interfaces_available: usize,
    pub active_interface: Option<usize>,
    pub network_configured: bool,
    pub pxe_available: bool,
    pub http_client_available: bool,
    pub config: NetworkConfig,
}

/// Initialize network boot subsystem
pub fn initialize_network_boot(system_table: &mut SystemTable<Boot>) -> NetworkBootContext {
    let mut network = NetworkBootContext::default();

    system_table.stdout().output_string(cstr16!("=== Network Boot Subsystem ===\r\n")).unwrap_or(());

    network.interfaces_available = discover_network_interfaces(system_table);

    if network.interfaces_available == 0 {
        log_warn("network", "No network interfaces available");
        system_table.stdout().output_string(cstr16!("   [WARN] No network interfaces found\r\n")).unwrap_or(());
        return network;
    }

    network.pxe_available = check_pxe_support(system_table);
    network.http_client_available = check_http_client_support(system_table);

    if network.interfaces_available > 0 {
        // Choose DHCP if enabled, else static
        if network.config.dhcp_enabled {
            if let Some(ip) = configure_dhcp(system_table) {
                log_info("network", &format!("DHCP succeeded: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                network.network_configured = true;
                network.active_interface = Some(0);
            } else {
                log_error("network", "DHCP failed on all interfaces");
                network.network_configured = false;
            }
        } else if let Some(ip) = network.config.static_ip {
            if configure_static_ip(system_table, ip, network.config.gateway) {
                log_info("network", "Static IP configuration succeeded.");
                network.network_configured = true;
                network.active_interface = Some(0);
            } else {
                log_error("network", "Static IP configuration failed.");
                network.network_configured = false;
            }
        }
    }

    display_network_status(&network, system_table);

    log_info("network", "Network boot subsystem initialization completed");
    network
}

/// Discover available network interfaces
fn discover_network_interfaces(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    match bs.find_handles::<SimpleNetwork>() {
        Ok(handles) if !handles.is_empty() => {
            let count = handles.len();
            log_info("network", "Simple Network interfaces detected");
            system_table.stdout().output_string(cstr16!("   [SUCCESS] Simple Network interfaces found\r\n")).unwrap_or(());
            count
        }
        _ => 0,
    }
}

/// DHCP configuration
pub fn configure_dhcp(system_table: &mut SystemTable<Boot>) -> Option<[u8; 4]> {
    let bs = system_table.boot_services();

    let handles = match bs.find_handles::<SimpleNetwork>() {
        Ok(h) if !h.is_empty() => h,
        _ => {
            log_error("dhcp", "No SimpleNetwork handles found");
            return None;
        }
    };

    for handle in handles {
        let dhcp4 = match bs.open_protocol_exclusive::<Dhcp4>(handle) {
            Ok(dhcp4) => dhcp4,
            Err(e) => {
                log_error("dhcp", &format!("Failed to open Dhcp4: {:?}", e.status()));
                continue;
            }
        };

        match dhcp4.start(&[]) {
            Ok(_) => {
                log_info("dhcp", "DHCP negotiation started.");
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

/// Static IP configuration
pub fn configure_static_ip(
    system_table: &mut SystemTable<Boot>,
    ip: [u8; 4],
    gateway: Option<[u8; 4]>,
) -> bool {
    let bs = system_table.boot_services();

    let handles = match bs.find_handles::<SimpleNetwork>() {
        Ok(h) if !h.is_empty() => h,
        _ => {
            log_error("static_ip", "No SimpleNetwork handles found");
            return false;
        }
    };

    for handle in handles {
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

/// PXE/TFTP kernel fetch
pub fn fetch_kernel_via_pxe(
    system_table: &mut SystemTable<Boot>,
    filename: &str,
) -> Result<Vec<u8>, &'static str> {
    let bs = system_table.boot_services();

    let handles = match bs.find_handles::<BaseCode>() {
        Ok(h) if !h.is_empty() => h,
        _ => {
            log_error("pxe", "No PXE BaseCode handles found");
            return Err("PXE not available");
        }
    };

    for handle in handles {
        let mut pxe = match bs.open_protocol_exclusive::<BaseCode>(handle) {
            Ok(p) => p,
            Err(e) => {
                log_error("pxe", &format!("Failed to open PXE BaseCode: {:?}", e.status()));
                continue;
            }
        };

        if !pxe.mode().started() {
            match pxe.start() {
                Ok(_) => log_info("pxe", "PXE started"),
                Err(e) => {
                    log_error("pxe", &format!("Failed to start PXE: {:?}", e.status()));
                    continue;
                }
            }
        }

        let mut buffer = vec![0u8; MAX_KERNEL_SIZE];

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

/// HTTP/HTTPS kernel fetch
pub fn fetch_kernel_via_http(
    system_table: &mut SystemTable<Boot>,
    url: &str,
) -> Result<Vec<u8>, &'static str> {
    let bs = system_table.boot_services();

    let handles = match bs.find_handles::<Http>() {
        Ok(h) if !h.is_empty() => h,
        _ => {
            log_error("http", "No HTTP protocol handles found");
            return Err("HTTP/HTTPS not available");
        }
    };

    for handle in handles {
        let mut http = match bs.open_protocol_exclusive::<Http>(handle) {
            Ok(p) => p,
            Err(e) => {
                log_error("http", &format!("Failed to open HTTP protocol: {:?}", e.status()));
                continue;
            }
        };

        let request = RequestData {
            method: HTTP_METHOD_GET,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        };

        let mut response = ResponseData::default();

        match http.request(&request, &mut response) {
            Ok(_) => {
                log_info("http", &format!("HTTP GET succeeded: {} bytes", response.body.len()));
                if response.body.len() > MAX_KERNEL_SIZE {
                    log_error("http", "Downloaded kernel too large");
                    return Err("Kernel too large");
                }
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

/// Signature verification for downloaded kernel
pub fn verify_downloaded_kernel(kernel: &[u8], signature: &[u8]) -> bool {
    for (idx, pubkey) in TRUSTED_PUBLIC_KEYS.iter().enumerate() {
        match verify_ed25519_signature(kernel, signature, pubkey) {
            Ok(true) => {
                log_info("verify", &format!("Kernel signature verified with key #{}", idx));
                return true;
            }
            Ok(false) | Err(_) => continue,
        }
    }
    log_error("verify", "Kernel signature verification failed with all trusted keys.");
    false
}

/// Fetch with retries and timeout
pub fn fetch_with_retries(
    fetch_fn: impl Fn() -> Result<Vec<u8>, &'static str>,
) -> Result<Vec<u8>, &'static str> {
    for attempt in 0..NET_MAX_RETRIES {
        log_info("network", &format!("Network fetch attempt {}", attempt + 1));
        match fetch_fn() {
            Ok(data) => return Ok(data),
            Err(e) => {
                log_warn("network", &format!("Attempt {} failed: {}", attempt + 1, e));
                // Next development: Sleep/backoff before retry, if needed
            }
        }
    }
    log_error("network", "All network fetch attempts failed");
    Err("Network fetch failed after retries")
}

/// Run network diagnostics and display/log results.
pub fn perform_network_diagnostics(system_table: &mut SystemTable<Boot>, interfaces_available: usize, network_configured: bool) -> bool {
    let mut diagnostics_passed = true;
    system_table.stdout().output_string(cstr16!("=== Network Diagnostics ===\r\n")).unwrap_or(());

    if interfaces_available == 0 {
        system_table.stdout().output_string(cstr16!("   [FAIL] No network interfaces found\r\n")).unwrap_or(());
        log_error("diagnostics", "No network interfaces available");
        diagnostics_passed = false;
    } else {
        system_table.stdout().output_string(cstr16!("   [PASS] Network interfaces detected\r\n")).unwrap_or(());
        log_info("diagnostics", "Network interface availability test passed");
    }

    if !network_configured {
        system_table.stdout().output_string(cstr16!("   [FAIL] Network configuration failed\r\n")).unwrap_or(());
        log_error("diagnostics", "Network configuration test failed");
        diagnostics_passed = false;
    } else {
        system_table.stdout().output_string(cstr16!("   [PASS] Network successfully configured\r\n")).unwrap_or(());
        log_info("diagnostics", "Network configuration test passed");
    }

    system_table.stdout().output_string(cstr16!("============================\r\n")).unwrap_or(());

    if diagnostics_passed {
        log_info("diagnostics", "All network diagnostics passed");
    } else {
        log_warn("diagnostics", "Network diagnostics revealed issues");
    }

    diagnostics_passed
}

/// Display network status
fn display_network_status(network: &NetworkBootContext, system_table: &mut SystemTable<Boot>) {
    system_table.stdout().output_string(cstr16!("\r\n=== Network Status ===\r\n")).unwrap_or(());
    if network.interfaces_available > 0 {
        system_table.stdout().output_string(cstr16!("Interfaces:        Available\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("Interfaces:        Not Available\r\n")).unwrap_or(());
    }
    if network.network_configured {
        system_table.stdout().output_string(cstr16!("Configuration:     SUCCESS\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("Configuration:     FAILED\r\n")).unwrap_or(());
    }
    if network.pxe_available {
        system_table.stdout().output_string(cstr16!("PXE Support:       Available\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("PXE Support:       Not Available\r\n")).unwrap_or(());
    }
    if network.http_client_available {
        system_table.stdout().output_string(cstr16!("HTTP Client:       Available\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("HTTP Client:       Not Available\r\n")).unwrap_or(());
    }
    system_table.stdout().output_string(cstr16!("======================\r\n\r\n")).unwrap_or(());
}

/// Network boot options
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkBootOption {
    Pxe,
    Http,
    Local,
}
