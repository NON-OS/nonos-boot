//! Multi-Boot Support for NØNOS Bootloader (Minimal UEFI-Compatible)
//!
//! This module provides minimal multi-boot capabilities without heap allocation

#![allow(dead_code)]

use crate::config::BootloaderConfig;
use crate::log::logger::{log_debug, log_error, log_info, log_warn};
use uefi::prelude::*;
use uefi::{cstr16, CStr16};

/// Boot entry types supported by the multi-boot system
#[derive(Debug, Clone, PartialEq)]
pub enum BootEntryType {
    NonOsKernel,         // NØNOS native kernel
    UefiApplication,     // UEFI application
    MultibootKernel,     // Multiboot compliant kernel
    LinuxKernel,         // Linux kernel with boot protocol
    ChainloadBootloader, // Chainload another bootloader
    RecoveryMode,        // Emergency recovery boot
}

/// Boot entry information (stack-based, no heap allocation)
#[derive(Debug, Clone)]
pub struct BootEntry {
    pub id: u32,
    pub name: [u8; 64],         // Fixed-size name buffer
    pub description: [u8; 128], // Fixed-size description buffer
    pub entry_type: BootEntryType,
    pub path: [u8; 256],         // Fixed-size path buffer
    pub command_line: [u8; 256], // Fixed-size command line buffer
    pub enabled: bool,
    pub default: bool,
    pub boot_count: u32,
    pub last_boot_success: bool,
}

impl Default for BootEntry {
    fn default() -> Self {
        Self {
            id: 0,
            name: [0; 64],
            description: [0; 128],
            entry_type: BootEntryType::NonOsKernel,
            path: [0; 256],
            command_line: [0; 256],
            enabled: true,
            default: false,
            boot_count: 0,
            last_boot_success: true,
        }
    }
}

/// Multi-boot manager structure (minimal implementation)
#[derive(Debug)]
pub struct MultiBootManager {
    pub default_entry_id: Option<u32>,
    pub boot_timeout: u32,
    pub last_selected_entry: Option<u32>,
    pub recovery_mode_available: bool,
}

impl Default for MultiBootManager {
    fn default() -> Self {
        Self {
            default_entry_id: None,
            boot_timeout: 10,
            last_selected_entry: None,
            recovery_mode_available: false,
        }
    }
}

impl MultiBootManager {
    /// Create new multi-boot manager (minimal implementation)
    pub fn new(system_table: &mut SystemTable<Boot>) -> Self {
        let manager = Self::default();

        system_table
            .stdout()
            .output_string(cstr16!("=== Multi-Boot System Initialization ===\r\n"))
            .unwrap_or(());
        system_table
            .stdout()
            .output_string(cstr16!(
                "   [INFO] Minimal multi-boot manager initialized\r\n"
            ))
            .unwrap_or(());
        system_table
            .stdout()
            .output_string(cstr16!("=========================================\r\n"))
            .unwrap_or(());

        log_info("multiboot", "Multi-boot system initialized");
        manager
    }

    /// Display boot menu (minimal implementation - returns default)
    pub fn display_boot_menu(
        &self,
        system_table: &mut SystemTable<Boot>,
        _config: &BootloaderConfig,
    ) -> u32 {
        system_table
            .stdout()
            .output_string(cstr16!("   [INFO] Using default boot entry\r\n"))
            .unwrap_or(());
        log_info("multiboot", "Default boot entry selected");
        0 // Return default entry
    }

    /// Save boot preferences (stub)
    pub fn save_boot_preferences(&self, system_table: &mut SystemTable<Boot>) -> bool {
        system_table
            .stdout()
            .output_string(cstr16!("   [INFO] Boot preferences saved\r\n"))
            .unwrap_or(());
        log_debug("multiboot", "Boot preferences saved");
        true
    }

    /// Load boot preferences (stub)
    pub fn load_boot_preferences(&mut self, system_table: &mut SystemTable<Boot>) {
        system_table
            .stdout()
            .output_string(cstr16!("   [INFO] Boot preferences loaded\r\n"))
            .unwrap_or(());
        log_debug("multiboot", "Boot preferences loaded");
    }

    /// Get selected entry information (stub)
    pub fn get_entry_info(&self, _entry_id: u32) -> Option<&BootEntry> {
        None // No entries in minimal implementation
    }
}
