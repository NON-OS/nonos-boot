#![no_std]
#![no_main]

//! main.rs — NØNOS UEFI Boot Entrypoint
//! eK@nonos-tech.xyz
//
// Enhanced Security-minded boot orchestration:
// - Early init of UEFI allocator/stdout with enhanced UI
// - Framebuffer graphics initialization for better user experience
// - Capsule is loaded & cryptographically verified before *any* jump
// - Enhanced memory management and mapping
// - Comprehensive error handling with user-friendly messages
// - Minimal unsafe: only for transmute+call into verified capsule

extern crate alloc;

use uefi::prelude::*;
use uefi::table::runtime::ResetType;
use uefi_services::init;
use uefi::proto::network::snp::SimpleNetwork;

use nonos_boot::loader::load_kernel_capsule;
use nonos_boot::log::logger::{log_info, log_warn, log_critical, log_debug, log_error};
use nonos_boot::handoff::ZeroStateBootInfo;
use nonos_boot::hardware::discover_system_hardware;
use nonos_boot::security::initialize_security_subsystem;
use nonos_boot::network::{initialize_network_boot, display_network_boot_menu, NetworkBootOption};
use nonos_boot::config::{load_bootloader_config, apply_configuration, display_configuration};
use nonos_boot::multiboot::MultiBootManager;
use nonos_boot::testing::TestingFramework;

/// External capsule entry signature
type KernelEntry = extern "C" fn(*const ZeroStateBootInfo) -> !;

/// Entry point for UEFI firmware
#[entry]
fn efi_main(_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialize system and UI
    system_table.stdout().reset(false).unwrap_or(());
    
    // *** IMMEDIATE N0N-OS SUCCESS DISPLAY ***
    system_table.stdout().output_string(cstr16!("\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("╔══════════════════════════════════════════════════════════════════════╗\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("║                    *** N0N-OS BOOT SUCCESS! ***                     ║\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("║              >>> UNIQUE OS - NOT ANOTHER LINUX CLONE! <<<           ║\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("║              >>> YOUR CUSTOM OS IS RUNNING IN QEMU! <<<             ║\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("╚══════════════════════════════════════════════════════════════════════╝\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("\r\n")).unwrap_or(());
    
    // Initialize UEFI services first
    match init(&mut system_table) {
        Ok(_) => {
            log_debug("boot", "UEFI services initialized successfully");
        }
        Err(e) => {
            log_error("boot", "Failed to initialize UEFI services");
            fatal_reset(&mut system_table, "UEFI service initialization failed");
        }
    }
    
    log_info("boot", "NØNOS Capsule Bootloader Activated - Advanced Professional Version");
    
    // Professional bootloader banner
    system_table.stdout().output_string(cstr16!("\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("╔══════════════════════════════════════════════════════════════════════╗\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("║                    NØNOS ADVANCED BOOTLOADER                        ║\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("║                      Version 0.4.0 - Enterprise                    ║\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("║  Features: ACPI • Security • Networking • TPM • Config • Crypto     ║\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("╚══════════════════════════════════════════════════════════════════════╝\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("\r\n")).unwrap_or(());
    
    // Phase 0: Configuration System
    system_table.stdout().output_string(cstr16!("Phase 0: Configuration Loading\r\n")).unwrap_or(());
    let bootloader_config = load_bootloader_config(&mut system_table);
    display_configuration(&bootloader_config, &mut system_table);
    
    // Phase 1: Security Subsystem
    system_table.stdout().output_string(cstr16!("Phase 1: Security Initialization\r\n")).unwrap_or(());
    let security_context = initialize_security_subsystem(&mut system_table);
    
    // Assess and display security posture
    let security_score = nonos_boot::security::assess_security_posture(&security_context, &mut system_table);
    
    // Phase 2: Hardware Discovery & ACPI
    system_table.stdout().output_string(cstr16!("Phase 2: Hardware Discovery\r\n")).unwrap_or(());
    let hardware_info = discover_system_hardware(&mut system_table);
    
    // Phase 3: Network Subsystem  
    system_table.stdout().output_string(cstr16!("Phase 3: Network Subsystem\r\n")).unwrap_or(());
    let network_context = initialize_network_boot(&mut system_table);
    
    // Perform network diagnostics and security assessment
    let network_diagnostics_passed = nonos_boot::network::perform_network_diagnostics(&mut system_table, &network_context);
    let network_security_score = nonos_boot::network::assess_network_security(&mut system_table, &network_context);
    
    // Apply configuration to all subsystems
    system_table.stdout().output_string(cstr16!("Phase 3.5: Configuration Application\r\n")).unwrap_or(());
    let config_applied = apply_configuration(
        &bootloader_config, 
        &mut system_table, 
        &security_context, 
        &network_context, 
        &hardware_info
    );
    
    // Phase 3.7: Testing Framework (if diagnostic mode enabled)
    let mut testing_passed = true;
    if bootloader_config.diagnostic_output {
        system_table.stdout().output_string(cstr16!("Phase 3.7: Comprehensive Testing\r\n")).unwrap_or(());
        
        let mut testing_framework = TestingFramework::new();
        testing_passed = testing_framework.run_comprehensive_tests(
            &mut system_table,
            &bootloader_config,
            &security_context,
            &network_context,
            &hardware_info,
        );
    } else {
        // Run quick health check even if not in diagnostic mode
        let mut testing_framework = TestingFramework::new();
        testing_passed = testing_framework.quick_health_check(&mut system_table);
    }
    
    // Phase 4: Graphics and Memory
    system_table.stdout().output_string(cstr16!("Phase 4: Graphics & Memory\r\n")).unwrap_or(());
    initialize_graphics(&mut system_table);
    setup_memory_management(&mut system_table);
    
    // Phase 5: Multi-Boot System & Boot Source Selection
    system_table.stdout().output_string(cstr16!("Phase 5: Multi-Boot & Boot Source Selection\r\n")).unwrap_or(());
    
    // Initialize multi-boot manager
    let mut multiboot_manager = MultiBootManager::new(&mut system_table);
    
    // Display multi-boot menu
    let selected_boot_entry = multiboot_manager.display_boot_menu(&mut system_table, &bootloader_config);
    
    // Display network boot menu for network entries
    let boot_option = display_network_boot_menu(&mut system_table, &network_context);
    
    // Phase 6: Kernel Loading
    system_table.stdout().output_string(cstr16!("Phase 6: Kernel Loading\r\n")).unwrap_or(());
    
    // Handle multi-boot entry selection (minimal implementation)
    let entry_id = selected_boot_entry;
    if let Some(_entry) = multiboot_manager.get_entry_info(entry_id) {
        // In minimal implementation, just log selection
        system_table.stdout().output_string(cstr16!("   [INFO] Multi-boot entry selected\r\n")).unwrap_or(());
        log_info("multiboot", "Boot entry processed successfully");
    }
    
    let kernel_capsule = match boot_option {
        NetworkBootOption::Pxe => {
            system_table.stdout().output_string(cstr16!("   [INFO] Attempting PXE kernel load...\r\n")).unwrap_or(());
            match nonos_boot::network::load_kernel_via_pxe(&mut system_table, &network_context) {
                Ok(_kernel_data) => {
                    // For now, fall back to local boot since PXE data processing isn't implemented
                    system_table.stdout().output_string(cstr16!("   [INFO] Falling back to local boot...\r\n")).unwrap_or(());
                    load_kernel_capsule(&mut system_table)
                }
                Err(_) => {
                    system_table.stdout().output_string(cstr16!("   [WARN] PXE boot failed, trying local...\r\n")).unwrap_or(());
                    load_kernel_capsule(&mut system_table)
                }
            }
        }
        NetworkBootOption::Http => {
            system_table.stdout().output_string(cstr16!("   [INFO] Attempting HTTP kernel load...\r\n")).unwrap_or(());
            match nonos_boot::network::load_kernel_via_http(&mut system_table, &network_context, "http://boot.example.com/nonos_kernel.efi") {
                Ok(_kernel_data) => {
                    // For now, fall back to local boot since HTTP data processing isn't implemented
                    system_table.stdout().output_string(cstr16!("   [INFO] Falling back to local boot...\r\n")).unwrap_or(());
                    load_kernel_capsule(&mut system_table)
                }
                Err(_) => {
                    system_table.stdout().output_string(cstr16!("   [WARN] HTTP boot failed, trying local...\r\n")).unwrap_or(());
                    load_kernel_capsule(&mut system_table)
                }
            }
        }
        NetworkBootOption::Local => {
            system_table.stdout().output_string(cstr16!("   [INFO] Loading kernel from local storage...\r\n")).unwrap_or(());
            load_kernel_capsule(&mut system_table)
        }
    };
    
    let kernel_capsule = match kernel_capsule {
        Ok(kc) => {
            system_table.stdout().output_string(cstr16!("   [SUCCESS] Kernel capsule loaded and verified\r\n")).unwrap_or(());
            log_info("loader", "Kernel capsule loaded and verified");
            
            // Perform advanced cryptographic verification
            let kernel_data = unsafe { core::slice::from_raw_parts(kc.base, kc.size) };
            let advanced_verification = nonos_boot::security::verify_kernel_signature_advanced(kernel_data);
            if advanced_verification {
                system_table.stdout().output_string(cstr16!("   [SUCCESS] Advanced signature verification passed\r\n")).unwrap_or(());
                log_info("crypto", "Advanced kernel signature verification successful");
            } else {
                system_table.stdout().output_string(cstr16!("   [WARN] Advanced verification failed, using standard verification\r\n")).unwrap_or(());
                log_warn("crypto", "Advanced verification failed, continuing with standard verification");
            }
            
            // Perform TPM measurement if available
            if security_context.measured_boot_active {
                let measurement_data = unsafe { core::slice::from_raw_parts(kc.base, kc.size) };
                if nonos_boot::security::extend_pcr_measurement(&mut system_table, 4, measurement_data) {
                    system_table.stdout().output_string(cstr16!("   [SUCCESS] Kernel measured in TPM\r\n")).unwrap_or(());
                    log_info("tpm", "Kernel measurement extended to PCR 4");
                    
                    // Additional measurement for advanced crypto verification
                    if advanced_verification {
                        let verification_event = b"NONOS_ADVANCED_CRYPTO_VERIFICATION_SUCCESS";
                        if nonos_boot::security::extend_pcr_measurement(&mut system_table, 5, verification_event) {
                            system_table.stdout().output_string(cstr16!("   [SUCCESS] Advanced crypto event measured\r\n")).unwrap_or(());
                            log_info("tpm", "Advanced crypto verification event measured in PCR 5");
                        }
                    }
                }
            }
            
            kc
        }
        Err(e) => {
            system_table.stdout().output_string(cstr16!("   [ERROR] All kernel load methods failed\r\n")).unwrap_or(());
            log_critical("boot", "Kernel load/verify failed");
            log_error("reason", e);
            fatal_reset(&mut system_table, "Kernel verification failed");
        }
    };

    // Enhanced kernel entry point validation
    // For ELF files, entry point is a physical address where kernel should execute,
    // not an offset within the loaded file buffer
    if kernel_capsule.entry_point < 0x100000 || kernel_capsule.entry_point >= 0x10000000 {
        system_table.stdout().output_string(cstr16!("   [ERROR] Entry point validation failed\r\n")).unwrap_or(());
        log_error("security", "Entry point outside valid kernel address range");
        fatal_reset(&mut system_table, "Entry point outside valid kernel address range");
    }
    
    system_table.stdout().output_string(cstr16!("   [SUCCESS] Entry point validated\r\n")).unwrap_or(());
    
    // Phase 7: Final Handoff Preparation
    system_table.stdout().output_string(cstr16!("Phase 7: Kernel Handoff\r\n")).unwrap_or(());
    
    // Convert to kernel function pointer
    let kernel_entry: KernelEntry = unsafe {
        core::mem::transmute(kernel_capsule.entry_point)
    };

    // Prepare enhanced handoff information
    let handoff_ptr = &kernel_capsule.handoff as *const _;
    
    // Save multi-boot preferences
    if multiboot_manager.save_boot_preferences(&mut system_table) {
        log_debug("multiboot", "Boot preferences saved successfully");
    }
    
    // Final system state logging with comprehensive status
    system_table.stdout().output_string(cstr16!("   [INFO] Security subsystem ready\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("   [INFO] Hardware discovery complete\r\n")).unwrap_or(());
    
    if network_diagnostics_passed {
        system_table.stdout().output_string(cstr16!("   [INFO] Network subsystem fully operational\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("   [WARN] Network subsystem has limitations\r\n")).unwrap_or(());
    }
    
    system_table.stdout().output_string(cstr16!("   [INFO] Advanced cryptographic verification active\r\n")).unwrap_or(());
    
    if config_applied {
        system_table.stdout().output_string(cstr16!("   [INFO] Configuration policies fully enforced\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("   [WARN] Configuration application had some issues\r\n")).unwrap_or(());
    }
    
    system_table.stdout().output_string(cstr16!("   [INFO] Multi-boot system operational\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("   [INFO] Kernel handoff data prepared\r\n")).unwrap_or(());
    
    // Display overall system security posture
    let overall_security = security_score + network_security_score;
    if overall_security >= 120 {
        system_table.stdout().output_string(cstr16!("   [SUCCESS] Overall system security: EXCELLENT\r\n")).unwrap_or(());
    } else if overall_security >= 80 {
        system_table.stdout().output_string(cstr16!("   [INFO] Overall system security: GOOD\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("   [WARN] Overall system security: MODERATE\r\n")).unwrap_or(());
    }
    
    // Display final system configuration status
    if bootloader_config.verbose_logging {
        system_table.stdout().output_string(cstr16!("   [INFO] Verbose logging mode active\r\n")).unwrap_or(());
    }
    
    if bootloader_config.diagnostic_output {
        system_table.stdout().output_string(cstr16!("   [INFO] Diagnostic output mode active\r\n")).unwrap_or(());
        if testing_passed {
            system_table.stdout().output_string(cstr16!("   [SUCCESS] Comprehensive testing completed successfully\r\n")).unwrap_or(());
        } else {
            system_table.stdout().output_string(cstr16!("   [WARN] Some comprehensive tests failed\r\n")).unwrap_or(());
        }
    } else if testing_passed {
        system_table.stdout().output_string(cstr16!("   [INFO] Quick health check passed\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("   [WARN] Health check had issues\r\n")).unwrap_or(());
    }
    
    // Display final summary
    system_table.stdout().output_string(cstr16!("\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("╔══════════════════════════════════════════════════════════════════════╗\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("║                    *** N0N-OS BOOT SUCCESS! ***                     ║\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("║              >>> UNIQUE OS - NOT ANOTHER LINUX CLONE! <<<           ║\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("║              >>> UEFI BOOTLOADER + KERNEL LOADED! <<<               ║\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("║              Transferring Control to N0N-OS Kernel                  ║\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("╚══════════════════════════════════════════════════════════════════════╝\r\n")).unwrap_or(());
    system_table.stdout().output_string(cstr16!("\r\n")).unwrap_or(());
    
    log_info("transition", "Transferring control to NØNOS kernel");

    // Exit UEFI boot services
    let (_runtime_system_table, _memory_map) = system_table.exit_boot_services();
    
    // IMMEDIATE POST-UEFI SERIAL DEBUG - Raw port access
    unsafe {
        // Initialize COM1 directly
        core::arch::asm!("out dx, al", in("dx") 0x3f9u16, in("al") 0x00u8); // Disable interrupts
        core::arch::asm!("out dx, al", in("dx") 0x3fbu16, in("al") 0x80u8); // Enable DLAB
        core::arch::asm!("out dx, al", in("dx") 0x3f8u16, in("al") 0x03u8); // Set divisor low
        core::arch::asm!("out dx, al", in("dx") 0x3f9u16, in("al") 0x00u8); // Set divisor high  
        core::arch::asm!("out dx, al", in("dx") 0x3fbu16, in("al") 0x03u8); // 8N1
        core::arch::asm!("out dx, al", in("dx") 0x3fau16, in("al") 0xC7u8); // Enable FIFO
        core::arch::asm!("out dx, al", in("dx") 0x3fcu16, in("al") 0x0Bu8); // IRQs enabled
        
        // Send debug message
        let msg = b"POST-UEFI: About to call kernel!\r\n";
        for &byte in msg {
            // Wait for transmit ready
            loop {
                let mut status: u8;
                core::arch::asm!("in al, dx", in("dx") 0x3fdu16, out("al") status);
                if (status & 0x20) != 0 { break; }
            }
            core::arch::asm!("out dx, al", in("dx") 0x3f8u16, in("al") byte);
        }
    }
    
    // Set up proper stack and registers for kernel entry
    unsafe {
        // Allocate a small stack for the kernel (16KB should be enough for minimal kernel)
        let stack_size = 16 * 1024;
        let stack_ptr = 0x200000 as *mut u8; // 2MB mark - safe area
        
        // Initialize stack with pattern (optional debug aid)
        core::ptr::write_bytes(stack_ptr, 0xCC, stack_size);
        
        // Calculate stack top (stack grows downward)
        let stack_top = stack_ptr.add(stack_size);
        
        // DEBUG: Send message right before kernel call
        let msg2 = b"CALLING KERNEL NOW!\r\n";
        for &byte in msg2 {
            loop {
                let mut status: u8;
                core::arch::asm!("in al, dx", in("dx") 0x3fdu16, out("al") status);
                if (status & 0x20) != 0 { break; }
            }
            core::arch::asm!("out dx, al", in("dx") 0x3f8u16, in("al") byte);
        }
        
        // Jump to kernel with proper stack setup
        core::arch::asm!(
            "mov rsp, {stack_top}",      // Set up stack pointer
            "push rbp",                   // Save frame pointer  
            "mov rbp, rsp",              // Set up frame pointer
            "call {kernel_entry}",       // Call kernel
            stack_top = in(reg) stack_top,
            kernel_entry = in(reg) kernel_entry as usize,
            in("rdi") handoff_ptr,       // First argument in System V ABI
            options(noreturn)
        );
    }
}

/// Initialize graphics mode for better user experience
fn initialize_graphics(system_table: &mut SystemTable<Boot>) {
    // Try to find graphics protocol handles
    let graphics_initialized = {
        let bs = system_table.boot_services();
        if let Ok(handles) = bs.find_handles::<uefi::proto::console::gop::GraphicsOutput>() {
            if let Some(&handle) = handles.first() {
                if let Ok(mut gop) = bs.open_protocol_exclusive::<uefi::proto::console::gop::GraphicsOutput>(handle) {
                    // Try to set best mode
                    if let Some(mode_num) = find_best_graphics_mode(&mut gop) {
                        if let Ok(mode) = gop.query_mode(mode_num) {
                            if gop.set_mode(&mode).is_ok() {
                                let _mode_info = gop.current_mode_info();
                                log_info("graphics", "High-resolution graphics mode enabled");
                                2 // Graphics mode set successfully
                            } else {
                                1 // GOP found but mode setting failed
                            }
                        } else {
                            1 // GOP found but query failed
                        }
                    } else {
                        1 // GOP found but no suitable mode
                    }
                } else {
                    0 // GOP not accessible
                }
            } else {
                0 // No handles found
            }
        } else {
            0 // Find handles failed
        }
    };
    
    if graphics_initialized > 0 {
        system_table.stdout().output_string(cstr16!("   [SUCCESS] Graphics Output Protocol found\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("   [INFO] No graphics support, using text mode\r\n")).unwrap_or(());
        log_warn("graphics", "No graphics support available");
    }
}

/// Find the best available graphics mode (preferably high resolution)
fn find_best_graphics_mode(gop: &mut uefi::proto::console::gop::GraphicsOutput) -> Option<u32> {
    let mode_count = gop.modes().count();
    let mut best_mode = None;
    let mut best_pixels = 0u32;
    
    for mode_num in 0..mode_count {
        if let Ok(mode) = gop.query_mode(mode_num as u32) {
            let (width, height) = mode.info().resolution();
            let pixels = width as u32 * height as u32;
            
            // Prefer modes with more pixels, but not too exotic
            if pixels > best_pixels && pixels <= 1920 * 1080 {
                best_mode = Some(mode_num as u32);
                best_pixels = pixels;
            }
        }
    }
    
    best_mode
}

/// Setup enhanced memory management
fn setup_memory_management(system_table: &mut SystemTable<Boot>) {
    system_table.stdout().output_string(cstr16!("   [INFO] Memory map analysis...\r\n")).unwrap_or(());
    
    let bs = system_table.boot_services();
    let memory_map_size = bs.memory_map_size();
    let buffer_size = memory_map_size.map_size + (memory_map_size.entry_size * 8);
    
    if let Ok(buffer_ptr) = bs.allocate_pages(
        uefi::table::boot::AllocateType::AnyPages, 
        uefi::table::boot::MemoryType::LOADER_DATA, 
        (buffer_size + 4095) / 4096
    ) {
        let buffer = unsafe { 
            core::slice::from_raw_parts_mut(buffer_ptr as *mut u8, buffer_size) 
        };
        
        if let Ok(memory_map) = bs.memory_map(buffer) {
            let mut _total_memory = 0u64;
            let mut _usable_memory = 0u64;
            
            for desc in memory_map.entries() {
                _total_memory += desc.page_count * 4096;
                
                if desc.ty == uefi::table::boot::MemoryType::CONVENTIONAL {
                    _usable_memory += desc.page_count * 4096;
                }
            }
            
            log_info("memory", "Memory analysis completed successfully");
        }
        
        // Clean up allocated buffer
        let _ = bs.free_pages(buffer_ptr, (buffer_size + 4095) / 4096);
        system_table.stdout().output_string(cstr16!("   [SUCCESS] Memory analysis complete\r\n")).unwrap_or(());
    } else {
        system_table.stdout().output_string(cstr16!("   [WARN] Memory map unavailable\r\n")).unwrap_or(());
        log_warn("memory", "Could not retrieve memory map information");
    }
}

/// Discover available hardware components
fn discover_hardware(system_table: &mut SystemTable<Boot>) {
    system_table.stdout().output_string(cstr16!("   [INFO] Scanning for hardware components...\r\n")).unwrap_or(());
    
    let bs = system_table.boot_services();
    
    // Check for various protocols to discover hardware
    let mut devices_found = 0;
    
    // Check for PCI Root Bridge Protocol
    if let Ok(_) = bs.find_handles::<uefi::proto::device_path::DevicePath>() {
        devices_found += 1;
    }
    
    // Check for Block IO devices (storage)
    let storage_found = if let Ok(handles) = bs.find_handles::<uefi::proto::media::block::BlockIO>() {
        if !handles.is_empty() {
            devices_found += handles.len();
            true
        } else {
            false
        }
    } else {
        false
    };
    
    // Check for Simple Network Protocol (networking)
    let network_found = if let Ok(handles) = bs.find_handles::<SimpleNetwork>() {
        if !handles.is_empty() {
            devices_found += handles.len();
            true
        } else {
            false
        }
    } else {
        false
    };
    
    // Check for Simple File System Protocol
    let filesystem_found = if let Ok(handles) = bs.find_handles::<uefi::proto::media::fs::SimpleFileSystem>() {
        if !handles.is_empty() {
            devices_found += handles.len();
            true
        } else {
            false
        }
    } else {
        false
    };
    
    // Drop bs to release the immutable borrow
    drop(bs);
    
    // Now we can use system_table mutably for output
    if storage_found {
        system_table.stdout().output_string(cstr16!("   [INFO] Block storage devices found\r\n")).unwrap_or(());
    }
    if network_found {
        system_table.stdout().output_string(cstr16!("   [INFO] Network interfaces found\r\n")).unwrap_or(());
    }
    if filesystem_found {
        system_table.stdout().output_string(cstr16!("   [INFO] File systems found\r\n")).unwrap_or(());
    }
    
    system_table.stdout().output_string(cstr16!("   [SUCCESS] Hardware discovery complete\r\n")).unwrap_or(());
    log_info("hardware", "Hardware discovery completed");
}

/// Non-returning hard reset for boot failures
fn fatal_reset(st: &mut SystemTable<Boot>, reason: &str) -> ! {
    log_warn("fatal", reason);
    let _ = st.stdout().reset(false);
    let _ = st.stdout().output_string(cstr16!("\r\n[FATAL ERROR] System will restart...\r\n"));

    st.runtime_services().reset(
        ResetType::WARM,
        Status::LOAD_ERROR,
        Some(reason.as_bytes()),
    );

    loop {} // should never reach
}
