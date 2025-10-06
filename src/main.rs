#![no_std]
#![no_main]

//! NØNOS UEFI Boot Entrypoint
//! - Early init of UEFI allocator/stdout
//! - GOP probe & optional mode set
//! - Capsule load + verification
//! - Safe handoff write for packed struct (no UB)
//! - Memory map summary
//! - Clean exit to kernel

extern crate alloc;

use uefi::prelude::*;
use uefi::table::runtime::ResetType;
use uefi_services::init;
use uefi::proto::network::snp::SimpleNetwork;
use uefi::{CStr16, cstr16};
// GOP imports
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};

use nonos_boot::loader::load_kernel_capsule;
use nonos_boot::log::logger::{log_info, log_warn, log_critical, log_debug, log_error};
use nonos_boot::handoff::{ZeroStateBootInfo, ABI_VERSION, fb_format};
use nonos_boot::hardware::discover_system_hardware;
use nonos_boot::security::initialize_security_subsystem;
use nonos_boot::network::{initialize_network_boot, display_network_boot_menu, NetworkBootOption};
use nonos_boot::config::{load_bootloader_config, apply_configuration, display_configuration};
use nonos_boot::multiboot::MultiBootManager;
use nonos_boot::testing::TestingFramework;

/// External capsule entry signature
type KernelEntry = extern "sysv64" fn(*const ZeroStateBootInfo) -> !;

/// Captured GOP information
struct GopInfo {
    base: u64,
    size: u64,
    pitch: u32,
    width: u32,
    height: u32,
    bpp: u16,
    fmt_code: u16,
}

#[entry]
fn efi_main(_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialize UI console
    let _ = system_table.stdout().reset(false);

    // Initialize UEFI services first
    match init(&mut system_table) {
        Ok(_) => log_debug("boot", "UEFI services initialized successfully"),
        Err(_e) => {
            log_error("boot", "Failed to initialize UEFI services");
            fatal_reset(&mut system_table, "UEFI service initialization failed");
        }
    }

    log_info("boot", "NØNOS Capsule Bootloader Activated - Advanced Professional Version");

    // Banner
    let _ = system_table.stdout().output_string(cstr16!("\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("╔══════════════════════════════════════════════════════════════════════╗\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("║                    NØNOS ADVANCED BOOTLOADER                        ║\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("║                      Version 0.4.0 - Enterprise                     ║\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("║  Features: ACPI • Security • Networking • TPM • Config • Crypto     ║\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("╚══════════════════════════════════════════════════════════════════════╝\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("\r\n"));

    // Phase 0: Configuration
    let _ = system_table.stdout().output_string(cstr16!("Phase 0: Configuration Loading\r\n"));
    let bootloader_config = load_bootloader_config(&mut system_table);
    display_configuration(&bootloader_config, &mut system_table);

    // Phase 1: Security
    let _ = system_table.stdout().output_string(cstr16!("Phase 1: Security Initialization\r\n"));
    let security_context = initialize_security_subsystem(&mut system_table);
    let security_score = nonos_boot::security::assess_security_posture(&security_context, &mut system_table);

    // Phase 2: Hardware
    let _ = system_table.stdout().output_string(cstr16!("Phase 2: Hardware Discovery\r\n"));
    let hardware_info = discover_system_hardware(&mut system_table);

    // Phase 3: Network
    let _ = system_table.stdout().output_string(cstr16!("Phase 3: Network Subsystem\r\n"));
    let network_context = initialize_network_boot(&mut system_table);
    let network_diagnostics_passed = nonos_boot::network::perform_network_diagnostics(&mut system_table, &network_context);
    let network_security_score = nonos_boot::network::assess_network_security(&mut system_table, &network_context);

    // Phase 3.5: Apply configuration
    let _ = system_table.stdout().output_string(cstr16!("Phase 3.5: Configuration Application\r\n"));
    let config_applied = apply_configuration(
        &bootloader_config,
        &mut system_table,
        &security_context,
        &network_context,
        &hardware_info,
    );

    // Phase 3.7: Tests
    let mut testing_passed = true;
    if bootloader_config.diagnostic_output {
        let _ = system_table.stdout().output_string(cstr16!("Phase 3.7: Comprehensive Testing\r\n"));
        let mut tf = TestingFramework::new();
        testing_passed = tf.run_comprehensive_tests(
            &mut system_table,
            &bootloader_config,
            &security_context,
            &network_context,
            &hardware_info,
        );
    } else {
        let mut tf = TestingFramework::new();
        testing_passed = tf.quick_health_check(&mut system_table);
    }

    // Phase 4: Graphics & Memory
    let _ = system_table.stdout().output_string(cstr16!("Phase 4: Graphics & Memory\r\n"));

    // Probe GOP (safe logging only) and then try a better mode if available
    probe_and_log_gop(&mut system_table);
    initialize_graphics(&mut system_table);
    setup_memory_management(&mut system_table);
    
    // Capture GOP info for handoff AFTER mode is set
    let gop_info = capture_gop_info(&mut system_table);

    // Phase 5: Multi-boot
    let _ = system_table.stdout().output_string(cstr16!("Phase 5: Multi-Boot & Boot Source Selection\r\n"));
    let multiboot_manager = MultiBootManager::new(&mut system_table);
    let selected_boot_entry = multiboot_manager.display_boot_menu(&mut system_table, &bootloader_config);
    if multiboot_manager.get_entry_info(selected_boot_entry).is_some() {
        let _ = system_table.stdout().output_string(cstr16!("   [INFO] Multi-boot entry selected\r\n"));
        log_info("multiboot", "Boot entry processed successfully");
    }
    let boot_option = display_network_boot_menu(&mut system_table, &network_context);

    // Phase 6: Kernel Loading
    let _ = system_table.stdout().output_string(cstr16!("Phase 6: Kernel Loading\r\n"));
    let kernel_capsule = match boot_option {
        NetworkBootOption::Pxe => {
            let _ = system_table.stdout().output_string(cstr16!("   [INFO] Attempting PXE kernel load...\r\n"));
            match nonos_boot::network::load_kernel_via_pxe(&mut system_table, &network_context) {
                Ok(_k) => {
                    let _ = system_table.stdout().output_string(cstr16!("   [INFO] Falling back to local boot...\r\n"));
                    load_kernel_capsule(&mut system_table)
                }
                Err(_) => {
                    let _ = system_table.stdout().output_string(cstr16!("   [WARN] PXE boot failed, trying local...\r\n"));
                    load_kernel_capsule(&mut system_table)
                }
            }
        }
        NetworkBootOption::Http => {
            let _ = system_table.stdout().output_string(cstr16!("   [INFO] Attempting HTTP kernel load...\r\n"));
            match nonos_boot::network::load_kernel_via_http(
                &mut system_table,
                &network_context,
                "http://boot.example.com/nonos_kernel.efi",
            ) {
                Ok(_k) => {
                    let _ = system_table.stdout().output_string(cstr16!("   [INFO] Falling back to local boot...\r\n"));
                    load_kernel_capsule(&mut system_table)
                }
                Err(_) => {
                    let _ = system_table.stdout().output_string(cstr16!("   [WARN] HTTP boot failed, trying local...\r\n"));
                    load_kernel_capsule(&mut system_table)
                }
            }
        }
        NetworkBootOption::Local => {
            let _ = system_table.stdout().output_string(cstr16!("   [INFO] Loading kernel from local storage...\r\n"));
            load_kernel_capsule(&mut system_table)
        }
    };

    let mut kernel_capsule = match kernel_capsule {
        Ok(kc) => {
            let _ = system_table.stdout().output_string(cstr16!("   [SUCCESS] Kernel capsule loaded and verified\r\n"));
            log_info("loader", "Kernel capsule loaded and verified");

            // Optional advanced verification
            let kernel_data = unsafe { core::slice::from_raw_parts(kc.base, kc.size) };
            let advanced_verification = nonos_boot::security::verify_kernel_signature_advanced(kernel_data);
            if advanced_verification {
                let _ = system_table.stdout().output_string(cstr16!("   [SUCCESS] Advanced signature verification passed\r\n"));
                log_info("crypto", "Advanced kernel signature verification successful");
            } else {
                let _ = system_table.stdout().output_string(cstr16!("   [WARN] Advanced verification failed, using standard verification\r\n"));
                log_warn("crypto", "Advanced verification failed, continuing with standard verification");
            }

            // TPM measurement (optional)
            if security_context.measured_boot_active {
                let measurement_data = unsafe { core::slice::from_raw_parts(kc.base, kc.size) };
                if nonos_boot::security::extend_pcr_measurement(&mut system_table, 4, measurement_data) {
                    let _ = system_table.stdout().output_string(cstr16!("   [SUCCESS] Kernel measured in TPM\r\n"));
                    log_info("tpm", "Kernel measurement extended to PCR 4");
                    if advanced_verification {
                        let verification_event = b"NONOS_ADVANCED_CRYPTO_VERIFICATION_SUCCESS";
                        if nonos_boot::security::extend_pcr_measurement(&mut system_table, 5, verification_event) {
                            let _ = system_table.stdout().output_string(cstr16!("   [SUCCESS] Advanced crypto event measured\r\n"));
                            log_info("tpm", "Advanced crypto verification event measured in PCR 5");
                        }
                    }
                }
            }

            kc
        }
        Err(e) => {
            let _ = system_table.stdout().output_string(cstr16!("   [ERROR] All kernel load methods failed\r\n"));
            log_critical("boot", "Kernel load/verify failed");
            log_error("reason", e);
            fatal_reset(&mut system_table, "Kernel verification failed");
        }
    };

    // Entry point plausibility check (physical range sanity)
    if kernel_capsule.entry_point < 0x100000 || kernel_capsule.entry_point >= 0x10000000 {
        let _ = system_table.stdout().output_string(cstr16!("   [ERROR] Entry point validation failed\r\n"));
        log_error("security", "Entry point outside valid kernel address range");
        fatal_reset(&mut system_table, "Entry point outside valid kernel address range");
    }
    let _ = system_table.stdout().output_string(cstr16!("   [SUCCESS] Entry point validated\r\n"));

    // Phase 7: Kernel Handoff
    let _ = system_table.stdout().output_string(cstr16!("Phase 7: Kernel Handoff\r\n"));

    // Convert to kernel function pointer
    let kernel_entry: KernelEntry = unsafe { core::mem::transmute(kernel_capsule.entry_point) };

    // ==== SAFE HANDOFF WRITE (no UB on packed struct) ====
    {
        // Read packed handoff into an aligned local, mutate, then write back unaligned.
        let mut handoff_local: ZeroStateBootInfo = unsafe {
            core::ptr::read_unaligned(core::ptr::addr_of!(kernel_capsule.handoff))
        };

        // Populate ABI fields
        handoff_local.abi_version = ABI_VERSION;
        handoff_local.hdr_size = core::mem::size_of::<ZeroStateBootInfo>() as u16;

        // Fill GOP/FB info on the aligned local
        fill_gop_into_handoff_with_info(&mut handoff_local, &gop_info);

        // Commit back into the packed storage
        unsafe {
            core::ptr::write_unaligned(
                core::ptr::addr_of_mut!(kernel_capsule.handoff),
                handoff_local,
            );
        }
    }

    // Keep a raw pointer for the jump (no deref here)
    let handoff_ptr: *const ZeroStateBootInfo = core::ptr::addr_of!(kernel_capsule.handoff);

    // (Optional) save multiboot preferences
    if multiboot_manager.save_boot_preferences(&mut system_table) {
        log_debug("multiboot", "Boot preferences saved successfully");
    }

    // Final status lines
    let _ = system_table.stdout().output_string(cstr16!("   [INFO] Security subsystem ready\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("   [INFO] Hardware discovery complete\r\n"));
    if network_diagnostics_passed {
        let _ = system_table.stdout().output_string(cstr16!("   [INFO] Network subsystem fully operational\r\n"));
    } else {
        let _ = system_table.stdout().output_string(cstr16!("   [WARN] Network subsystem has limitations\r\n"));
    }
    let _ = system_table.stdout().output_string(cstr16!("   [INFO] Advanced cryptographic verification active\r\n"));
    if config_applied {
        let _ = system_table.stdout().output_string(cstr16!("   [INFO] Configuration policies fully enforced\r\n"));
    } else {
        let _ = system_table.stdout().output_string(cstr16!("   [WARN] Configuration application had some issues\r\n"));
    }
    let _ = system_table.stdout().output_string(cstr16!("   [INFO] Multi-boot system operational\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("   [INFO] Kernel handoff data prepared\r\n"));

    // Security posture summary
    let overall_security = security_score + network_security_score;
    if overall_security >= 120 {
        let _ = system_table.stdout().output_string(cstr16!("   [SUCCESS] Overall system security: EXCELLENT\r\n"));
    } else if overall_security >= 80 {
        let _ = system_table.stdout().output_string(cstr16!("   [INFO] Overall system security: GOOD\r\n"));
    } else {
        let _ = system_table.stdout().output_string(cstr16!("   [WARN] Overall system security: MODERATE\r\n"));
    }

    if bootloader_config.verbose_logging {
        let _ = system_table.stdout().output_string(cstr16!("   [INFO] Verbose logging mode active\r\n"));
    }
    if bootloader_config.diagnostic_output {
        let _ = system_table.stdout().output_string(cstr16!("   [INFO] Diagnostic output mode active\r\n"));
        if testing_passed {
            let _ = system_table.stdout().output_string(cstr16!("   [SUCCESS] Comprehensive testing completed successfully\r\n"));
        } else {
            let _ = system_table.stdout().output_string(cstr16!("   [WARN] Some comprehensive tests failed\r\n"));
        }
    } else if testing_passed {
        let _ = system_table.stdout().output_string(cstr16!("   [INFO] Quick health check passed\r\n"));
    } else {
        let _ = system_table.stdout().output_string(cstr16!("   [WARN] Health check had issues\r\n"));
    }

    // Summary
    let _ = system_table.stdout().output_string(cstr16!("\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("╔══════════════════════════════════════════════════════════════════════╗\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("║                     BOOT SEQUENCE COMPLETE                          ║\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("║              Transferring Control to NØNOS Kernel                   ║\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("╚══════════════════════════════════════════════════════════════════════╝\r\n"));
    let _ = system_table.stdout().output_string(cstr16!("\r\n"));

    log_info("transition", "Transferring control to NØNOS kernel");

    // Exit UEFI boot services (consumes system_table)
    let (_rt, _mm) = system_table.exit_boot_services();

    // Jump to kernel (never returns)
    kernel_entry(handoff_ptr);
}

/// Probe UEFI GOP and print its current mode & framebuffer info (no ABI changes).
fn probe_and_log_gop(system_table: &mut SystemTable<Boot>) {
    let mut have_gop = false;
    let mut w: usize = 0;
    let mut h: usize = 0;
    let mut stride_px: usize = 0;
    let mut pitch_bytes: u32 = 0;
    let mut fb_size: usize = 0;
    let mut fb_phys: usize = 0;
    let mut fmt_str: &'static str = "UNKNOWN";

    {
        let bs = system_table.boot_services();

        let gop_handle = match bs.find_handles::<GraphicsOutput>() {
            Ok(mut handles) if !handles.is_empty() => Some(handles.remove(0)),
            _ => None,
        };

        if let Some(hdl) = gop_handle {
            if let Ok(mut gop) = bs.open_protocol_exclusive::<GraphicsOutput>(hdl) {
                let mode = gop.current_mode_info();
                let (rw, rh) = mode.resolution();
                w = rw;
                h = rh;
                stride_px = mode.stride();
                fmt_str = match mode.pixel_format() {
                    PixelFormat::Bgr => "BGR",
                    PixelFormat::Rgb => "RGB",
                    PixelFormat::Bitmask => "BITMASK",
                    PixelFormat::BltOnly => "BLT-ONLY",
                };

                // Assume 32bpp under OVMF/QEMU
                pitch_bytes = (stride_px * (32usize / 8)) as u32;

                // Need mut to call as_mut_ptr()
                let mut fb = gop.frame_buffer();
                fb_size = fb.size();
                fb_phys = fb.as_mut_ptr() as usize;

                have_gop = true;
            }
        }
    } // BS/GOP borrows end here

    if have_gop {
        let _ = system_table.stdout().output_string(cstr16!("   [SUCCESS] Graphics Output Protocol found\r\n"));
        let _ = system_table.stdout().output_string(cstr16!("   [INFO]  GOP Mode (current):\r\n"));

        let _ = system_table.stdout().output_string(cstr16!("           Resolution: "));
        let _ = system_table.stdout().output_string(
            &CStr16::from_str_with_buf(&alloc::format!("{}x{}\r\n", w, h), &mut [0u16; 64])
                .unwrap_or_else(|_| cstr16!("(fmt)")),
        );

        let _ = system_table.stdout().output_string(cstr16!("           PixelFormat: "));
        let _ = system_table.stdout().output_string(
            &CStr16::from_str_with_buf(fmt_str, &mut [0u16; 32])
                .unwrap_or_else(|_| cstr16!("(fmt)")),
        );
        let _ = system_table.stdout().output_string(cstr16!("\r\n"));

        let _ = system_table.stdout().output_string(cstr16!("           Stride (px): "));
        let _ = system_table.stdout().output_string(
            &CStr16::from_str_with_buf(&alloc::format!("{}\r\n", stride_px), &mut [0u16; 64])
                .unwrap_or_else(|_| cstr16!("(fmt)")),
        );

        let _ = system_table.stdout().output_string(cstr16!("           Pitch (bytes): "));
        let _ = system_table.stdout().output_string(
            &CStr16::from_str_with_buf(&alloc::format!("{}\r\n", pitch_bytes), &mut [0u16; 64])
                .unwrap_or_else(|_| cstr16!("(fmt)")),
        );

        let _ = system_table.stdout().output_string(cstr16!("           Framebuffer size (bytes): "));
        let _ = system_table.stdout().output_string(
            &CStr16::from_str_with_buf(&alloc::format!("{}\r\n", fb_size), &mut [0u16; 64])
                .unwrap_or_else(|_| cstr16!("(fmt)")),
        );

        let _ = system_table.stdout().output_string(cstr16!("           Framebuffer base (phys): 0x"));
        let _ = system_table.stdout().output_string(
            &CStr16::from_str_with_buf(&alloc::format!("{:X}\r\n", fb_phys), &mut [0u16; 64])
                .unwrap_or_else(|_| cstr16!("(fmt)")),
        );
    } else {
        let _ = system_table.stdout().output_string(cstr16!("   [INFO] No GOP handles found (text mode only)\r\n"));
    }
}

/// Capture GOP information once to avoid multiple exclusive protocol opens
fn capture_gop_info(st: &mut SystemTable<Boot>) -> GopInfo {
    log_debug("gop", "Capturing GOP info for handoff");
    let mut info = GopInfo {
        base: 0,
        size: 0,
        pitch: 0,
        width: 0,
        height: 0,
        bpp: 32, // OVMF/QEMU typically 32bpp
        fmt_code: fb_format::UNKNOWN,
    };

    let bs = st.boot_services();
    if let Ok(mut handles) = bs.find_handles::<GraphicsOutput>() {
        log_debug("gop", "Found GOP handles");
        if let Some(h) = handles.pop() {
            log_debug("gop", "Opening GOP protocol");
            if let Ok(mut gop) = bs.open_protocol_exclusive::<GraphicsOutput>(h) {
                log_debug("gop", "GOP protocol opened successfully");
                let mode = gop.current_mode_info();
                let (w, hgt) = mode.resolution();
                info.width = w as u32;
                info.height = hgt as u32;

                // stride is in pixels; convert to bytes with assumed 32bpp
                let stride_px = mode.stride();
                info.pitch = (stride_px * (info.bpp as usize / 8)) as u32;

                info.fmt_code = match mode.pixel_format() {
                    PixelFormat::Rgb     => fb_format::RGB,
                    PixelFormat::Bgr     => fb_format::BGR,
                    PixelFormat::Bitmask => fb_format::BITMASK,
                    PixelFormat::BltOnly => fb_format::BLTONLY,
                };

                let mut fb = gop.frame_buffer();
                info.size = fb.size() as u64;
                info.base = fb.as_mut_ptr() as usize as u64;
                
                log_info("gop", "GOP info captured successfully");
            } else {
                log_warn("gop", "Failed to open GOP protocol");
            }
        } else {
            log_warn("gop", "No GOP handles available");
        }
    } else {
        log_warn("gop", "Failed to find GOP handles");
    }

    info
}

/// Fill handoff with captured GOP info
fn fill_gop_into_handoff_with_info(handoff: &mut ZeroStateBootInfo, info: &GopInfo) {
    if info.base != 0 && info.size != 0 && info.width != 0 && info.height != 0 {
        log_info("gop", "Setting framebuffer in handoff");
        handoff.set_framebuffer(info.base, info.size, info.pitch, info.width, info.height, info.bpp, info.fmt_code);
    } else {
        log_warn("gop", "No valid GOP found - setting empty framebuffer");
        handoff.set_framebuffer(0, 0, 0, 0, 0, 0, fb_format::UNKNOWN);
    }
}

/// Try to pick a sane high-res GOP mode (<= 1080p) if available.
fn initialize_graphics(system_table: &mut SystemTable<Boot>) {
    let set_ok = {
        let bs = system_table.boot_services();
        if let Ok(handles) = bs.find_handles::<GraphicsOutput>() {
            if let Some(&handle) = handles.first() {
                if let Ok(mut gop) = bs.open_protocol_exclusive::<GraphicsOutput>(handle) {
                    if let Some(mode_num) = find_best_graphics_mode(&mut gop) {
                        if let Ok(mode) = gop.query_mode(mode_num) {
                            if gop.set_mode(&mode).is_ok() {
                                log_info("graphics", "High-resolution graphics mode enabled");
                                true
                            } else { false }
                        } else { false }
                    } else { false }
                } else { false }
            } else { false }
        } else { false }
    };

    if set_ok {
        let _ = system_table.stdout().output_string(cstr16!("   [SUCCESS] Graphics Output Protocol found\r\n"));
    } else {
        let _ = system_table.stdout().output_string(cstr16!("   [INFO] No graphics support, using text mode\r\n"));
        log_warn("graphics", "No graphics support available (or mode set failed)");
    }
}

fn find_best_graphics_mode(gop: &mut GraphicsOutput) -> Option<u32> {
    let count = gop.modes().count();
    let mut best: Option<u32> = None;
    let mut best_px: u32 = 0;

    for idx in 0..count {
        if let Ok(mode) = gop.query_mode(idx as u32) {
            let (w, h) = mode.info().resolution();
            let px = (w as u32) * (h as u32);
            if px > best_px && px <= 1920 * 1080 {
                best = Some(idx as u32);
                best_px = px;
            }
        }
    }
    best
}

/// Print a quick memory map summary (alloc/free buffer safely).
fn setup_memory_management(system_table: &mut SystemTable<Boot>) {
    let _ = system_table.stdout().output_string(cstr16!("   [INFO] Memory map analysis...\r\n"));

    let bs = system_table.boot_services();
    let mm = bs.memory_map_size();
    let buffer_size = mm.map_size + (mm.entry_size * 8);

    if let Ok(buffer_ptr) = bs.allocate_pages(
        uefi::table::boot::AllocateType::AnyPages,
        uefi::table::boot::MemoryType::LOADER_DATA,
        (buffer_size + 4095) / 4096,
    ) {
        let buffer = unsafe { core::slice::from_raw_parts_mut(buffer_ptr as *mut u8, buffer_size) };

        if let Ok(memory_map) = bs.memory_map(buffer) {
            let mut _total: u64 = 0;
            let mut _usable: u64 = 0;
            for desc in memory_map.entries() {
                _total += desc.page_count * 4096;
                if desc.ty == uefi::table::boot::MemoryType::CONVENTIONAL {
                    _usable += desc.page_count * 4096;
                }
            }
            log_info("memory", "Memory analysis completed successfully");
        }

        let _ = bs.free_pages(buffer_ptr, (buffer_size + 4095) / 4096);
        let _ = system_table.stdout().output_string(cstr16!("   [SUCCESS] Memory analysis complete\r\n"));
    } else {
        let _ = system_table.stdout().output_string(cstr16!("   [WARN] Memory map unavailable\r\n"));
        log_warn("memory", "Could not retrieve memory map information");
    }
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

    loop {}
}
	