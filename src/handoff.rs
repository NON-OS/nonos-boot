#![no_std]

/// ABI constants
pub const ABI_VERSION: u16 = 1;

/// Framebuffer format enum (stable ABI: u16 codes)
pub mod fb_format {
    pub const UNKNOWN: u16  = 0;
    pub const RGB: u16      = 1;
    pub const BGR: u16      = 2;
    pub const BITMASK: u16  = 3;
    pub const BLTONLY: u16  = 4;
}

/// Optional boot mode flags (bitfield)
pub mod BootModeFlags {
    pub const NONE: u32          = 0;
    pub const SECURE_BOOT: u32   = 1 << 0;
    pub const COLD_START: u32    = 1 << 1;
    pub const DIAGNOSTIC: u32    = 1 << 2;
}

/// N0NOS boot handoff struct
/// IMPORTANT: This is the canonical layout. Kernel must match this `repr(C)`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ZeroStateBootInfo {
    pub magic: u64,          // e.g. 0x4E4F4E4F_53424F4Fu64 ("NONOSBOO")
    pub abi_version: u16,    // ABI version
    pub hdr_size: u16,       // size_of::<ZeroStateBootInfo>()
    pub boot_flags: u32,     // bitfield (see boot_flags)

    pub capsule_base: u64,   // physical address of kernel capsule
    pub capsule_size: u64,   // bytes
    pub capsule_hash: [u8; 32],

    pub memory_start: u64,   // optional metadata
    pub memory_size: u64,

    pub entropy: [u8; 32],
    pub rtc_utc: [u8; 8],
    pub reserved: [u8; 8],   // keep for future

    // -------- Framebuffer / GOP (UEFI Graphics Output) --------
    pub fb_base_phys: u64,   // physical base of linear framebuffer
    pub fb_size: u64,        // total bytes of FB mapping
    pub fb_pitch: u32,       // bytes per scanline
    pub fb_width: u32,       // pixels
    pub fb_height: u32,      // pixels
    pub fb_bpp: u16,         // bits per pixel (typically 32)
    pub fb_format: u16,      // fb_format::* code
}

impl ZeroStateBootInfo {
    /// Initialize a blank structure with required header fields.
    pub fn new(magic: u64, boot_flags: u32) -> Self {
        ZeroStateBootInfo {
            magic,
            abi_version: ABI_VERSION,
            hdr_size: core::mem::size_of::<ZeroStateBootInfo>() as u16,
            boot_flags,

            capsule_base: 0,
            capsule_size: 0,
            capsule_hash: [0u8; 32],

            memory_start: 0,
            memory_size: 0,

            entropy: [0u8; 32],
            rtc_utc: [0u8; 8],
            reserved: [0u8; 8],

            fb_base_phys: 0,
            fb_size: 0,
            fb_pitch: 0,
            fb_width: 0,
            fb_height: 0,
            fb_bpp: 0,
            fb_format: fb_format::UNKNOWN,
        }
    }

    /// Set capsule location/size/hash
    pub fn set_capsule(&mut self, base_phys: u64, size: u64, hash32: [u8; 32]) {
        self.capsule_base = base_phys;
        self.capsule_size = size;
        self.capsule_hash = hash32;
    }

    /// Set memory region summary
    pub fn set_memory(&mut self, start: u64, size: u64) {
        self.memory_start = start;
        self.memory_size = size;
    }

    /// Set entropy and RTC (UTC) timestamp (little-endian)
    pub fn set_entropy_rtc(&mut self, entropy: [u8; 32], rtc_utc: [u8; 8]) {
        self.entropy = entropy;
        self.rtc_utc = rtc_utc;
    }

    /// Fill UEFI GOP framebuffer information
    pub fn set_framebuffer(
        &mut self,
        base_phys: u64,
        size: u64,
        pitch: u32,
        width: u32,
        height: u32,
        bpp: u16,
        fmt_code: u16,
    ) {
        self.fb_base_phys = base_phys;
        self.fb_size = size;
        self.fb_pitch = pitch;
        self.fb_width = width;
        self.fb_height = height;
        self.fb_bpp = bpp;
        self.fb_format = fmt_code;
    }
}

/// Helper function to build a ZeroStateBootInfo
pub fn build_bootinfo(
    magic: u64,
    capsule_base: u64,
    capsule_size: u64,
    capsule_hash: [u8; 32],
    memory_start: u64,
    memory_size: u64,
    entropy: [u8; 32],
    rtc_utc: [u8; 8],
    boot_flags: u32,
) -> ZeroStateBootInfo {
    let mut info = ZeroStateBootInfo::new(magic, boot_flags);
    info.set_capsule(capsule_base, capsule_size, capsule_hash);
    info.set_memory(memory_start, memory_size);
    info.set_entropy_rtc(entropy, rtc_utc);
    info
}

