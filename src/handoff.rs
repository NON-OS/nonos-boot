#![allow(dead_code)]

extern crate alloc;

use core::mem::size_of;

// Expose current ABI version
pub const ABI_VERSION: u16 = 2;

// Framebuffer pixel-format codes shared with the kernel
pub mod fb_format {
    pub const RGB: u16     = 0;
    pub const BGR: u16     = 1;
    pub const BITMASK: u16 = 2;
    pub const BLTONLY: u16 = 3;
    pub const UNKNOWN: u16 = 0xFFFF;
}

// Bitflags compatible with earlier callers
bitflags::bitflags! {
    pub struct BootModeFlags: u32 {
        const NONE        = 0;
        const SECURE_BOOT = 1 << 0;
        const MEASURED    = 1 << 1;
        const COLD_START  = 1 << 2;
        const WARM_START  = 1 << 3;
        const NET_BOOT    = 1 << 4;
        const PXE         = 1 << 5;
        const HTTP        = 1 << 6;
        const LEGACY_VGA  = 1 << 7;
        const UEFI_GOP    = 1 << 8;
    }
}

/// Bootloader → Kernel handoff (ABI v2 with GOP/Framebuffer)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ZeroStateBootInfo {
    // v1 fields
    pub magic: u64,
    pub abi_version: u16,
    pub hdr_size: u16,
    pub boot_flags: u32,

    pub capsule_base: u64,
    pub capsule_size: u64,
    pub capsule_hash: [u8; 32],

    pub memory_start: u64,
    pub memory_size: u64,

    pub entropy: [u8; 32],
    pub rtc_utc: [u8; 8],
    pub reserved: [u8; 8],

    // v2 fields (GOP / linear framebuffer)
    pub fb_base:   u64,  // physical address
    pub fb_size:   u64,  // bytes
    pub fb_pitch:  u32,  // bytes per scanline
    pub fb_width:  u32,  // px
    pub fb_height: u32,  // px
    pub fb_bpp:    u16,  // bits per pixel (usually 32)
    pub fb_format: u16,  // fb_format::* codes
}

impl ZeroStateBootInfo {
    pub const fn new() -> Self {
        Self {
            magic: 0x4E304E2D4F535A53, // "N0N-OSZS" arbitrary magic; replace if you have a canonical one
            abi_version: ABI_VERSION,
            hdr_size: size_of::<ZeroStateBootInfo>() as u16,
            boot_flags: BootModeFlags::NONE.bits(),

            capsule_base: 0,
            capsule_size: 0,
            capsule_hash: [0u8; 32],

            memory_start: 0,
            memory_size: 0,

            entropy: [0u8; 32],
            rtc_utc: [0u8; 8],
            reserved: [0u8; 8],

            fb_base: 0,
            fb_size: 0,
            fb_pitch: 0,
            fb_width: 0,
            fb_height: 0,
            fb_bpp: 0,
            fb_format: fb_format::UNKNOWN,
        }
    }

    #[inline]
    pub fn set_framebuffer(
        &mut self,
        base: u64,
        size: u64,
        pitch_bytes: u32,
        width: u32,
        height: u32,
        bpp: u16,
        format: u16,
    ) {
        self.fb_base   = base;
        self.fb_size   = size;
        self.fb_pitch  = pitch_bytes;
        self.fb_width  = width;
        self.fb_height = height;
        self.fb_bpp    = bpp;
        self.fb_format = format;

        // Mark that UEFI GOP is available
        self.boot_flags |= BootModeFlags::UEFI_GOP.bits();
    }
}

/// ------------------------------------------------------------------------------------
/// Legacy shim: callers in loader.rs/capsule/mod.rs expect `build_bootinfo(...)`.
/// This constructor keeps their code compiling without touching call sites.
/// If your call sites need a different signature, paste the compile error and
/// we’ll add an overload shim here.
/// ------------------------------------------------------------------------------------
#[allow(clippy::too_many_arguments)]
// ---- Compatibility helpers so older callsites keep compiling ----

pub trait EntropyLike {
    fn to32(self) -> [u8; 32];
}

impl EntropyLike for [u8; 32] {
    #[inline] fn to32(self) -> [u8; 32] { self }
}

impl<'a> EntropyLike for &'a [u8; 64] {
    #[inline] fn to32(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self[..32]); // truncate
        out
    }
}

pub trait IntoBootFlags {
    fn to_flags(self) -> BootModeFlags;
}

impl IntoBootFlags for BootModeFlags {
    #[inline] fn to_flags(self) -> BootModeFlags { self }
}

impl IntoBootFlags for u32 {
    #[inline] fn to_flags(self) -> BootModeFlags {
        BootModeFlags::from_bits_truncate(self)
    }
}

/// Generic shim that accepts both legacy and new call patterns.
/// Works with:
/// - entropy: [u8;32]  OR  & [u8;64]
/// - boot_flags: BootModeFlags  OR  u32
#[allow(clippy::too_many_arguments)]
pub fn build_bootinfo<E, F>(
    capsule_base: u64,
    capsule_size: u64,
    capsule_hash: [u8; 32],
    memory_start: u64,
    memory_size: u64,
    entropy: E,
    rtc_utc: [u8; 8],
    boot_flags: F,
) -> ZeroStateBootInfo
where
    E: EntropyLike,
    F: IntoBootFlags,
{
    let mut bi = ZeroStateBootInfo::new();
    bi.capsule_base = capsule_base;
    bi.capsule_size = capsule_size;
    bi.capsule_hash = capsule_hash;
    bi.memory_start = memory_start;
    bi.memory_size  = memory_size;
    bi.entropy      = entropy.to32();
    bi.rtc_utc      = rtc_utc;
    bi.boot_flags   = boot_flags.to_flags().bits();
    bi
}

