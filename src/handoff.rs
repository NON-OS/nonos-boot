#![allow(dead_code)]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FramebufferInfo {
    pub ptr: u64,         // physical address
    pub size: u64,        // bytes
    pub width: u32,
    pub height: u32,
    pub stride: u32,      // pixels per scanline
    pub pixel_format: u32 // mirror UEFI GOP pixel format enum
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MemoryMap {
    pub ptr: u64,       // pointer to UEFI memory map buffer
    pub entry_size: u32,
    pub entry_count: u32,
    pub desc_version: u32
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AcpiInfo {
    pub rsdp: u64 // physical address to RSDP
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SmbiosInfo {
    pub entry: u64 // physical address to SMBIOS entry point 
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Module {
    pub base: u64,
    pub size: u64,
    pub kind: u32,   // 0=kernel, 1=initrd, 2=ramfs, 3=other
    pub reserved: u32
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Modules {
    pub ptr: u64,       // pointer to [Module]
    pub count: u32,
    pub reserved: u32
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Timing {
    pub tsc_hz: u64,       // TSC frequency
    pub unix_epoch_ms: u64 // If RTC/NTP available
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Measurements {
    pub kernel_sha256: [u8; 32],
    pub kernel_sig_ok: u8, // 0/1
    pub secure_boot: u8,   // 0/1
    pub reserved: [u8; 6]
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RngSeed {
    pub seed32: [u8; 32] // mixed from UEFI RNG/RDSEED/TPM 
}

pub const HANDOFF_MAGIC: u32 = 0x4E_4F_4E_4F; // 'NONO' LE
pub const HANDOFF_VERSION: u16 = 1;

// flags: bit 0=W^X enabled, 1=NXE, 2=SMEP, 3=SMAP, 4=UMIP, 5=IDMAP_PRESERVED, etc.
pub mod flags {
    pub const WX: u64 = 1 << 0;
    pub const NXE: u64 = 1 << 1;
    pub const SMEP: u64 = 1 << 2;
    pub const SMAP: u64 = 1 << 3;
    pub const UMIP: u64 = 1 << 4;
    pub const IDMAP_PRESERVED: u64 = 1 << 5;
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BootHandoffV1 {
    pub magic: u32,        // HANDOFF_MAGIC
    pub version: u16,      // HANDOFF_VERSION
    pub size: u16,         // size of this struct
    pub flags: u64,        // see flags module above
    pub entry_point: u64,  // kernel entry VA or PA 
    pub fb: FramebufferInfo,
    pub mmap: MemoryMap,
    pub acpi: AcpiInfo,
    pub smbios: SmbiosInfo,
    pub modules: Modules,
    pub timing: Timing,
    pub meas: Measurements,
    pub rng: RngSeed,
    pub cmdline_ptr: u64,  // C-string
    pub reserved0: u64
}

impl BootHandoffV1 {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == HANDOFF_MAGIC
            && self.version == HANDOFF_VERSION
            && self.size as usize == core::mem::size_of::<Self>()
    }
}
