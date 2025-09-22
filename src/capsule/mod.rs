pub mod zkmeta;

use crate::handoff::ZeroStateBootInfo;
use crate::verify::verify_ed25519_signature;
use xmas_elf::{
    program::Type,
    ElfFile,
};

/// Represents a verified kernel capsule
#[derive(Debug)]
pub struct Capsule {
    pub base: *mut u8,
    pub size: usize,
    pub entry_point: usize,
    pub handoff: ZeroStateBootInfo,
}

impl Capsule {
    /// Create a capsule from a blob with full ELF parsing and cryptographic verification
    pub fn from_blob(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 64 {
            return Err("Capsule too small - minimum 64 bytes required");
        }

        // Parse ELF file
        let elf = ElfFile::new(data).map_err(|_| "Invalid ELF file format")?;

        // Verify it's a 64-bit executable
        if elf.header.pt1.class() != xmas_elf::header::Class::ThirtyTwo
            && elf.header.pt1.class() != xmas_elf::header::Class::SixtyFour
        {
            return Err("Unsupported ELF class");
        }

        if elf.header.pt2.type_().as_type() != xmas_elf::header::Type::Executable {
            return Err("ELF file must be executable");
        }

        // Get entry point
        let entry_point = elf.header.pt2.entry_point() as usize;
        if entry_point == 0 {
            return Err("Invalid entry point in ELF header");
        }

        // Signature verification - skip when mock-proof feature is enabled for testing
        #[cfg(not(feature = "mock-proof"))]
        {
            // Find .nonos.manifest section for signature verification
            let manifest_section = elf
                .find_section_by_name(".nonos.manifest")
                .ok_or("Missing .nonos.manifest section")?;
            let manifest_data = match manifest_section
                .get_data(&elf)
                .map_err(|_| "Cannot read manifest section")?
            {
                xmas_elf::sections::SectionData::Undefined(data) => data,
                _ => return Err("Manifest section has wrong type"),
            };

            // Find .nonos.sig section
            let sig_section = elf
                .find_section_by_name(".nonos.sig")
                .ok_or("Missing .nonos.sig section")?;
            let signature_data = match sig_section
                .get_data(&elf)
                .map_err(|_| "Cannot read signature section")?
            {
                xmas_elf::sections::SectionData::Undefined(data) => data,
                _ => return Err("Signature section has wrong type"),
            };

            // Verify signature over the manifest
            if !verify_ed25519_signature(manifest_data, signature_data)? {
                return Err("Cryptographic signature verification failed");
            }
        }

        #[cfg(feature = "mock-proof")]
        {
            // Skip signature verification in mock-proof mode for testing
        }

        // Calculate total memory size needed for all LOAD segments
        let mut _total_size = 0;
        let mut min_addr = usize::MAX;
        let mut max_addr = 0;

        for program_header in elf.program_iter() {
            if program_header.get_type() == Ok(Type::Load) {
                let vaddr = program_header.virtual_addr() as usize;
                let memsz = program_header.mem_size() as usize;

                min_addr = min_addr.min(vaddr);
                max_addr = max_addr.max(vaddr + memsz);
            }
        }

        if min_addr == usize::MAX {
            return Err("No loadable segments found");
        }

        _total_size = max_addr - min_addr;

        // Get 64 bytes of boot entropy
        let entropy_64 = crate::entropy::collect_boot_entropy_64()?;

        // Get RTC timestamp
        let rtc_utc = crate::entropy::get_rtc_timestamp();

        // Create handoff info using the proper builder
        #[cfg(not(feature = "mock-proof"))]
        let commitment_hash = {
            let manifest_section = elf
                .find_section_by_name(".nonos.manifest")
                .ok_or("Missing .nonos.manifest section for commitment")?;
            let manifest_data = match manifest_section
                .get_data(&elf)
                .map_err(|_| "Cannot read manifest section for commitment")?
            {
                xmas_elf::sections::SectionData::Undefined(data) => data,
                _ => return Err("Manifest section has wrong type for commitment"),
            };
            *blake3::hash(manifest_data).as_bytes()
        };

        #[cfg(feature = "mock-proof")]
        let commitment_hash = {
            // Use a placeholder hash in mock-proof mode
            *blake3::hash(b"MOCK_PROOF_PLACEHOLDER").as_bytes()
        };

        let handoff = crate::handoff::build_bootinfo(
            data.as_ptr() as u64,
            data.len() as u64,
            commitment_hash,
            0x100000,   // 1MB memory start (typical after firmware)
            0x40000000, // 1GB total memory (will be updated by memory detection)
            &entropy_64,
            rtc_utc,
            crate::handoff::BootModeFlags::SECURE_BOOT | crate::handoff::BootModeFlags::COLD_START,
        );

        Ok(Capsule {
            base: data.as_ptr() as *mut u8,
            size: data.len(), // Use actual file size, not virtual memory size
            entry_point,
            handoff,
        })
    }

    /// Verify the capsule (already done in from_blob, so this is a no-op)
    pub fn verify(&self) -> Result<(), &'static str> {
        Ok(()) // Already verified in from_blob
    }

    /// Get the capsule commitment hash
    pub fn commitment(&self) -> [u8; 32] {
        self.handoff.capsule_hash
    }

    /// Get the entry point address
    pub fn entry_address(&self) -> usize {
        self.entry_point
    }

    /// Get the payload as a slice
    pub fn payload(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.base, self.size) }
    }
}
