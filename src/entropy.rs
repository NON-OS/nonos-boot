//! NØNOS Preboot Entropy Generator — Capsule Seeder
//! - EFI RNG 
//! - RDSEED/RDRAND
//! - TSC jitter with lfence serialization
//! - RTC time salt
//! - BLAKE3 domain-separated KDF to 64 bytes

#![allow(dead_code)]

use uefi::table::boot::BootServices;
use uefi_services::system_table;
use crate::handoff::ZeroStateBootInfo;

use blake3; // add in Cargo.toml

/* --------------------- UEFI getrandom backend --------------------- */

/// Custom getrandom implementation for UEFI environment.
/// This provides the getrandom backend that blake3 and other crypto libs need.
#[no_mangle]
pub extern "C" fn getrandom(buf: *mut u8, len: usize, _flags: u32) -> isize {
    if buf.is_null() || len == 0 {
        return -1;
    }
    
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    
    // Use the advanced entropy collection system
    let st = unsafe { system_table().as_ref() };
    let bt = st.boot_services();
    let entropy_pool = collect_boot_entropy(bt);
    
    // Expand entropy with BLAKE3 XOF
    let mut hasher = blake3::Hasher::new();
    hasher.update(&entropy_pool);
    hasher.finalize_xof().fill(slice);
    
    len as isize
}

/* --------------------- Constants --------------------- */

/// Domain separation labels
const DS_ENTROPY_ACCUM: &str = "NONOS:BOOT:ENTROPY:ACCUM";
const DS_ENTROPY_OUTPUT: &str = "NONOS:BOOT:ENTROPY:OUTPUT";

/* --------------------- Public API --------------------- */

/// Collect 64 bytes of boot entropy - public API
pub fn collect_boot_entropy_64() -> Result<[u8; 64], &'static str> {
    let st = unsafe { system_table().as_ref() };
    let bt = st.boot_services();
    Ok(collect_boot_entropy(bt))
}

/// Get RTC timestamp as 8-byte array (for compatibility with loader.rs)
pub fn get_rtc_timestamp() -> [u8; 8] {
    let st = unsafe { system_table().as_ref() };
    if let Ok(rtc) = st.runtime_services().get_time() {
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&(rtc.year() as u16).to_le_bytes());
        buf[2] = rtc.month();
        buf[3] = rtc.day();
        buf[4] = rtc.hour();
        buf[5] = rtc.minute();
        buf[6] = rtc.second();
        buf[7] = (rtc.nanosecond() / 1_000_000) as u8; // milliseconds
        buf
    } else {
        rdtsc_serialized().to_le_bytes()
    }
}

/// Get RTC entropy as 16-byte array (richer than get_rtc_timestamp)
pub fn collect_rtc() -> [u8; 16] {
    let st = unsafe { system_table().as_ref() };
    if let Ok(rtc) = st.runtime_services().get_time() {
        let mut rtc_buf = [0u8; 16];
        rtc_buf[0..4].copy_from_slice(&(rtc.year() as u32).to_le_bytes());
        rtc_buf[4] = rtc.month();
        rtc_buf[5] = rtc.day();
        rtc_buf[6] = rtc.hour();
        rtc_buf[7] = rtc.minute();
        rtc_buf[8] = rtc.second();
        rtc_buf[9..13].copy_from_slice(&(rtc.nanosecond() as u32).to_le_bytes());
        rtc_buf[13] = match rtc.time_zone() { Some(tz) => tz as u8, None => 0 };
        rtc_buf[14] = match rtc.daylight() {
            uefi::table::runtime::Daylight::ADJUST_DAYLIGHT => 1,
            _ => 0,
        };
        rtc_buf[15] = 0;
        rtc_buf
    } else {
        rdtsc_serialized().to_le_bytes().repeat(2).try_into().unwrap()
    }
}

/// Populate entropy field in `ZeroStateBootInfo` capsule struct
pub fn seed_entropy(info: &mut ZeroStateBootInfo, bs: &BootServices) {
    let mut collected = collect_boot_entropy(bs);
    info.entropy.copy_from_slice(&collected);
    scrub(&mut collected);
}

/* --------------------- Entropy Collection --------------------- */

pub fn collect_boot_entropy(bs: &BootServices) -> [u8; 64] {
    let mut h = blake3::Hasher::new_derive_key(DS_ENTROPY_ACCUM);

    // 1) EFI RNG (if feature enabled)
    #[cfg(feature = "efi-rng")]
    if let Ok(handle) = bs.locate_protocol::<uefi::proto::rng::Rng>() {
        let rng = unsafe { &mut *handle.get() };
        let mut buf = [0u8; 64];
        if rng.get_rng(None, &mut buf).is_ok() {
            h.update(&buf);
            scrub(&mut buf);
        }
    }

    // 2) RDSEED / RDRAND
    let mut hw = [0u8; 64];
    let mut off = 0usize;
    for _ in 0..32 {
        if let Some(x) = rdseed64() {
            hw[off % 64] ^= x as u8;
            hw[(off + 7) % 64] ^= (x >> 8) as u8;
            hw[(off + 13) % 64] ^= (x >> 16) as u8;
            off = off.wrapping_add(1);
        } else if let Some(x) = rdrand64() {
            hw[off % 64] ^= x as u8;
            hw[(off + 3) % 64] ^= (x >> 24) as u8;
            hw[(off + 11) % 64] ^= (x >> 40) as u8;
            off = off.wrapping_add(1);
        }
    }
    h.update(&hw);
    scrub(&mut hw);

    // 3) TSC jitter with lfence serialization + micro stalls
    for round in 0..256u32 {
        let t1 = rdtsc_serialized();
        bs.stall(23 + ((round as usize * 7) % 17) as usize);
        let t2 = rdtsc_serialized();
        let delta = t2.wrapping_sub(t1);

        let mut frame = [0u8; 24];
        frame[0..8].copy_from_slice(&t1.to_le_bytes());
        frame[8..16].copy_from_slice(&t2.to_le_bytes());
        frame[16..20].copy_from_slice(&round.to_le_bytes());
        frame[20..24].copy_from_slice(&(delta.rotate_left((round % 63) + 1)).to_le_bytes()[0..4]);
        h.update(&frame);
    }

    // 4) RTC salt
    h.update(&collect_rtc());

    // Finalize to 64 bytes with distinct output key
    let mut out = [0u8; 64];
    blake3::Hasher::new_derive_key(DS_ENTROPY_OUTPUT)
        .update(h.finalize().as_bytes())
        .finalize_xof()
        .fill(&mut out);

    // Minimal health check
    if is_weak_entropy(&out) {
        let rescue = rdtsc_serialized().to_le_bytes();
        let mut hh = blake3::Hasher::new();
        hh.update(&out);
        hh.update(&rescue);
        out.copy_from_slice(hh.finalize().as_bytes());
    }

    out
}

/* --------------------- Helpers --------------------- */

#[inline(always)]
fn scrub(b: &mut [u8]) {
    for x in b {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        *x = 0;
    }
}

#[inline(always)]
fn is_weak_entropy(buf: &[u8; 64]) -> bool {
    let all_zero = buf.iter().all(|&b| b == 0);
    if all_zero {
        return true;
    }
    let half = &buf[0..32];
    half == &buf[32..64]
}

#[inline(always)]
fn rdtsc_serialized() -> u64 {
    unsafe {
        let mut hi: u32;
        let mut lo: u32;
        core::arch::asm!(
            "lfence",
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}

/// Try RDSEED (returns Some(u64) on success)
#[inline(always)]
fn rdseed64() -> Option<u64> {
    #[cfg(any(target_arch = "x86_64"))]
    unsafe {
        let mut x: u64 = 0;
        let ok = core::arch::x86_64::_rdseed64_step(&mut x);
        if ok == 1 { Some(x) } else { None }
    }
    #[cfg(not(any(target_arch = "x86_64")))]
    { None }
}

/// Try RDRAND (returns Some(u64) on success)
#[inline(always)]
fn rdrand64() -> Option<u64> {
    #[cfg(any(target_arch = "x86_64"))]
    unsafe {
        let mut x: u64;
        let ok: u8;
        core::arch::asm!(
            "rdrand {x}",
            "setc   {ok}",
            x = out(reg) x,
            ok = out(reg_byte) ok,
            options(nostack, nomem)
        );
        if ok != 0 { Some(x) } else { None }
    }
    #[cfg(not(any(target_arch = "x86_64")))]
    { None }
}
