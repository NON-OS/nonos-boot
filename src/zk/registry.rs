//! Verifying key registry (program hash -> VK bytes).
//!
//! ***EVERYONE***       
//! Replace the placeholder entry with PROGRAM_HASH_* and VK_* constants
//! produced by tools/zk-embed before enabling `zk-vk-provisioned`.***
//! ***Will do a proper tutorial on Youtube***


use crate::zk::zkverify::ct_eq32;

#[cfg(feature = "zk-groth16")]
// Placeholder constants (MUST be replaced).
pub const PROGRAM_HASH_PLACEHOLDER: [u8; 32] = [0u8; 32];
#[cfg(feature = "zk-groth16")]
pub const VK_PLACEHOLDER_BLS12_381_GROTH16: &[u8] = &[];

#[cfg(feature = "zk-groth16")]
static ENTRIES: &[(&[u8; 32], &[u8])] = &[
    // Example pattern after replacement:
    // (&PROGRAM_HASH_ATTEST_V1, VK_ATTEST_V1_BLS12_381_GROTH16),
    (&PROGRAM_HASH_PLACEHOLDER, VK_PLACEHOLDER_BLS12_381_GROTH16),
];

#[cfg(feature = "zk-groth16")]
pub fn lookup(program_hash: &[u8; 32]) -> Option<&'static [u8]> {
    let mut result: Option<&'static [u8]> = None;
    for (h, vk) in ENTRIES {
        let eq = ct_eq32(h, program_hash);
        // Accumulate without early return
        if eq {
            result = Some(*vk);
        }
    }
    result
}

#[cfg(all(feature = "zk-groth16", feature = "zk-vk-provisioned"))]
const _: () = {
    // Force replace placeholder before provisioning flag passes CI.
    if VK_PLACEHOLDER_BLS12_381_GROTH16.len() == 0 {
        panic!("zk-vk-provisioned set but placeholder VK still present; embed real VK constants first.");
    }
};
