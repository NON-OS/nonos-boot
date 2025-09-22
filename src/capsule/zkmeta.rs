//! Simple ZK metadata helper for capsule verification

use crate::verify::CapsuleMetadata;

/// Check if capsule requires ZK verification based on flags
pub fn requires_zk(meta: &CapsuleMetadata) -> bool {
    const FLAG_ZK_REQUIRED: u8 = 1 << 0;
    (meta.flags & FLAG_ZK_REQUIRED) != 0
}
