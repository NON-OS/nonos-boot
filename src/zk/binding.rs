//! Commitment binding policy.

use blake3;

pub const DS_COMMITMENT: &str = "NONOS:CAPSULE:COMMITMENT:v1";
pub const MAX_MANIFEST_SIZE: usize = 128 * 1024;

#[inline]
fn blake3_commit(bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DS_COMMITMENT);
    h.update(bytes);
    *h.finalize().as_bytes()
}

pub enum BindingInput<'a> {
    PublicInputs(&'a [u8]),
    Manifest(&'a [u8]),
}

#[cfg(feature = "zk-bind-manifest")]
pub fn select_binding<'a>(public_inputs: &'a [u8], manifest: Option<&'a [u8]>) -> Result<BindingInput<'a>, &'static str> {
    let m = manifest.ok_or("zk: manifest missing for binding")?;
    if m.len() > MAX_MANIFEST_SIZE {
        return Err("zk: manifest too large");
    }
    Ok(BindingInput::Manifest(m))
}

#[cfg(not(feature = "zk-bind-manifest"))]
pub fn select_binding<'a>(public_inputs: &'a [u8], _manifest: Option<&'a [u8]>) -> Result<BindingInput<'a>, &'static str> {
    Ok(BindingInput::PublicInputs(public_inputs))
}

pub fn compute_commit(binding: BindingInput<'_>) -> [u8; 32] {
    match binding {
        BindingInput::PublicInputs(pi) => blake3_commit(pi),
        BindingInput::Manifest(m) => blake3_commit(m),
    }
}
