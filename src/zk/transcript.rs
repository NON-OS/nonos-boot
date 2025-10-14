//! Lightweight transcript helper (future protocols).

use blake3;

#[derive(Clone)]
pub struct Transcript {
    h: blake3::Hasher,
}

impl Transcript {
    pub fn new(domain: &str) -> Self {
        let mut h = blake3::Hasher::new_derive_key(domain);
        h.update(domain.as_bytes());
        Transcript { h }
    }

    pub fn absorb(&mut self, label: &str, data: &[u8]) {
        self.h.update(&(label.len() as u32).to_le_bytes());
        self.h.update(label.as_bytes());
        self.h.update(&(data.len() as u32).to_le_bytes());
        self.h.update(data);
    }

    pub fn challenge32(&self, label: &str) -> [u8; 32] {
        let mut h2 = self.h.clone();
        h2.update(&(label.len() as u32).to_le_bytes());
        h2.update(label.as_bytes());
        *h2.finalize().as_bytes()
    }
}
