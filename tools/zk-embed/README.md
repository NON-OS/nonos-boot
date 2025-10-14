# zk-embed (host-side)

**Author:** eK (team@nonos.systems) — https://nonos.systems   unite, we win.
**License:** AGPL-3.0

A small, precise host tool that derives your PROGRAM_HASH and normalizes your Groth16 verifying key (VK) into canonical compressed bytes for embedding in the NØNOS bootloader.

---

## Contents

- Overview
- Diagram
- Installation
- Quick start
- Inputs and outputs
- End-to-end example
- Embedding in the bootloader
- Security notes
- Troubleshooting
- FAQ

---

## Overview

zk-embed does three things:

1. Accepts your program/circuit ID (string, hex, or raw file)
2. Derives a 32-byte PROGRAM_HASH using BLAKE3 with a domain separator
3. Loads your Groth16 VK (BLS12‑381), validates it, and re‑serializes to arkworks canonical compressed bytes

It then prints ready-to-paste Rust consts and a mapping snippet for the bootloader’s ZK verifier registry.

---

## Diagram

┌─────────────────────────┐       ┌─────────────────────────────────┐
│ Program/Circuit ID      │       │ Verifying Key bytes             │
│ (str │ hex │ file)      │       │ (arkworks compressed/uncomp.)   │
└────────────┬────────────┘       └─────────────┬───────────────────┘
             │                                  │
             │ BLAKE3::derive_key               │
             │ "NONOS:ZK:PROGRAM:v1"            │
             ▼                                  ▼
    ┌─────────────────┐                ┌─────────────────────┐
    │ PROGRAM_HASH    │                │ Deserialize VK      │
    │ [32 bytes]      │                │ (try compressed     │
    └─────────┬───────┘                │  else uncompressed) │
              │                        └──────────┬──────────┘
              │                                   │
              │                                   │ reserialize to
              │                                   │ canonical compressed
              │                                   ▼
              └─────────────────┬─────────────────────────────────────┐
                                │                                     │
                                ▼                                     │
                    ┌──────────────────────────────────────────────────┴──┐
                    │ Rust consts + registry mapping                      │
                    │  • PROGRAM_HASH_<PREFIX>                            │
                    │  • VK_<PREFIX>_BLS12_381_GROTH16                    │
                    │  • program_vk_lookup() snippet                      │
                    └─────────────────────────┬───────────────────────────┘
                                              │
                                              ▼
                            📁 Paste into boot/src/zk/zkverify.rs and build

---

## Installation

Assuming this repository includes the tool under `tools/zk-embed/`:

```bash
# from repo root
cargo build --release -p zk-embed
```

Or run directly:

```bash
cargo run --release -p zk-embed -- --help
```

---

## Quick start

```bash
# Derive PROGRAM_HASH and normalize VK. Prints a paste-ready snippet.
cargo run --release -p zk-embed -- \
  --program-id-str "zkmod-attestation-program-v1" \
  --vk path/to/verifying_key.bin \
  --const-prefix ATTEST_V1

# Optional: write snippet to a file
cargo run --release -p zk-embed -- \
  --program-id-hex 6b6579... \
  --vk vk.bin \
  --out zk_embed_out.rs
```

---

## Inputs and outputs

- Program ID (choose one):
  - `--program-id-str <utf8>`
  - `--program-id-hex <hex-without-0x>`
  - `--program-id-file <path>` (raw bytes)

- Verifying Key:
  - `--vk <path>` — arkworks CanonicalSerialize (compressed or uncompressed).  
    The tool validates and re-serializes to canonical compressed bytes.

- Domain separator (optional):
  - `--ds-program <string>` (default: `NONOS:ZK:PROGRAM:v1`)

- Const prefix (optional):
  - `--const-prefix <NAME>` to tag emitted consts (e.g., `ATTEST_V1`)

- Output target (optional):
  - `--out <path>` to write the generated snippet to a file

What it prints:

- `PROGRAM_HASH_<PREFIX>: [u8; 32]`
- `VK_<PREFIX>_BLS12_381_GROTH16: &[u8]`
- A `program_vk_lookup()` mapping snippet ready to paste into the bootloader

---

## End-to-end example

### 1. Generate a snippet

```bash
cargo run --release -p zk-embed -- \
  --program-id-str "zkmod-attestation-program-v1" \
  --vk ./vk_attestation.bin \
  --const-prefix ATTEST_V1 \
  --out zk_embed_out.rs
```

### 2. Inspect the output file

Inspect the output file `zk_embed_out.rs`:

- It contains:
  - A 32-byte `PROGRAM_HASH_ATTEST_V1`
  - A byte slice `VK_ATTEST_V1_BLS12_381_GROTH16` with canonical compressed VK bytes
  - A mapping function that ties the program hash to the VK slice

### 3. Paste into bootloader

Paste those consts and the mapping into your bootloader at:

```
src/zk/zkverify.rs
```

---

## Embedding in the bootloader

- Paste the generated consts and mapping into the VK registry section of `src/zk/zkverify.rs`.
- Build the bootloader with ZK verification enabled and VK provisioning asserted:

```bash
cargo build --release --features zk-groth16,zk-vk-provisioned
```

Feature policy:

- `zk-groth16`: turns on Groth16 verification (arkworks)
- `zk-vk-provisioned`: compile-time guard stating VKs are embedded

---

## Security notes

- PROGRAM_HASH is derived via `blake3::derive_key` with the domain separator `NONOS:ZK:PROGRAM:v1`.  
  Keep your program ID stable. The prover and the bootloader must match exactly.

- VK provenance matters. Treat verifying keys as part of your trust root:
  - Document the ceremony or generation process.
  - Track versions and revoke/rotate as needed.
  - Store and review VK bytes under code review.

- The tool validates your VK by deserializing with arkworks and emits canonical compressed bytes.  
  That canonical form is what the bootloader embeds and verifies against at runtime.

---

## Troubleshooting

- “program id provided more than once”  
  Provide only one of: `--program-id-str`, `--program-id-hex`, or `--program-id-file`.

- “vk deserialize failed (neither compressed nor uncompressed)”  
  Ensure your VK file is arkworks CanonicalSerialize-encoded. If you have a different format, convert it with a small arkworks-based converter.

- “verifying key file is empty”  
  Check the path and contents of `--vk`.

- Boot build fails with compile_error! about provisioning  
  Add your VK and PROGRAM_HASH mapping to `src/zk/zkverify.rs` and build with `--features zk-groth16,zk-vk-provisioned`.

---

## FAQ

- Which curve and proof system does this target?  
  Groth16 over BLS12‑381 via arkworks.

- What is “canonical compressed”?  
  Arkworks’ canonical, compressed serialization of elliptic curve points (G1/G2). This is what the runtime verifier expects.

- Can the domain separator be changed?  
  Yes, via `--ds-program`, but only do so if your prover side does the same. Keep it consistent across your stack.

- Does this tool ship in firmware?  
  No. It is a host-side helper used during provisioning and release engineering.

---

---

**Community:** team@nonos.systems • https://nonos.systems

