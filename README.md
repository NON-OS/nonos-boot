

# NØNOS UEFI Bootloader

A minimal, experimental UEFI bootloader written in Rust for the NØNOS project.  
It can parse and verify a “capsule” (ELF + metadata), perform cryptographic checks (mockable), and hand off measured boot info to the kernel.

> ⚠️ **Status**: early, WIP. The `mock-proof` path skips true ZK verification and is for development only.

---

## Table of Contents

- [Features](#features)
- [Repo Layout](#repo-layout)
- [Requirements](#requirements)
- [Quick Start (macOS + Homebrew)](#quick-start-macos--homebrew)
- [Quick Start (Linux)](#quick-start-linux)
- [Make Targets](#make-targets)
- [Capsules & Verification](#capsules--verification)
- [Troubleshooting](#troubleshooting)
- [Roadmap / Known Gaps](#roadmap--known-gaps)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- UEFI x86_64 payload (`.efi`) built with `no_std`.
- ELF capsule parsing (via `xmas-elf`), entrypoint extraction.
- Capsule metadata parsing & bounds checking (`src/capsule/zkmeta.rs`).
- Signature plumbing:
  - Ed25519 verification via `ed25519-dalek` (trusted keyring stubbed for dev).
  - Optional compatibility/fallback paths for early bring-up.
- “Mock ZK proof” path (feature `mock-proof`) to develop the pipeline.
- Minimal logging façade (`src/log/logger.rs`) designed for UEFI console.
- Hand-off structure (`src/handoff.rs`) carrying capsule hash, entropy, RTC, flags.

---

## Repo Layout

```

├── .cargo/config.toml        # target config
├── Cargo.toml
├── Makefile                  # build helpers
├── build.rs
├── esp/                      # staged ESP (BootX64.efi lands here)
├── src/
│   ├── capsule/
│   │   ├── mod.rs           # Capsule wrapper
│   │   └── zkmeta.rs        # Canonical capsule metadata & helpers
│   ├── crypto/
│   │   ├── mod.rs
│   │   └── sig.rs           # Signature plumbing & verifier
│   ├── entropy.rs           # entropy/RTC helpers
│   ├── handoff.rs           # measured boot info struct + builder
│   ├── hardware.rs          # firmware/hw probes (WIP)
│   ├── loader.rs            # loading helpers (WIP)
│   ├── log/
│   │   ├── logger.rs        # logging façade for UEFI
│   │   └── mod.rs
│   ├── main.rs              # UEFI entry + boot pipeline
│   ├── multiboot.rs         # (WIP)
│   ├── network.rs           # (stub)
│   ├── security.rs          # (WIP)
│   ├── testing.rs           # (WIP)
│   ├── ui.rs                # (WIP)
│   ├── verify.rs            # capsule verify orchestration (ZK/static)
│   ├── zkmeta.rs            # (kept as module root re-export / shim)
│   └── zkverify.rs          # ZK verification interface (mock by default)
└── ...

````

---

## Requirements

- **Rust nightly** with the UEFI target:
  ```bash
  rustup target add x86_64-unknown-uefi

* **QEMU + OVMF** (edk2) firmware:

  * **macOS (Homebrew)**: `brew install qemu`

    * Firmware files are at: `$(brew --prefix qemu)/share/qemu/edk2-x86_64-code.fd`
      (and `edk2-x86_64-secure-code.fd` if you want Secure Boot experiments)
  * **Linux**: install `qemu-system-x86`, and OVMF package (e.g. `ovmf`), often at:

    * `/usr/share/OVMF/OVMF_CODE.fd` (code) and `/usr/share/OVMF/OVMF_VARS.fd` (vars)

---

## Quick Start (macOS + Homebrew)

1. **Build (dev + mock ZK)**

```bash
cargo build --target x86_64-unknown-uefi --features "default,mock-proof"
```

2. **Stage the ESP layout**

```bash
mkdir -p esp/EFI/Boot
cp target/x86_64-unknown-uefi/debug/nonos_boot.efi esp/EFI/Boot/BootX64.efi
```

3. **Create a writable OVMF vars file (first run only)**

```bash
BREW_QEMU_DIR="$(brew --prefix qemu)/share/qemu"
VARS="$PWD/OVMF_VARS_rw.fd"
SIZE="$(stat -f%z "$BREW_QEMU_DIR/edk2-x86_64-code.fd")"
qemu-img create -f raw "$VARS" "$SIZE"
```

4. **Run in QEMU**

```bash
ESP_DIR="$PWD/esp"
qemu-system-x86_64 \
  -machine q35,accel=hvf -cpu host -m 1024 \
  -drive if=pflash,format=raw,readonly=on,file="$BREW_QEMU_DIR/edk2-x86_64-code.fd" \
  -drive if=pflash,format=raw,file="$VARS" \
  -drive format=raw,file=fat:rw:$ESP_DIR \
  -serial stdio -monitor none
```

> If `hvf` isn’t available, replace `accel=hvf` with `accel=tcg`.

---

## Quick Start (Linux)

1. **Build**

```bash
rustup target add x86_64-unknown-uefi
cargo build --target x86_64-unknown-uefi --features "default,mock-proof"
```

2. **Stage ESP**

```bash
mkdir -p esp/EFI/Boot
cp target/x86_64-unknown-uefi/debug/nonos_boot.efi esp/EFI/Boot/BootX64.efi
```

3. **Run with system OVMF**

```bash
ESP_DIR="$PWD/esp"
qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host -m 1024 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=/usr/share/OVMF/OVMF_VARS.fd \
  -drive format=raw,file=fat:rw:$ESP_DIR \
  -serial stdio -monitor none
```

> Paths may vary by distro (try `/usr/share/OVMF` or `/usr/share/edk2/ovmf/`).

---

## Make Targets

The repo ships a helper `Makefile`:

* `make build` → dev build (`default,mock-proof`), stages `esp/EFI/Boot/BootX64.efi`
* `make release` → release build (`default,zk-snark,efi-rng,nonos-cet`), stages ESP
* `make production` → release + extra strip/UPX (if available)
* `make fast` → quick dev rebuild
* `make check` / `make clippy` / `make fmt`
* `make analyze` / `make disasm`
* `make clean` / `make distclean`
* `make dist` → package `target/dist`

> A dedicated `make run` target can be added; for now, use the **Quick Start** QEMU command above.

---

## Capsules & Verification

* **ELF parsing**: `src/capsule/mod.rs` reads the ELF, validates `PT_LOAD` segments, extracts entrypoint.
* **Metadata**: `src/capsule/zkmeta.rs` defines `CapsuleMeta` (packed on-wire), plus:

  * `parse_capsule_metadata`
  * `validate_capsule_layout` (bounds & non-overlap)
  * `extract_signature_and_payload`
  * `requires_zk`
* **Verification orchestration**: `src/verify.rs`

  * `verify_capsule`: chooses ZK vs static signature path
  * static path uses `verify_ed25519_signature`
  * ZK path builds a `ZkProof` and calls `zk::verify_proof` (mock)
* **Logging**: `src/log/logger.rs` provides `log_info/warn/error/debug` wrappers.
  Currently a minimal façade, designed to evolve into proper UEFI console logging.

**Features**

* `mock-proof`: skip real ZK, run with placeholder proof blob
* `zk-snark`: (placeholder switch for future verifier)
* `efi-rng`, `nonos-cet`: reserved features for platform integration

---

## Troubleshooting

* **“Could not read directory esp”**: ensure `esp/EFI/Boot/BootX64.efi` exists and `esp` is a directory.
* **“Could not open … edk2-x86\_64-code.fd”**: verify the firmware path; on macOS:

  ```bash
  ls "$(brew --prefix qemu)/share/qemu" | grep edk2
  ```
* **Stuck boot / blank screen**: try `-serial stdio -monitor none` to see logs; reduce features to `mock-proof`.
* **Warnings in build**: many are known (unused imports / WIP paths). You can apply safe auto-fixes:

  ```bash
  cargo fix --target x86_64-unknown-uefi --allow-dirty
  ```

  (review diffs before committing).

---

## Roadmap / Known Gaps

* Real ZK verification backend (Halo2/plonky2/etc.) wired to `zkverify.rs`.
* Proper key management & provisioning (remove dev-compatible “derived key” behaviors).
* Full UEFI console logger with color/severity and serial fallback.
* Robust loader/multiboot flow; memory map & paging setup hardening.
* Secure Boot (signed `.efi`) path and db/dbx tooling.
* Capsule builder/signing utility + tests.
* CI (build & run a headless smoke test via QEMU).

---

## Contributing

PRs are welcome. Please keep changes modular, gated behind features when appropriate, and include a brief design note in the PR description.


