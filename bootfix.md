
# Run NØNOS Bootloader on QEMU (macOS) — with a Tiny Test Kernel

This documents the exact steps we used to fix Phase 6 and boot cleanly end-to-end on macOS using Homebrew LLVM/LLD and QEMU.

---

## 0) Prerequisites

```bash
# Tools
brew install qemu llvm lld ripgrep

# (optional) keep these on your PATH for future shells
echo 'export PATH="$(brew --prefix llvm)/bin:$(brew --prefix lld)/bin:$PATH"' >> ~/.zshrc
export PATH="$(brew --prefix llvm)/bin:$(brew --prefix lld)/bin:$PATH"
```

> Why LLVM/LLD? Apple’s `ld` doesn’t accept our flags, so we link with `ld.lld`.

---

## 1) Build a Minimal ELF “Kernel”

Create a linker script (load at 1 MiB), and a tiny entry that halts:

```bash
cat > kernel.ld <<'EOF'
ENTRY(_start)
SECTIONS {
  . = 0x100000;
  .text   : { *(.text*) }
  .rodata : { *(.rodata*) }
  .data   : { *(.data*) }
  .bss    : { *(.bss*) *(COMMON) }
}
EOF

cat > kernel.c <<'EOF'
__attribute__((noreturn))
void _start(void) {
    for(;;) { __asm__ __volatile__("hlt"); }
}
EOF
```

Compile & link with Homebrew toolchain:

```bash
"$(brew --prefix llvm)/bin/clang" -target x86_64-unknown-none \
  -ffreestanding -fno-stack-protector -fno-pic -fno-pie -nostdlib \
  -c kernel.c -o kernel.o

"$(brew --prefix lld)/bin/ld.lld" -nostdlib -static -no-pie -z max-page-size=0x1000 \
  -T kernel.ld -o kernel.elf kernel.o
```

---

## 2) Build the Bootloader & Stage the ESP

```bash
# Build bootloader (development profile with mock ZK)
cargo build --target x86_64-unknown-uefi --features mock-proof

# Create ESP layout and place the bootloader as BOOTX64.EFI
mkdir -p esp/EFI/Boot
cp target/x86_64-unknown-uefi/debug/nonos_boot.efi esp/EFI/Boot/BootX64.efi

# Put the ELF kernel where the loader expects it
cp kernel.elf esp/nonos_kernel.efi
```

---

## 3) Prepare OVMF (UEFI firmware)

Homebrew’s OVMF files ship with QEMU:

```bash
BREW_QEMU_DIR="$(brew --prefix qemu)/share/qemu"
VARS="$PWD/OVMF_VARS_rw.fd"

# Create a writable VARS file matching code.fd size (one-time)
[ -f "$VARS" ] || qemu-img create -f raw "$VARS" \
  "$(stat -f%z "$BREW_QEMU_DIR/edk2-x86_64-code.fd")"
```

---

## 4) Run QEMU

```bash
qemu-system-x86_64 \
  -machine q35,accel=hvf -cpu host -m 1024 \
  -drive if=pflash,format=raw,readonly=on,file="$BREW_QEMU_DIR/edk2-x86_64-code.fd" \
  -drive if=pflash,format=raw,file="$VARS" \
  -drive format=raw,file=fat:rw:esp \
  -serial stdio -monitor none -no-reboot
```

> Optional extra debug:
> `-debugcon stdio -global isa-debugcon.iobase=0xe9` and write to port `0xE9` in your kernel.

---

## 5) Expected Output

You should see Phase 6 succeed:

```
[INFO] Attempting PXE kernel load...
[WARN] PXE boot failed, trying local...
[SUCCESS] Kernel capsule loaded and verified
[WARN] Advanced verification failed, using standard verification   # expected w/o signature
[SUCCESS] Entry point validated
...
Transferring Control to NØNOS Kernel
```

If you supply a signed kernel (our dev format is payload + 32-byte pubkey + 64-byte Ed25519 signature), you’ll get:

```
[SUCCESS] Advanced kernel signature verification successful
```

---

## 6) What Went Wrong Before (Phase 6) & How This Fixes It

* **Cause:** there was **no `esp/nonos_kernel.efi`**, and PXE/HTTP paths are stubs → nothing to boot → Phase 6 failure and firmware reset.
* **Fix:** we built a valid **x86\_64 ELF** (`kernel.elf`), placed it at `esp/nonos_kernel.efi`, and used the correct OVMF paths with pflash. The loader parsed, validated, and jumped to it.

---

## 7) Troubleshooting

* **`ld.lld: command not found`**
  `brew install lld` and ensure PATH includes `$(brew --prefix lld)/bin`.

* **`Could not read directory esp`**
  Create it and stage the files exactly as shown above.

* **`Could not open edk2-x86_64-code.fd`**
  Use the Homebrew path: `$(brew --prefix qemu)/share/qemu/edk2-x86_64-code.fd`, and the **pflash** form shown (not `-bios`).

* **Instant reboot after Phase 6**
  Check `esp/nonos_kernel.efi` exists, is a **64-bit little-endian ELF**, and has a sane entry (we validate bounds).

