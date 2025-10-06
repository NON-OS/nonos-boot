# -------------------------------
# NONOS Boot Makefile (robust kernel copy)
# -------------------------------

# ---------- QEMU / OVMF ----------
QEMU_DIR   := $(shell brew --prefix qemu)/share/qemu
CODE_FD    := $(QEMU_DIR)/edk2-x86_64-code.fd
VARS_FD    := OVMF_VARS_rw.fd

# ---------- ESP paths ----------
ESP_DIR    := esp
EFI_BOOT   := $(ESP_DIR)/EFI/Boot/BootX64.efi
KERNEL_EFI := $(ESP_DIR)/nonos_kernel.efi

# ---------- Bootloader (this repo) ----------
TARGET        := x86_64-unknown-uefi
BUILD_DIR     := target/$(TARGET)/debug
LOADER_EFI    := $(BUILD_DIR)/nonos_boot.efi

# ---------- Kernel (sibling repo) ----------
# override with: make KERNEL_REPO=/path/to/nonos-kernel KERNEL_PROFILE=release run
KERNEL_REPO        ?= ../nonos-kernel
KERNEL_TARGET       = x86_64-nonos
KERNEL_PROFILE     ?= debug                # 'debug' or 'release'

# -------------------------------
# Targets
# -------------------------------

.PHONY: all build vars esp run clean kernel bootloader

all: run

bootloader:
	cargo build --target $(TARGET) --features mock-proof
	mkdir -p $(ESP_DIR)/EFI/Boot
	cp "$(LOADER_EFI)" "$(EFI_BOOT)"

# Build kernel and copy its *actual* produced executable into ESP.
# We query Cargo's JSON output to get the path (works for hyphen/underscore names).
kernel:
	@[ -d "$(KERNEL_REPO)" ] || (echo "Missing $(KERNEL_REPO). Clone the kernel repo next to this bootloader repo."; exit 1)
	@echo "Building kernel in $(KERNEL_REPO) ($(KERNEL_PROFILE))..."
	@cd "$(KERNEL_REPO)" && { \
	  if command -v jq >/dev/null 2>&1; then \
	    KPATH=$$(cargo build --target $(KERNEL_TARGET).json $(if $(filter $(KERNEL_PROFILE),release),--release,) --message-format=json \
	      | jq -r 'select(.executable!=null) | .executable' | tail -n1); \
	  else \
	    KPATH=$$(cargo build --target $(KERNEL_TARGET).json $(if $(filter $(KERNEL_PROFILE),release),--release,) --message-format=json \
	      | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n1); \
	  fi; \
	  echo "Kernel path: $$KPATH"; \
	  [ -n "$$KPATH" ] && [ -f "$$KPATH" ] || { echo "Kernel binary not found via cargo output"; exit 1; }; \
	  mkdir -p "$(ESP_DIR)/EFI/Boot"; \
	  cp "$$KPATH" "$(PWD)/$(KERNEL_EFI)"; \
	}

build: bootloader kernel

vars:
	@[ -f "$(CODE_FD)" ] || (echo "Missing $(CODE_FD). Install/reinstall qemu with Homebrew."; exit 1)
	@[ -f "$(VARS_FD)" ] || qemu-img create -f raw "$(VARS_FD)" "$$(stat -f%z "$(CODE_FD)")"

esp: build vars

run: esp
	qemu-system-x86_64 \
		-machine q35,accel=hvf -cpu host -m 1024 \
		-drive if=pflash,format=raw,readonly=on,file="$(CODE_FD)" \
		-drive if=pflash,format=raw,file="$(VARS_FD)" \
		-drive format=raw,file=fat:rw:$(ESP_DIR) \
		-serial stdio -monitor none -no-reboot

clean:
	rm -rf "$(ESP_DIR)" "$(VARS_FD)" target
