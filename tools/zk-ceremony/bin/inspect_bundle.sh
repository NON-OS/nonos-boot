#!/usr/bin/env bash
set -euo pipefail

BUNDLE=""
ROOT_PUBKEY=""

usage() {
  cat <<EOF
inspect_bundle.sh --bundle <bundle.tar.gz> [--root-pubkey <pubkey-file>]
Extracts bundle, prints metadata, computes vk_blake3 and optionally verifies signature with root public key.
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2 ;;
    --root-pubkey) ROOT_PUBKEY="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "${BUNDLE}" ]]; then
  usage
fi

command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 1; }

TMP=$(mktemp -d)
tar -xzf "${BUNDLE}" -C "${TMP}"
VK="${TMP}/attestation_verifying_key.bin"
META="${TMP}/metadata.json"
SIG="${TMP}/signature.sig"

echo "[inspect] metadata:"
cat "${META}" | jq -C .

# Compute blake3 using blake3 CLI when available, else try python
if command -v blake3 >/dev/null 2>&1; then
  VK_BLAKE3=$(blake3 "${VK}")
elif command -v python3 >/dev/null 2>&1; then
  VK_BLAKE3=$(python3 - <<PY
import sys
try:
    import blake3
except Exception:
    print("blake3-cli-not-available")
    sys.exit(0)
b=open("${VK}","rb").read()
print(blake3.blake3(b).hexdigest())
PY
)
else
  VK_BLAKE3="blake3-tool-missing"
fi

echo "[inspect] vk_blake3: ${VK_BLAKE3}"
echo "[inspect] metadata vk_blake3: $(jq -r '.vk_blake3 // "none"' ${META})"

if [[ -n "${ROOT_PUBKEY}" && -f "${SIG}" ]]; then
  if command -v ed25519verify >/dev/null 2>&1; then
    ed25519verify --pub "${ROOT_PUBKEY}" --sig "${SIG}" --in "${VK}" || { echo "VK signature verify failed"; exit 2; }
    echo "[inspect] signature verified with root pubkey"
  else
    echo "[inspect] signature present but ed25519verify not available; manual verification required"
  fi
else
  echo "[inspect] signature not verified locally (no root pubkey provided or signature missing)"
fi

echo "[inspect] tmpdir: ${TMP} (preserve for audit or remove manually)"
