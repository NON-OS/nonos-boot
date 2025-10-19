#!/usr/bin/env bash
set -euo pipefail

VK=""
META=""
OUT="attestation_bundle.tar.gz"
HSM_SIGN=""
LOCAL_SIGN_KEY=""

usage() {
  cat <<EOF
create_signed_bundle.sh --vk <vk.bin> --metadata <metadata.json> --out <bundle.tar.gz> [--hsm <uri>] [--local-sign-key <path>]
Creates tar.gz bundle: attestation_verifying_key.bin, metadata.json, signature.sig.
**use --hsm to sign with KMS/HSM.** **Local signing is for test only.**
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vk) VK="$2"; shift 2 ;;
    --metadata) META="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --hsm) HSM_SIGN="$2"; shift 2 ;;
    --local-sign-key) LOCAL_SIGN_KEY="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "${VK}" || -z "${META}" ]]; then
  usage
fi

TMPDIR=$(mktemp -d)
cp "${VK}" "${TMPDIR}/attestation_verifying_key.bin"
cp "${META}" "${TMPDIR}/metadata.json"
SIGN_INPUT="${TMPDIR}/signed_input.bin"
cat "${TMPDIR}/attestation_verifying_key.bin" "${TMPDIR}/metadata.json" > "${SIGN_INPUT}"
SIG_OUT="${TMPDIR}/signature.sig"

if [[ -n "${HSM_SIGN}" ]]; then
  echo "[bundle] HSM signing requested (${HSM_SIGN}). Implement HSM signing integration here."
  exit 1
elif [[ -n "${LOCAL_SIGN_KEY}" ]]; then
  if command -v ed25519sign >/dev/null 2>&1; then
    ed25519sign --key "${LOCAL_SIGN_KEY}" --in "${SIGN_INPUT}" --out "${SIG_OUT}" || { echo "local sign failed"; exit 2; }
  else
    echo "[bundle] ed25519sign tool not available; local signing not possible."
    exit 1
  fi
else
  echo "[bundle] No signing requested; producing unsigned bundle (NOT FOR PRODUCTION)"
  > "${SIG_OUT}"
fi

tar -C "${TMPDIR}" -czf "${OUT}" attestation_verifying_key.bin metadata.json signature.sig
SHA256=$(sha256sum "${OUT}" | awk '{print $1}')
echo "bundle ${OUT} created (sha256=${SHA256})"
echo "tmpdir: ${TMPDIR}"
