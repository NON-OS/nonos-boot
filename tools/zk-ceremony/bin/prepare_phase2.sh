#!/usr/bin/env bash
set -euo pipefail

TAU=""
OUT=""
POWERSOFTAU="${POWERSOFTAU:-powersoftau}"

usage() {
  cat <<EOF
prepare_phase2.sh --tau <final.ptau> --out <phase2.ptau> [--tool <powersoftau>]
Prepares a phase2 transcript for circuit-specific Groth16 setup.
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tau) TAU="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --tool) POWERSOFTAU="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "${TAU}" || -z "${OUT}" ]]; then
  usage
fi

echo "[prepare_phase2] input=${TAU}, out=${OUT}, tool=${POWERSOFTAU}"
"${POWERSOFTAU}" prepare_phase2 --input "${TAU}" --output "${OUT}" || { echo "prepare_phase2 failed"; exit 2; }
echo "phase2 prepared: ${OUT} (sha256: $(sha256sum "${OUT}" | awk '{print $1}'))"
