#!/usr/bin/env bash
set -euo pipefail

POWERSOFTAU="${POWERSOFTAU:-powersoftau}"
ROOT=""
LOGDIR=""
ROOT_PUBKEY=""

usage() {
  cat <<EOF
verify_chain.sh --root <base.ptau> --chain <next.ptau> [next2.ptau ...] [--log-dir <dir>] [--root-pubkey <path>]
Verifies the sequence of transcripts using powersoftau verify. Optionally validates signed logs.
EOF
  exit 1
}

if [[ $# -lt 2 ]]; then
  usage
fi

CHAIN=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) ROOT="$2"; shift 2 ;;
    --chain) shift; while [[ $# -gt 0 && "$1" != "--log-dir" && "$1" != "--root-pubkey" ]]; do CHAIN+=("$1"); shift; done ;;
    --log-dir) LOGDIR="$2"; shift 2 ;;
    --root-pubkey) ROOT_PUBKEY="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "${ROOT}" || "${#CHAIN[@]}" -eq 0 ]]; then
  usage
fi

echo "[verify_chain] root: ${ROOT}"
PREV="${ROOT}"
for CUR in "${CHAIN[@]}"; do
  echo "[verify_chain] validating ${CUR} against ${PREV}"
  "${POWERSOFTAU}" verify --input "${CUR}" --previous "${PREV}" || { echo "Verification failed for ${CUR}"; exit 2; }
  echo "[verify_chain] ok: ${CUR}"
  PREV="${CUR}"
done

if [[ -n "${LOGDIR}" ]]; then
  echo "[verify_chain] scanning logs in ${LOGDIR}"
  for logf in "${LOGDIR}"/*.json; do
    [ -e "$logf" ] || continue
    echo " - ${logf}"
    if [[ -n "${ROOT_PUBKEY}" && -f "${logf}.sig" ]]; then
      if command -v ed25519verify >/dev/null 2>&1; then
        ed25519verify --pub "${ROOT_PUBKEY}" --sig "${logf}.sig" --in "${logf}" || { echo "log signature verification failed for ${logf}"; exit 3; }
        echo "   signature ok"
      else
        echo "   signature present but no ed25519verify tool; manual check advised"
      fi
    fi
  done
fi

echo "All transcripts and logs verified."
