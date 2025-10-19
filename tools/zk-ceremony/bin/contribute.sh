#!/usr/bin/env bash
set -euo pipefail

IN=""
OUT=""
NAME=""
ENTROPY="/dev/random"
POWERSOFTAU="${POWERSOFTAU:-powersoftau}"
LOGDIR="${LOGDIR:-contrib_logs}"
LOCAL_SIGN_KEY=""

usage() {
  cat <<EOF
contribute.sh --in <in.ptau> --out <out.ptau> --name "<Org:Name>" [--entropy <file>] [--tool <powersoftau>] [--local-sign-key <path>]
Performs a single participant contribution to the PoT transcript with provenance logging.
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --in) IN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --entropy) ENTROPY="$2"; shift 2 ;;
    --tool) POWERSOFTAU="$2"; shift 2 ;;
    --local-sign-key) LOCAL_SIGN_KEY="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "${IN}" || -z "${OUT}" || -z "${NAME}" ]]; then
  usage
fi

command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 1; }

mkdir -p "${LOGDIR}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LOGFILE="${LOGDIR}/contrib_$(echo "${NAME}" | tr ' /' '_')_${TIMESTAMP}.json"

echo "[contrib] Verifying prior transcript ${IN}"
"${POWERSOFTAU}" verify --input "${IN}" || { echo "prior transcript verification failed"; exit 2; }

echo "[contrib] Contributing randomness..."
"${POWERSOFTAU}" contribute --input "${IN}" --output "${OUT}" --name "${NAME}" --entropy "${ENTROPY}"

OUT_SHA=$(sha256sum "${OUT}" | awk '{print $1}')
IN_SHA=$(sha256sum "${IN}" | awk '{print $1}')
POW_VER=$("${POWERSOFTAU}" --version 2>/dev/null || echo "unknown")
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
UNAME=$(uname -a)

jq -n --arg participant "${NAME}" \
      --arg input_transcript "$(basename "${IN}")" \
      --arg input_sha "${IN_SHA}" \
      --arg output_transcript "$(basename "${OUT}")" \
      --arg output_sha "${OUT_SHA}" \
      --arg powersoftau "${POWERSOFTAU}" \
      --arg powersoftau_version "${POW_VER}" \
      --arg entropy "${ENTROPY}" \
      --arg timestamp "${TIMESTAMP}" \
      --arg host "${HOSTNAME}" \
      --arg uname "${UNAME}" \
      '{
        participant: $participant,
        input_transcript: $input_transcript,
        input_sha256: $input_sha,
        output_transcript: $output_transcript,
        output_sha256: $output_sha,
        powersoftau: $powersoftau,
        powersoftau_version: $powersoftau_version,
        entropy_source: $entropy,
        timestamp: $timestamp,
        host: $host,
        uname: $uname
      }' > "${LOGFILE}"

echo "[contrib] Contribution log: ${LOGFILE}"

if [[ -n "${LOCAL_SIGN_KEY}" ]]; then
  if command -v ed25519sign >/dev/null 2>&1; then
    ed25519sign --key "${LOCAL_SIGN_KEY}" --in "${LOGFILE}" --out "${LOGFILE}.sig" || echo "[contrib] local signing failed"
    echo "[contrib] Signed log: ${LOGFILE}.sig"
  else
    echo "[contrib] ed25519sign not available; skip local signing. Use HSM in production."
  fi
fi

echo "contribution_complete=true"
echo "contribution_log=${LOGFILE}"
echo "Publish ${OUT} and ${LOGFILE} (and ${LOGFILE}.sig if present) to artifact store."
