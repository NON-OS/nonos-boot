```markdown
# NONOS ZK Ceremony Toolkit — Powers-of-Tau

This directory contains production-grade, auditable tooling and runbooks for running
a multi-party Powers-of-Tau (PoT) ceremony and preparing a circuit-specific Groth16
setup for NONOS attestation.

This toolkit is intended to be used by operators running a trusted ceremony with
multiple independent participants. Do not treat single-party runs as production; they
are for testing and reproducibility only.

Key design goals
- Auditable transcripts and per-contribution provenance logs (JSON)
- Reproducible builds for the PoT tool (Dockerfile included)
- Explicit integration points for secure signing (HSM/KMS) and CI verification
- Canonical output formats compatible with arkworks Groth16 tooling used by NONOS
- Clear, operator-focused runbook with checklists and evidence collection

References
- Powers-of-Tau reference implementation: zkcrypto / powersoftau — https://github.com/zkcrypto/powersoftau
- Groth16 and Rust tooling: arkworks — https://arkworks.rs/

Prerequisites
- The `powersoftau` CLI built from a pinned, audited commit (see Dockerfile)
- `jq`, `tar`, `sha256sum`, and a signing tool (HSM/KMS preferred)
- A secure artifact storage mechanism for transcripts and logs
- Coordination between independent participants and auditors

Directory layout
- bin/
  - init_powersoftau.sh
  - contribute.sh
  - verify_chain.sh
  - prepare_phase2.sh
  - create_signed_bundle.sh
  - inspect_bundle.sh
- Dockerfile
- RUNBOOK.md

Overview of recommended flow
1. Coordinator creates initial transcript (`init_powersoftau.sh`).
2. Each participant verifies the prior transcript, contributes randomness (`contribute.sh`),
   and publishes a signed JSON contribution log and the new transcript.
3. Auditors verify all contributions (`verify_chain.sh`).
4. Coordinator prepares phase-2 transcript (`prepare_phase2.sh`).
5. Circuit-specific key generation (offline, using arkworks) produces PK (secret) and VK.
6. Release authority signs VK + metadata using HSM/KMS; create signed bundle
   using `create_signed_bundle.sh` (HSM path preferred).
7. CI verifies signed bundle, runs `zk-embed` to emit trusted snippet, injects snippet,
   then build with `zk-vk-provisioned` (build guard enforces provenance).

Security note
- Keep private keys and proving keys secret and in protected storage. ** JUST DO IT :') **
- Produce signed bundles only in protected environments (HSM/KMS).
- Archive transcripts and logs in immutable storage for audit.

Operator checklist and detailed runbook are in RUNBOOK.md.
```
