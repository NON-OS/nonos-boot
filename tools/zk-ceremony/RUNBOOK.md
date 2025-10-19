```markdown
# Ceremony Runbook — Powers‑of‑Tau + Groth16 

This runbook provides step-by-step, auditable instructions for performing a production
multi‑party Powers‑of‑Tau (PoT) ceremony and preparing a circuit-specific Groth16
setup for NONOS attestation.

Credits and references
- Phase‑1 PoT concept and reference implementation: zkcrypto / powersoftau (https://github.com/zkcrypto/powersoftau)
- Groth16 and Rust ecosystem: arkworks (https://arkworks.rs/)

Preconditions and roles
- Coordinator: prepares initial transcript and orchestrates participant order.
- Participant/Contributor: verifies prior transcript, contributes randomness, records evidence.
- Auditor: verifies contributions and final transcripts.
- Release Authority: verifies PK/VK and produces signed VK bundle using HSM/KMS.

System and software prerequisites
- Pinned, audited `powersoftau` binary accessible to all participants (use the Dockerfile to build).
- `jq`, `tar`, `sha256sum`, `openssl` or HSM client tools for signing/verification.
- Secure artifact store (immutable, access-controlled) for transcripts and logs.
- Root public key for verifying signed VK bundles (for CI and operators).

High-level procedure

Phase 1 — Universal PoT
1. Coordinator creates initial transcript:
   - Run: `./bin/init_powersoftau.sh --power <t> --out pot_0000.ptau --operator "Org:Coordinator"`
   - Record: transcript SHA256, tool binary version, operator identity, timestamp; save JSON log.
   - Distribute: securely publish pot_0000.ptau and init log to all participants.

2. Participant contributions (repeat for each participant):
   - Verify prior transcript:
     - `powersoftau verify --input pot_000{k}.ptau`
   - Contribute:
     - `./bin/contribute.sh --in pot_000{k}.ptau --out pot_000{k+1}.ptau --name "Org:Alice" --entropy /dev/random`
   - Produce log (JSON) with fields:
     - participant, input_sha256, output_sha256, powersoftau_version, entropy description, host, timestamp
   - Sign and publish log:
     - Production: sign log with participant HSM or other endorsed signing method; publish signature with log.
     - Upload pot_000{k+1}.ptau and log to artifact store.

3. Auditor verification:
   - Collect all transcripts and logs.
   - Run: `./bin/verify_chain.sh --root pot_0000.ptau --chain pot_0001.ptau pot_0002.ptau ... --log-dir contrib_logs --root-pubkey auditors_root.pub`
   - Confirm every contribution log corresponds to the next transcript and signature verifies.

Phase 2 — Circuit-specific
1. Prepare phase-2:
   - `./bin/prepare_phase2.sh --tau pot_final.ptau --out pot_phase2.ptau`
2. Circuit key generation (offline, controlled environment):
   - Use arkworks or another audited SNARK backend and pot_phase2.ptau to generate proving_key.bin (keep secret) and verifying_key.bin (canonical compressed).
   - Run sample proof/verify tests with known witnesses to validate PK/VK.

Packaging and signing
1. Create metadata.json:
   - Include fields: tool versions, commit, participants (ordered list with their transcript SHA256), vk_blake3, public_inputs_expected, canonical_vk_len, timestamp.
2. Sign bundle:
   - Production: use HSM/KMS (AWS KMS, Cloud KMS, Vault, or hardware signer). Sign the concatenation: vk_bytes || metadata.json.
   - Create tar.gz bundle containing: attestation_verifying_key.bin, metadata.json, signature.sig.
   - Use `./bin/create_signed_bundle.sh` as template; implement HSM signing integration per your environment.
3. Publish signed bundle:
   - Place in release artifacts (immutable store) and record vk_blake3 in release notes.

CI / Provisioning
1. CI verifies signed bundle with release root public key.
2. CI runs `zk-embed --bundle <bundle> --root-pubkey <root.pub> --program-id-str "<id>" --const-prefix <PREFIX> --out vk_snippet.rs`.
   - The emitted snippet contains a provenance marker that build.rs checks.
3. CI injects snippet into build working tree (no private keys committed) and runs the build with `--features "zk-groth16 zk-vk-provisioned"`.
4. build.rs enforces presence of provenance marker and basic sanity checks.

Audit and retention
- Archive all transcripts, contribution logs, signatures, and final bundle in immutable storage.
- Produce SBOM for tools used and run `cargo-audit` on relevant Rust artifacts.
- Engage a third-party cryptographic auditor to verify transcripts and tooling for the production release.

Emergency and rotation
- If suspected compromise occurs:
  - Halt provisioning and builds that depend on the VK.
  - Publish a signed revocation notice and start a new ceremony following the same audited steps.
  - Rotate signing keys and update CI and release authority records.

Example quick commands (single-party dev/test, not production)
- Build PoT container:
  docker build -t nonos/powersoftau:latest tools/zk-ceremony
- Init:
  ./bin/init_powersoftau.sh --power 22 --operator "TestOrg"
- Contribute:
  ./bin/contribute.sh --in pot_0000.ptau --out pot_0001.ptau --name "TestOrg:CI" --entropy /dev/urandom
- Prepare phase2:
  ./bin/prepare_phase2.sh --tau pot_0001.ptau --out pot_phase2.ptau

End of runbook.
