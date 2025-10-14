# NØNOS Zero‑Knowledge Attestation

Author: eK (team@nonos.systems) — https://nonos.systems  
License: AGPL-3.0

## Summary

The bootloader optionally verifies a Groth16 (BLS12-381) proof bound to the capsule. Verification is feature-controlled, constant-time on 32-byte identifiers, and guarded so a ZK-enabled build cannot ship without explicit verifying key provisioning.

## Domain Separation

- Program hash: `NONOS:ZK:PROGRAM:v1` (BLAKE3 derive_key)
- Capsule commitment: `NONOS:CAPSULE:COMMITMENT:v1`

## Binding Modes

|          Mode           |           Feature Flag & Commitment Input      |              Use Case                  |
|-------------------------|------------------------------------------------|----------------------------------------|
| Public Inputs (default) | (none) | concatenated 32-byte Fr public inputs | Simpler;re-derives commitment          |
|    Manifest Binding     | `zk-bind-manifest` | raw signed manifest bytes | Linkage between signature and ZK proof |

## Proof Encoding (Logical)

- `program_hash`: 32 bytes
- `capsule_commitment`: 32 bytes
- `public_inputs`: N * 32-byte big-endian field elements (Fr)
- `proof_blob`: Groth16 proof A(G1)|B(G2)|C(G1), canonical compressed (192 bytes)

Public input count must equal `vk.ic.len() - 1`.

## Verifying Key Provisioning

Use `tools/zk-embed`:
1. Provide stable program ID bytes (UTF‑8, hex, or file).
2. Derive PROGRAM_HASH (BLAKE3 derive_key).
3. Normalize VK to canonical compressed bytes.
4. Paste constants + mapping into `src/zk/registry.rs`.
5. Enable `zk-groth16,zk-vk-provisioned` (and optionally `zk-bind-manifest`).

## Feature Flags

| Flag | Purpose |
|------|---------|
| `zk-groth16` | Enable Groth16 verifier & registry |
| `zk-vk-provisioned` | Assert verifying keys are truly embedded (no placeholders) |
| `zk-bind-manifest` | Switch binding source to manifest bytes |
| `zk-testvectors` | Include test vector scaffolding |
| `zk-zeroize` | Zeroize proof/input buffers after verification |

## Size & Structural Limits

| Item | Limit |
|------|-------|
| Proof size | 192 bytes (Groth16 compressed A+B+C) |
| Public inputs total bytes | ≤ 256 KiB |
| Manifest (if bound) | ≤ 128 KiB |
| Proof blob max (cap) | 2 MiB (defensive) |

## Error Semantics

Errors are deterministic & stable:
- Invalid: structural or semantic mismatch (commitment mismatch, malformed inputs)
- Unsupported: disabled backend or unknown program hash
- Error: internal backend errors (deserialization, empty VK)
- Valid: successful verification

Policy: If ZK required by manifest/policy and result ≠ Valid, abort boot.

## Security Invariants

- Constant-time compare for commitments & program hash selection.
- Domain-separated hashing to prevent cross-protocol collisions.
- Compile-time guard: cannot enable `zk-groth16` + `zk-vk-provisioned` with placeholder VK.
- Input count validated against VK.
- Proof size fixed (rejects trailing junk).
- Optional buffer zeroization (defense-in-depth).

## Governance Recommendations

Maintain `docs/PROGRAMS.md` listing each PROGRAM_HASH, VK fingerprint (BLAKE3 hash of VK bytes), circuit purpose, and status (active, deprecated, revoked). Changing circuit constraints ⇒ new program ID (never reuse).

## Tests

- Fuzz: section parser + `verify_proof` (bounded sizes).
- Tests: mismatch paths, size caps, alignment, input count mismatch, success vector (when real VK/proof added).

## Roadmap

- Multi-prover support (add new feature-gated backends)
- Remote attestation: export hashed transcript of public inputs
- VK revocation list integration
