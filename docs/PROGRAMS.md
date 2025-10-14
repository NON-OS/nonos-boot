# Registered ZK Programs

Add one entry per Groth16 (or future) circuit. Never reuse a program ID for a changed circuit.

| Program ID | PROGRAM_HASH (hex) | VK Fingerprint (BLAKE3 hex) | Binding Mode | Circuit Purpose | Status | Notes |
|------------|--------------------|-----------------------------|--------------|-----------------|--------|-------|
| (example) zkmod-attest-v1 | (fill) | (fill) | public_inputs or manifest | Attestation circuit (example) | active | Replace placeholders |

Instructions:
1. Generate PROGRAM_HASH & VK constants with `zk-embed`.
2. Compute VK fingerprint: `blake3 verifying_key.bin`.
3. Add row before merging.
4. Update Status to `deprecated` or `revoked` when retiring.

Statuses:
- active: accepted for production proofs
- deprecated: still accepted, plan removal
- revoked: rejected (verification must fail)

Revocation approach: maintain a small list in code to block revoked PROGRAM_HASH values prior to registry lookup (optional enhancement).
