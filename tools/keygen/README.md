```markdown
# NONOS Key Generator (nonos-keygen) 
Purpose
- Generate Ed25519 signer keypairs for the NONOS ceremony and produce a signers.json
  file that contains each signer's id, public key (hex) and fingerprints (SHA256 and Blake3).

- Zeroize: secret bytes are zeroed from memory after use.
- Atomic writes: all files are written via tempfile + fsync + atomic rename.
- generation_log.json: records tool version, rustc/cargo versions, git commit, host fingerprint, operator hash, timestamp, key count and threshold.
- --pub-only: write only public files (for HSM/external generation workflows).
- Explicit guard: secret files are only written when --allow-write-secrets is provided.
- Default secret file permissions are 0o600 (Unix).

Important security guidance
- Run on an air-gapped host or use HSM-backed keys for production.
- Do NOT commit secret key files to source control.
- After generation, move secrets to secure storage (HSM, sealed encrypted artifact store), and securely erase local copies.
- Prefer signers that hold keys in HSMs and only share public keys with the coordinator.

Quick start (dev)
- Build:
  cd tools/keygen
  cargo build --release

- Generate 4 signers (test/dev):
  ./target/release/nonos-keygen --count 4 --out-dir keys --format hex --signers signers.json --threshold 3 --allow-write-secrets

- Generate signers.json only (for HSM-external keys):
  ./target/release/nonos-keygen --count 4 --out-dir keys --format hex --signers signers.json --threshold 3 --pub-only

Notes on permissions and CI
- The tool refuses to write secret files unless --allow-write-secrets is explicitly provided to prevent accidental commits.
- For CI smoke-tests, we use --pub-only or run generation in a self-contained runner and we do NOT upload secret files as artifacts.
