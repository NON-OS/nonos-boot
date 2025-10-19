//! Groth16 key operations for NONOS attestation circuit

use std::{fs, fs::File, io::Write, path::PathBuf, process::Command, time::SystemTime};

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use blake3::Hasher as Blake3;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use hex::ToHex;
use chrono::Utc;

use nonos_attestation_circuit::{expected_program_hash_bytes, NonosAttestationCircuit};

#[derive(Parser, Debug)]
#[command(name = "generate-keys", about = "NONOS attestation keys (Groth16, BLS12‑381) — production utilities")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate proving/verifying keys for the attestation circuit.
    Generate {
        #[arg(short, long, value_name = "DIR", default_value = ".")]
        output: String,

        #[arg(short = 's', long = "seed", value_name = "SEED", default_value = "42")]
        seed: String,

        #[arg(long = "print-program-hash")]
        print_program_hash: bool,

        #[arg(long = "sign-key", value_name = "PATH")]
        sign_key: Option<PathBuf>,

        /// Default: attestation_bundle.tar.gz
        #[arg(long = "bundle-out", value_name = "PATH")]
        bundle_out: Option<PathBuf>,

        /// If set, produce metadata.json but do NOT sign the bundle (for test/dev).
        #[arg(long = "allow-unsigned", action = clap::ArgAction::SetTrue)]
        allow_unsigned: bool,
    },

    /// Extract a verifying key (VK) from a proving key (PK)
    ExtractVk {
        #[arg(long, value_name = "PATH")]
        pk: PathBuf,

        #[arg(long, value_name = "PATH", default_value = "attestation_verifying_key.bin")]
        out: PathBuf,
    },

    /// Inspect a verifying key and print metadata/fingerprint
    InspectVk {
        #[arg(long, value_name = "PATH")]
        vk: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    tool: String,
    tool_version: String,
    rustc_version: String,
    cargo_version: String,
    commit: Option<String>,
    seed: String,
    vk_blake3: String,
    public_inputs_expected: usize,
    canonical_vk_len: usize,
    generated_at_utc: String,
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    match args.cmd {
        Cmd::Generate {
            output,
            seed,
            print_program_hash,
            sign_key,
            bundle_out,
            allow_unsigned,
        } => {
            let out_dir = PathBuf::from(output);
            if !out_dir.exists() {
                fs::create_dir_all(&out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
            }

            let seed_u64 = parse_seed(&seed);
            let mut rng = StdRng::seed_from_u64(seed_u64);

            // Circuit with default witness; only shape needs for VK.
            let circuit: NonosAttestationCircuit<Fr> = Default::default();
            let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
                .map_err(|e| format!("setup: {e}"))?;

            // Serialize (canonical compressed) + write
            let mut pk_bytes = Vec::new();
            pk.serialize_with_mode(&mut pk_bytes, Compress::Yes)
                .map_err(|e| format!("pk serialize: {e}"))?;

            let mut vk_bytes = Vec::new();
            vk.serialize_with_mode(&mut vk_bytes, Compress::Yes)
                .map_err(|e| format!("vk serialize: {e}"))?;

            let pk_path = out_dir.join("attestation_proving_key.bin");
            let vk_path = out_dir.join("attestation_verifying_key.bin");

            write_bin(&pk_path, &pk_bytes)?;
            write_bin(&vk_path, &vk_bytes)?;

            let fp = blake3_hex(&vk_bytes);
            let inputs = vk.ic.len().saturating_sub(1);

            // Build metadata
            let tool = "nonos-attestation-circuit".to_string();
            let tool_version = env!("CARGO_PKG_VERSION").to_string();
            let rustc_version = get_rustc_version();
            let cargo_version = get_cargo_version();
            let commit = std::env::var("GIT_COMMIT").ok().or_else(|| git_commit_hash());
            let ts = Utc::now().to_rfc3339();

            let metadata = Metadata {
                tool,
                tool_version,
                rustc_version,
                cargo_version,
                commit,
                seed: seed.clone(),
                vk_blake3: fp.clone(),
                public_inputs_expected: inputs,
                canonical_vk_len: vk_bytes.len(),
                generated_at_utc: ts,
            };

            let metadata_json = serde_json::to_vec_pretty(&metadata).map_err(|e| format!("metadata json: {e}"))?;
            write_bin(&out_dir.join("metadata.json"), &metadata_json)?;

            println!("NONOS attestation keys generated");
            println!("proving_key:   {} ({} bytes)", pk_path.display(), pk_bytes.len());
            println!("verifying_key: {} ({} bytes)", vk_path.display(), vk_bytes.len());
            println!("vk_blake3:     {}", fp);
            println!("public_inputs_expected: {}", inputs);

            if print_program_hash {
                let ph = expected_program_hash_bytes();
                println!("program_hash_hex: {}", hex::encode(ph));
            }

            // Bundle creation: tar.gz contains: attestation_verifying_key.bin, metadata.json, signature.sig
            let bundle_path = bundle_out.unwrap_or_else(|| out_dir.join("attestation_bundle.tar.gz"));

            // Sign if sign_key supplied
            let signature_path = out_dir.join("signature.sig");
            if let Some(sign_key_path) = sign_key {
                let sig = sign_bundle(&sign_key_path, &vk_bytes, &metadata_json)?;
                write_bin(&signature_path, &sig)?;
                create_bundle(&bundle_path, &vk_path, &out_dir.join("metadata.json"), &signature_path)?;
                println!("signed bundle written: {}", bundle_path.display());
            } else if allow_unsigned {
                // create bundle without signature
                // Create an empty signature file to keep layout
                let _ = write_bin(&signature_path, &[]); // zero-length
                create_bundle(&bundle_path, &vk_path, &out_dir.join("metadata.json"), &signature_path)?;
                println!("unsigned bundle written: {}", bundle_path.display());
            } else {
                println!("No signing key provided; bundle not signed. Use --sign-key to produce signed bundle or --allow-unsigned for test builds.");
            }

            Ok(())
        }

        Cmd::ExtractVk { pk, out } => {
            let pk = read_pk_any(&pk)?;
            let vk = pk.vk;

            let mut vk_bytes = Vec::new();
            vk.serialize_with_mode(&mut vk_bytes, Compress::Yes)
                .map_err(|e| format!("vk serialize: {e}"))?;
            write_bin(&out, &vk_bytes)?;

            let fp = blake3_hex(&vk_bytes);
            let inputs = vk.ic.len().saturating_sub(1);

            println!("verifying_key_written: {} ({} bytes)", out.display(), vk_bytes.len());
            println!("vk_blake3: {}", fp);
            println!("public_inputs_expected: {}", inputs);
            Ok(())
        }

        Cmd::InspectVk { vk } => {
            let vk = read_vk_any(&vk)?;
            let mut comp = Vec::new();
            vk.serialize_with_mode(&mut comp, Compress::Yes)
                .map_err(|e| format!("vk serialize: {e}"))?;

            let fp = blake3_hex(&comp);
            let inputs = vk.ic.len().saturating_sub(1);

            println!("vk_ok");
            println!("canonical_compressed_len: {}", comp.len());
            println!("vk_blake3: {}", fp);
            println!("public_inputs_expected: {}", inputs);
            Ok(())
        }
    }
}

fn write_bin(path: &PathBuf, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
    }
    let mut f = File::create(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    f.write_all(bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

fn read_vk_any(path: &PathBuf) -> Result<VerifyingKey<Bls12_381>, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if bytes.is_empty() {
        return Err("vk file is empty".into());
    }
    VerifyingKey::<Bls12_381>::deserialize_with_mode(
        &mut ark_std::io::Cursor::new(&bytes),
        Compress::Yes,
        true,
    )
    .or_else(|_| {
        VerifyingKey::<Bls12_381>::deserialize_with_mode(
            &mut ark_std::io::Cursor::new(&bytes),
            Compress::No,
            true,
        )
    })
    .map_err(|_| "not a valid arkworks Groth16 VK (BLS12-381)".to_string())
}

fn read_pk_any(path: &PathBuf) -> Result<ProvingKey<Bls12_381>, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if bytes.is_empty() {
        return Err("pk file is empty".into());
    }
    ProvingKey::<Bls12_381>::deserialize_with_mode(
        &mut ark_std::io::Cursor::new(&bytes),
        true,
        true,
    )
    .or_else(|_| {
        ProvingKey::<Bls12_381>::deserialize_with_mode(
            &mut ark_std::io::Cursor::new(&bytes),
            Compress::No,
            true,
        )
    })
    .map_err(|_| "not a valid arkworks Groth16 ProvingKey (BLS12-381)".to_string())
}

fn parse_seed(s: &str) -> u64 {
    if let Ok(v) = s.parse::<u64>() {
        return v;
    }
    let s = s.trim_start_matches("0x");
    let mut acc = 0u64;
    for &b in s.as_bytes() {
        let v = match b {
            b'0'..=b'9' => (b - b'0') as u8,
            b'a'..=b'f' => 10 + (b - b'a') as u8,
            b'A'..=b'F' => 10 + (b - b'A') as u8,
            _ => 0,
        } as u64;
        acc = acc.wrapping_mul(257).wrapping_add(v);
    }
    if acc == 0 { 42 } else { acc }
}

fn blake3_hex(bytes: &[u8]) -> String {
    let mut h = Blake3::new();
    h.update(bytes);
    h.finalize().to_hex().to_string()
}

fn git_commit_hash() -> Option<String> {
    if let Ok(out) = Command::new("git").args(&["rev-parse", "HEAD"]).output() {
        if out.status.success() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                return Some(s.trim().to_string());
            }
        }
    }
    None
}

fn get_rustc_version() -> String {
    std::env::var("RUSTC_VERSION").unwrap_or_else(|_| {
        std::process::Command::new("rustc").arg("--version").output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".into())
    })
}

fn get_cargo_version() -> String {
    std::env::var("CARGO_VERSION").unwrap_or_else(|_| {
        std::process::Command::new("cargo").arg("--version").output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".into())
    })
}

fn create_bundle(bundle_out: &PathBuf, vk_path: &PathBuf, metadata_path: &PathBuf, signature_path: &PathBuf) -> Result<(), String> {
    // tar.gz 
    use tar::Builder;
    use flate2::{Compression, write::GzEncoder};

    let f = File::create(bundle_out).map_err(|e| format!("create bundle: {e}"))?;
    let enc = GzEncoder::new(f, Compression::default());
    let mut tar = Builder::new(enc);

    tar.append_path_with_name(vk_path, "attestation_verifying_key.bin").map_err(|e| format!("tar vk: {e}"))?;
    tar.append_path_with_name(metadata_path, "metadata.json").map_err(|e| format!("tar metadata: {e}"))?;
    if signature_path.exists() && signature_path.metadata().map_err(|e| e.to_string())?.len() > 0 {
        tar.append_path_with_name(signature_path, "signature.sig").map_err(|e| format!("tar sig: {e}"))?;
    }

    tar.finish().map_err(|e| format!("finish tar: {e}"))?;
    Ok(())
}

fn sign_bundle(sign_key_path: &PathBuf, vk_bytes: &[u8], metadata_json: &[u8]) -> Result<Vec<u8>, String> {
    use ed25519_dalek::{Keypair, Signature, Signer, SECRET_KEY_LENGTH, KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH};
    let key_bytes = fs::read(sign_key_path).map_err(|e| format!("read sign key: {e}"))?;

    // Accept 64-byte keypair, or 32-byte seed secret
    let kp = if key_bytes.len() == KEYPAIR_LENGTH {
        Keypair::from_bytes(&key_bytes).map_err(|e| format!("keypair parse: {e}"))?
    } else if key_bytes.len() == SECRET_KEY_LENGTH {
        let secret = ed25519_dalek::SecretKey::from_bytes(&key_bytes).map_err(|e| format!("secret parse: {e}"))?;
        let public = ed25519_dalek::PublicKey::from(&secret);
        Keypair { secret, public }
    } else {
        // try hex-encoded secret
        if let Ok(s) = std::str::from_utf8(&key_bytes) {
            let s = s.trim();
            let raw = hex::decode(s).map_err(|e| format!("hex decode sign key: {e}"))?;
            if raw.len() == SECRET_KEY_LENGTH {
                let secret = ed25519_dalek::SecretKey::from_bytes(&raw).map_err(|e| format!("secret parse hex: {e}"))?;
                let public = ed25519_dalek::PublicKey::from(&secret);
                Keypair { secret, public }
            } else if raw.len() == KEYPAIR_LENGTH {
                Keypair::from_bytes(&raw).map_err(|e| format!("keypair parse hex: {e}"))?
            } else {
                return Err("sign key must be 32-byte secret or 64-byte keypair (raw) or hex".into());
            }
        } else {
            return Err("sign key must be 32-byte secret or 64-byte keypair (raw) or hex".into());
        }
    };

    // vk_bytes || metadata_json
    let mut signed_input = Vec::with_capacity(vk_bytes.len() + metadata_json.len());
    signed_input.extend_from_slice(vk_bytes);
    signed_input.extend_from_slice(metadata_json);

    let signature: Signature = kp.sign(&signed_input);
    Ok(signature.to_bytes().to_vec())
}
