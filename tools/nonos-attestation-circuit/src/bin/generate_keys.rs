//! Groth16 key operations for NONOS attestation circuit.

use std::{fs, fs::File, io::Write, path::PathBuf};

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use blake3::Hasher as Blake3;
use clap::{Parser, Subcommand};

use nonos_attestation_circuit::{expected_program_hash_bytes, NonosAttestationCircuit};

#[derive(Parser, Debug)]
#[command(name = "generate-keys", about = "NONOS attestation keys (Groth16, BLS12-381) — production utilities")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate proving/verifying keys for the attestation circuit.
    /// For production MPC, run your ceremony externally and use extract-vk to obtain VK.
    Generate {
        /// Output directory to write keys into
        #[arg(short, long, value_name = "DIR", default_value = ".")]
        output: String,

        /// Optional deterministic seed (hex or decimal). If absent, uses a fixed default.
        #[arg(short = 's', long = "seed", value_name = "SEED", default_value = "42")]
        seed: String,

        /// Also print the program hash to assist provisioning
        #[arg(long = "print-program-hash")]
        print_program_hash: bool,
    },

    /// Extract a verifying key (VK) from a proving key (PK)
    ExtractVk {
        /// Input proving key path (arkworks CanonicalSerialize; compressed or uncompressed)
        #[arg(long, value_name = "PATH")]
        pk: PathBuf,

        /// Output verifying key path (canonical compressed)
        #[arg(long, value_name = "PATH", default_value = "attestation_verifying_key.bin")]
        out: PathBuf,
    },

    /// Inspect a verifying key and print metadata/fingerprint
    InspectVk {
        /// Input verifying key path (arkworks CanonicalSerialize; compressed or uncompressed)
        #[arg(long, value_name = "PATH")]
        vk: PathBuf,
    },
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    match args.cmd {
        Cmd::Generate {
            output,
            seed,
            print_program_hash,
        } => {
            let out_dir = PathBuf::from(output);
            if !out_dir.exists() {
                fs::create_dir_all(&out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
            }

            let seed_u64 = parse_seed(&seed);
            let mut rng = StdRng::seed_from_u64(seed_u64);

            // Circuit with default witness; only the shape matters for VK.
            let circuit: NonosAttestationCircuit<Fr> = Default::default();
            let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
                .map_err(|e| format!("setup: {e}"))?;

            // Serialize (canonical compressed) and write
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

            println!("NONOS attestation keys generated");
            println!("proving_key:   {} ({} bytes)", pk_path.display(), pk_bytes.len());
            println!("verifying_key: {} ({} bytes)", vk_path.display(), vk_bytes.len());
            println!("vk_blake3:     {}", fp);
            println!("public_inputs_expected: {}", inputs);

            if print_program_hash {
                let ph = expected_program_hash_bytes();
                println!("program_hash_hex: {}", hex::encode(ph));
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
        Validate::Yes,
        Validate::Yes, // Ark 0.4 requires Compress and Validate; using Yes/Yes with compressed bytes
    )
    .or_else(|_| {
        VerifyingKey::<Bls12_381>::deserialize_with_mode(
            &mut ark_std::io::Cursor::new(&bytes),
            Compress::No,
            Validate::Yes,
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
        Validate::Yes,
        Validate::Yes,
    )
    .or_else(|_| {
        ProvingKey::<Bls12_381>::deserialize_with_mode(
            &mut ark_std::io::Cursor::new(&bytes),
            Compress::No,
            Validate::Yes,
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
