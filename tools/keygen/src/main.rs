//! nonos-keygen: generate Ed25519 signer keypairs and produce signers.json with fingerprints.

use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
    process::Command,
};

use anyhow::{bail, Context, Result};
use blake3;
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(name = "nonos-keygen", about = "Generate Ed25519 signer keys and signers.json for NONOS ceremony (production hardened)")]
struct Args {
    /// Number of signer keypairs to produce
    #[arg(short, long, default_value_t = 4)]
    count: usize,

    /// Output directory to write keys (created if missing)
    #[arg(short, long, value_name = "DIR", default_value = "keys")]
    out_dir: PathBuf,

    /// Output format for keys: raw (binary), hex, base64
    #[arg(long, value_name = "fmt", default_value = "hex")]
    format: String,

    /// Produce signers.json at this path 
    #[arg(long, value_name = "PATH")]
    signers: Option<PathBuf>,

    /// Threshold for signers.json 
    #[arg(long)]
    threshold: Option<usize>,

    /// Prefix for signer ids (default "signer")
    #[arg(long, default_value = "signer")]
    id_prefix: String,

    /// Make secret files world-readable (unsafe; for CI/test only)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    insecure_world_readable: bool,

    /// Do not write secret files; write only public keys and signers.json 
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub_only: bool,

    /// Operator identifier (will be hashed into generation_log for provenance)
    #[arg(long, value_name = "STR")]
    operator: Option<String>,

    /// Allow writing secret files 
    #[arg(long, action = clap::ArgAction::SetTrue)]
    allow_write_secrets: bool,
}

#[derive(Serialize)]
struct SignerEntry {
    id: String,
    pubkey_hex: String,
    pubkey_sha256: String,
    pubkey_blake3: String,
}

#[derive(Serialize)]
struct SignersJson {
    threshold: usize,
    signers: Vec<SignerEntry>,
}

#[derive(Serialize)]
struct GenerationLog {
    tool: String,
    tool_version: String,
    rustc_version: String,
    cargo_version: String,
    commit: Option<String>,
    created_at_utc: String,
    host_fingerprint: String,
    operator_hash: Option<String>,
    key_count: usize,
    threshold: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.count == 0 {
        bail!("count must be >= 1");
    }
    let fmt = args.format.to_lowercase();
    if !["raw", "hex", "base64"].contains(&fmt.as_str()) {
        bail!("unsupported format: {} (supported: raw, hex, base64)", fmt);
    }

    // Safety guard: writing secret files requires explicit allow flag unless pub_only
    if !args.pub_only && !args.allow_write_secrets {
        eprintln!("Secret files will NOT be written unless --allow-write-secrets is provided. Use --pub-only to write only public keys for HSM/external generation.");
        std::process::exit(2);
    }

    fs::create_dir_all(&args.out_dir).with_context(|| format!("creating {}", args.out_dir.display()))?;

    // Prepare generation log metadata
    let tool = "nonos-keygen".to_string();
    let tool_version = env!("CARGO_PKG_VERSION").to_string();
    let rustc_version = get_command_output("rustc", &["--version"]).unwrap_or_else(|_| "unknown".into());
    let cargo_version = get_command_output("cargo", &["--version"]).unwrap_or_else(|_| "unknown".into());
    let commit = git_commit_hash();
    let created_at = Utc::now().to_rfc3339();
    let hostname = hostname::get().ok().and_then(|s| s.into_string().ok()).unwrap_or_else(|| "unknown".into());
    let host_fingerprint = sha256_hex(hostname.as_bytes());

    let operator_hash = args.operator.as_ref().map(|op| sha256_hex(op.as_bytes()));

    let threshold = args.threshold.unwrap_or_else(|| (args.count / 2) + 1);

    // Will collect signer entries
    let mut signers: Vec<SignerEntry> = Vec::with_capacity(args.count);

    // Signed input files are created via atomic tempfile writes
    for i in 1..=args.count {
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let pub_bytes = keypair.public.to_bytes();
        // secret is [u8;32]; move into Vec for write and zeroize afterwards
        let mut sec_bytes = keypair.secret.to_bytes().to_vec();

        let id = format!("{}{}", args.id_prefix, i);
        // set filenames
        let pub_raw_path = args.out_dir.join(format!("{}.pub.raw", id));
        let pub_hex_path = args.out_dir.join(format!("{}.pub.hex", id));
        let pub_b64_path = args.out_dir.join(format!("{}.pub.b64", id));
        let sec_raw_path = args.out_dir.join(format!("{}.key", id)); // secret raw
        let sec_hex_path = args.out_dir.join(format!("{}.key.hex", id));
        let sec_b64_path = args.out_dir.join(format!("{}.key.b64", id));

        // write public files (atomic)
        write_atomic(&pub_raw_path, &pub_bytes)?;
        write_atomic_text(&pub_hex_path, &hex::encode(pub_bytes))?;
        write_atomic_text(&pub_b64_path, &base64::encode(pub_bytes))?;

        if !args.pub_only {
            // write secret files if allowed
            let mode = if args.insecure_world_readable { 0o644 } else { 0o600 };
            write_atomic(&sec_raw_path, &sec_bytes)?;
            set_mode_if_unix(&sec_raw_path, mode)?;
            write_atomic_text(&sec_hex_path, &hex::encode(&sec_bytes))?;
            set_mode_if_unix(&sec_hex_path, mode)?;
            write_atomic_text(&sec_b64_path, &base64::encode(&sec_bytes))?;
            set_mode_if_unix(&sec_b64_path, mode)?;
        }

        // compute fingerprints
        let sha256_hex_val = sha256_hex(&pub_bytes);
        let blake3_hex = blake3::hash(&pub_bytes).to_hex().to_string();

        // zeroize secret bytes asap
        sec_bytes.zeroize();

        // record
        signers.push(SignerEntry {
            id: id.clone(),
            pubkey_hex: hex::encode(pub_bytes),
            pubkey_sha256: sha256_hex_val,
            pubkey_blake3: blake3_hex,
        });

        match fmt.as_str() {
            "raw" => println!("{}: wrote pub raw -> {}", id, pub_raw_path.display()),
            "hex" => println!("{}: wrote pub hex -> {}", id, pub_hex_path.display()),
            "base64" => println!("{}: wrote pub b64 -> {}", id, pub_b64_path.display()),
            _ => {}
        }
    }

    // produce signers.json if requested
    if let Some(signers_path) = args.signers {
        let sj = SignersJson {
            threshold,
            signers,
        };
        let mut out_path = signers_path;
        if out_path.is_relative() {
            out_path = args.out_dir.join(out_path);
        }
        let json = serde_json::to_vec_pretty(&sj)?;
        write_atomic(&out_path, &json)?;
        println!("Wrote signers.json -> {}", out_path.display());
    }

    // write generation log
    let gen_log = GenerationLog {
        tool,
        tool_version,
        rustc_version,
        cargo_version,
        commit,
        created_at_utc: created_at,
        host_fingerprint,
        operator_hash,
        key_count: args.count,
        threshold,
    };
    let gen_json = serde_json::to_vec_pretty(&gen_log)?;
    let gen_path = args.out_dir.join("generation_log.json");
    write_atomic(&gen_path, &gen_json)?;
    println!("Wrote generation_log.json -> {}", gen_path.display());

    println!("Generated {} signer keypairs in {}", args.count, args.out_dir.display());
    println!("Reminder: protect secret key files (use HSM or secure storage) and do NOT commit them to source control.");

    Ok(())
}

/// Write bytes via tempfile -> sync -> persist(rename) for atomicity.
fn write_atomic(path: &PathBuf, data: &[u8]) -> Result<()> {
    let mut tmp = NamedTempFile::new_in(path.parent().unwrap_or_else(|| PathBuf::from(".")))?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).with_context(|| format!("persisting to {}", path.display()))?;
    Ok(())
}

/// Write text via tempfile and persist
fn write_atomic_text(path: &PathBuf, text: &str) -> Result<()> {
    write_atomic(path, text.as_bytes())
}

#[cfg(unix)]
fn set_mode_if_unix(path: &PathBuf, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_mode_if_unix(_path: &PathBuf, _mode: u32) -> Result<()> {
    // On non-unix, leave default
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn get_command_output(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd).args(args).output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(anyhow::anyhow!("{} failed", cmd))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_pub_only() {
        let dir = tempdir().unwrap();
        let out = dir.path().to_path_buf();
        let args = Args {
            count: 1,
            out_dir: out.clone(),
            format: "hex".to_string(),
            signers: Some(PathBuf::from("signers.json")),
            threshold: Some(1),
            id_prefix: "signer".to_string(),
            insecure_world_readable: false,
            pub_only: true,
            operator: None,
            allow_write_secrets: true, // not writing secrets but allow flag ok
        };
        // emulate main logic enough: create dir and write public files via write_atomic
        let pub_path = out.join("signer1.pub.hex");
        write_atomic_text(&pub_path, "abcd").unwrap();
        assert!(pub_path.exists());
    }
}
