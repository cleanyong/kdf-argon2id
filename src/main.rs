use std::error::Error;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use clap::Parser;
use rpassword::prompt_password;

const DEFAULT_SHARED_SALT: [u8; 16] = *b"argon2id-shared!";

#[derive(Parser, Debug)]
#[command(
    name = "kdf-argon2id",
    about = "Derive an encryption key from a human-memorable password using Argon2id"
)]
struct Args {
    /// Memory cost in KiB
    #[arg(long, default_value = "65536")]
    mem_kib: u32,

    /// Number of iterations (time cost)
    #[arg(long, default_value = "3")]
    iterations: u32,

    /// Degree of parallelism (lanes)
    #[arg(long, default_value = "1")]
    lanes: u32,

    /// Output key length in bytes
    #[arg(long, default_value = "32")]
    out_len: u32,

    /// Salt as hex (if omitted, a fixed shared 16-byte salt is used)
    #[arg(long)]
    salt_hex: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let password = prompt_password("Enter password: ")?;

    let salt = match args.salt_hex {
        Some(hex) => parse_hex(&hex)?,
        None => DEFAULT_SHARED_SALT.to_vec(),
    };

    let params = Params::new(
        args.mem_kib,
        args.iterations,
        args.lanes,
        Some(args.out_len as usize),
    )
    .map_err(|e| format!("invalid Argon2 parameters: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = vec![0u8; args.out_len as usize];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut derived)
        .map_err(|e| format!("argon2 derivation failed: {e}"))?;

    println!("Algorithm: Argon2id v0x13");
    println!(
        "Params: mem_kib={} iterations={} lanes={} out_len={}",
        args.mem_kib, args.iterations, args.lanes, args.out_len
    );
    println!("Salt (hex): {}", hex::encode(&salt));
    println!(
        "Derived key (hex, {} chars): {}",
        derived.len() * 2,
        hex::encode(&derived)
    );
    println!(
        "Derived key (base64): {}",
        base64::engine::general_purpose::STANDARD.encode(&derived)
    );

    Ok(())
}

fn parse_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if input.len() % 2 != 0 {
        return Err("salt hex must have even length".into());
    }
    let bytes = hex::decode(input)?;
    if bytes.is_empty() {
        return Err("salt cannot be empty".into());
    }
    Ok(bytes)
}
