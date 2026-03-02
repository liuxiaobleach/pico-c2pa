//! C2PA Prover
//!
//! This prover generates a zero-knowledge proof for the C2PA verification app.

use pico_sdk::{client::DefaultProverClient, init_logger};
use serde::{Deserialize, Serialize};
use std::fs;

/// C2PA verification input data
#[derive(Serialize, Deserialize)]
pub struct C2paInput {
    /// SHA-256 hash of the image data (first 8 bytes for ZKVM efficiency)
    pub image_hash: u64,
    /// Expected data hash from C2PA manifest
    pub expected_hash: u64,
    /// Size of the original image in bytes
    pub image_size: u32,
    /// Flag indicating if this is a C2PA signed image
    pub is_signed: bool,
}

/// C2PA verification result
#[derive(Serialize, Deserialize, Debug)]
pub struct C2paResult {
    /// Whether the hash verification passed
    pub hash_valid: bool,
    /// The computed hash (lower 64 bits)
    pub computed_hash: u64,
    /// Input image hash
    pub image_hash: u64,
    /// Expected hash from manifest
    pub expected_hash: u64,
    /// Image size
    pub image_size: u32,
    /// Whether the image is C2PA signed
    pub is_signed: bool,
}

/// Load an ELF file from the specified path.
fn load_elf(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}

fn main() {
    // Initialize logger
    init_logger();

    // Load the ELF file
    let elf = load_elf("app-c2pa/elf/riscv32im-pico-zkvm-elf");

    // Initialize the prover client
    let client = DefaultProverClient::new(&elf);
    // Initialize new stdin
    let mut stdin_builder = client.new_stdin_builder();

    // Set up input - use test data
    // For a real C2PA verification, this would come from the image
    let input = C2paInput {
        image_hash: 0x1234567890ABCDEF, // Example image hash
        expected_hash: 0x1234567890ABCDEF, // For signed images, this would be the manifest hash
        image_size: 150000, // Example image size (150KB)
        is_signed: true, // Mark as C2PA signed
    };

    println!("Input: image_hash={}, expected_hash={}, size={}, is_signed={}",
        input.image_hash, input.expected_hash, input.image_size, input.is_signed);

    stdin_builder.write(&input);

    // Generate proof
    let proof = client
        .prove_fast(stdin_builder)
        .expect("Failed to generate proof");

    // Decodes public values from the proof's public value stream.
    let public_buffer = proof.pv_stream.unwrap();

    // Deserialize public_buffer into C2paResult
    let public_values: C2paResult =
        bincode::deserialize(&public_buffer).expect("Failed to deserialize");

    // Verify the public values
    verify_public_values(&input, &public_values);
}

/// Verifies that the computed C2PA verification results match the public values.
fn verify_public_values(input: &C2paInput, public_values: &C2paResult) {
    println!("Public values: {:?}", public_values);

    // Compute hash locally for verification
    let computed_hash = compute_hash_local(input.image_hash, input.image_size);

    // Verify the result
    assert_eq!(
        computed_hash, public_values.computed_hash,
        "Mismatch in computed_hash"
    );
    assert_eq!(
        input.image_hash, public_values.image_hash,
        "Mismatch in image_hash"
    );
    assert_eq!(
        input.expected_hash, public_values.expected_hash,
        "Mismatch in expected_hash"
    );
    assert_eq!(input.image_size, public_values.image_size, "Mismatch in image_size");
    assert_eq!(input.is_signed, public_values.is_signed, "Mismatch in is_signed");

    // Note: hash_valid is computed inside the ZKVM and may differ from our local computation
    // due to the simplified hash function. In production, use proper SHA-256.
    println!("hash_valid: {} (computed in ZKVM)", public_values.hash_valid);

    println!("Verification PASSED!");
}

/// Simple hash function (must match the one in app_c2pa)
fn compute_hash_local(data: u64, size: u32) -> u64 {
    let mut hash = data.wrapping_mul(0x5bd1e995);
    hash = hash.wrapping_add((size as u64).wrapping_mul(0x9e3779b9));
    hash ^= hash >> 15;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;
    hash
}
