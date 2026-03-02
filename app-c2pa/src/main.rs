//! C2PA Verification App for Pico ZKVM
//!
//! This is a simplified C2PA verification that runs on the Pico ZKVM.
//! It takes input data and performs basic hash verification operations.

#![no_main]

pico_sdk::entrypoint!(main);

use pico_sdk::io::{commit, read_as};
use serde::{Deserialize, Serialize};

/// C2PA verification input data
/// In a real implementation, this would contain the image data or its hash
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
#[derive(Serialize, Deserialize)]
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

/// Simple hash function for verification
/// In production, this would use proper SHA-256
fn compute_hash(data: u64, size: u32) -> u64 {
    // Simplified hash computation for ZKVM
    // Uses a simple mixing function
    let mut hash = data.wrapping_mul(0x5bd1e995);
    hash = hash.wrapping_add((size as u64).wrapping_mul(0x9e3779b9));
    hash ^= hash >> 15;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;
    hash
}

pub fn main() {
    // Read C2PA input data from the environment
    let input: C2paInput = read_as();

    // Compute hash from input data
    let computed_hash = compute_hash(input.image_hash, input.image_size);

    // Verify hash
    let hash_valid = if input.is_signed {
        // For signed images, verify against expected hash
        computed_hash == input.expected_hash
    } else {
        // For unsigned images, just check that hash is non-zero
        computed_hash != 0
    };

    // Create result
    let result = C2paResult {
        hash_valid,
        computed_hash,
        image_hash: input.image_hash,
        expected_hash: input.expected_hash,
        image_size: input.image_size,
        is_signed: input.is_signed,
    };

    // Commit the result as public values in the Pico proof
    commit(&result);
}
