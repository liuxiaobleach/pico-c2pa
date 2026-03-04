//! C2PA Verification App for Pico ZKVM
//!
//! This is a C2PA verification app that runs on Pico ZKVM.
//! It performs data hash verification in a privacy-preserving way.

#![no_main]

pico_sdk::entrypoint!(main);

use pico_sdk::io::{commit, read_as};
use serde::{Deserialize, Serialize};

/// Maximum number of actions we can verify
const MAX_ACTIONS: usize = 16;

/// A single modification action
#[derive(Serialize, Deserialize, Clone)]
pub struct C2paAction {
    /// Action type (e.g., "c2pa.created", "c2pa.cropped")
    pub action: [u8; 32],  // Fixed-size for ZK efficiency
}

/// C2PA verification input data
/// This data comes from the C2PA manifest and is used for verification
#[derive(Serialize, Deserialize)]
pub struct C2paInput {
    /// SHA-256 hash of the image data (full 32 bytes)
    pub data_hash: [u8; 32],
    /// Expected data hash from C2PA manifest
    pub expected_hash: [u8; 32],
    /// Size of the original image in bytes
    pub image_size: u32,
    /// Flag indicating if this is a C2PA signed image
    pub is_signed: bool,
    /// Number of actions
    pub action_count: u8,
    /// Actions (modification history)
    pub actions: [C2paAction; MAX_ACTIONS],
    /// Expected hash of actions (for verification)
    pub expected_actions_hash: [u8; 32],
}

/// C2PA verification result (public values)
#[derive(Serialize, Deserialize)]
pub struct C2paResult {
    /// Whether the hash verification passed
    pub hash_valid: bool,
    /// The computed hash (first 8 bytes for efficiency)
    pub computed_hash_prefix: u64,
    /// Whether the image is C2PA signed
    pub is_signed: bool,
    /// Image size
    pub image_size: u32,
    /// Number of actions verified
    pub action_count: u8,
    /// Whether actions are valid
    pub actions_valid: bool,
}

/// Simple comparison function - compares two 32-byte arrays
/// Returns true if they match
fn compare_hashes(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for i in 0..32 {
        result |= a[i] ^ b[i];
    }
    result == 0
}

/// Compute a simple hash of the input for verification
/// In production, this would use SHA-256
/// For ZKVM, we use a simple rolling hash based on the input
fn compute_hash(data_hash: &[u8; 32], size: u32) -> u64 {
    // Simple hash computation for ZKVM efficiency
    // Uses the first 8 bytes of data_hash combined with size
    let mut hash = 0u64;

    // Mix the first 8 bytes of data_hash
    for i in 0..8 {
        hash = hash.wrapping_add((data_hash[i] as u64).wrapping_mul((i as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15)));
    }

    // Mix the size
    hash = hash.wrapping_add((size as u64).wrapping_mul(0x5bd1e995));

    // Final mixing
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51afd7ed558ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ceb9fe1a85ec53);
    hash ^= hash >> 33;

    hash
}

/// Convert action string to fixed-size array
fn action_to_bytes(action: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let len = action.len().min(32);
    bytes[..len].copy_from_slice(action.as_bytes().trim_ascii());
    bytes
}

/// Compute hash of actions - returns a 32-byte array
fn compute_actions_hash(actions: &[C2paAction], count: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];

    if count == 0 {
        return hash;
    }

    // Simple hash computation for ZKVM efficiency
    // Mix all action bytes into the hash
    for (i, action) in actions.iter().enumerate() {
        if i >= count as usize {
            break;
        }
        for (j, &byte) in action.action.iter().enumerate() {
            hash[j] = hash[j].wrapping_add(byte.wrapping_mul((i as u8 + 1).wrapping_mul(0x9e)));
        }
    }

    // Final mixing
    let mut mixed = 0u64;
    for (i, &byte) in hash.iter().enumerate() {
        mixed = mixed.wrapping_add((byte as u64).wrapping_mul((i as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15)));
    }

    // Write mixed hash back
    for i in 0..32 {
        hash[i] = (mixed >> (i * 2)) as u8;
    }

    hash
}

/// Verify actions - compare computed hash with expected hash
fn verify_actions(actions: &[C2paAction], count: u8, expected_hash: &[u8; 32]) -> bool {
    if count == 0 && expected_hash == &[0u8; 32] {
        return true; // No actions is valid
    }

    // Compute hash of provided actions
    let computed_hash = compute_actions_hash(actions, count);

    // Compare with expected hash
    let mut result = 0u8;
    for i in 0..32 {
        result |= computed_hash[i] ^ expected_hash[i];
    }

    result == 0
}

pub fn main() {
    // Read C2PA input data from the environment
    let input: C2paInput = read_as();

    // Compute hash from input data
    let computed_hash_prefix = compute_hash(&input.data_hash, input.image_size);

    // Verify hash
    let hash_valid = if input.is_signed {
        // For signed images, verify data hash matches expected hash
        compare_hashes(&input.data_hash, &input.expected_hash)
    } else {
        // For unsigned images, just check that hash is non-zero
        computed_hash_prefix != 0
    };

    // Verify actions (modification history) - compare computed hash with expected
    let actions_valid = if input.is_signed {
        // For signed images, verify actions hash matches expected
        verify_actions(&input.actions, input.action_count, &input.expected_actions_hash)
    } else {
        // For unsigned images, no actions to verify
        input.action_count == 0
    };

    // Create result
    let result = C2paResult {
        hash_valid,
        computed_hash_prefix,
        is_signed: input.is_signed,
        image_size: input.image_size,
        action_count: input.action_count,
        actions_valid,
    };

    // Commit the result as public values in the Pico proof
    // These values are revealed to the verifier without exposing the private input
    commit(&result);
}
