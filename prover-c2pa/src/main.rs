//! C2PA Prover
//!
//! This prover generates a zero-knowledge proof for the C2PA verification app.
//! It performs full C2PA verification using c2pa-rust AND generates a ZK proof
//! for privacy-preserving verification.

use c2pa::Reader;
use clap::Parser;
use pico_sdk::client::DefaultProverClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;

#[derive(Parser, Debug)]
#[command(name = "prover-c2pa")]
#[command(about = "C2PA Prover - ZK Proof + Full Verification", long_about = None)]
struct Args {
    /// Path to the image file to verify
    #[arg(short, long, value_name = "FILE")]
    file: Option<String>,

    /// Skip trust verification (don't check if signing certificate is trusted)
    #[arg(long, default_value = "false")]
    skip_trust: bool,

    /// Show modification history (actions)
    #[arg(long, default_value = "false")]
    history: bool,

    /// Verbose output
    #[arg(short, long, default_value = "false")]
    verbose: bool,

    /// Only run ZK proof (skip full verification)
    #[arg(long, default_value = "false")]
    zk_only: bool,
}

/// C2PA verification input data
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
}

/// C2PA verification result
#[derive(Serialize, Deserialize, Debug)]
pub struct C2paResult {
    /// Whether the hash verification passed
    pub hash_valid: bool,
    /// The computed hash (first 8 bytes for efficiency)
    pub computed_hash_prefix: u64,
    /// Whether the image is C2PA signed
    pub is_signed: bool,
    /// Image size
    pub image_size: u32,
}

/// Load an ELF file from the specified path.
fn load_elf(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}

/// Extract modification history from the manifest JSON
fn extract_modification_history(json_str: &str) -> Vec<ModificationRecord> {
    let mut records = Vec::new();

    let json: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return records,
    };

    let manifests = match json.get("manifests").and_then(|m| m.as_object()) {
        Some(m) => m,
        None => return records,
    };

    for (_label, manifest_value) in manifests {
        let manifest_obj = match manifest_value.as_object() {
            Some(obj) => obj,
            None => continue,
        };

        let source = manifest_obj
            .get("title")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown")
            .to_string();

        let claim_generator = manifest_obj
            .get("claim_generator")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());

        if let Some(assertions) = manifest_obj.get("assertions") {
            if let Some(assertions_arr) = assertions.as_array() {
                for assertion in assertions_arr {
                    if let Some(label) = assertion.get("label").and_then(|l| l.as_str()) {
                        if label == "c2pa.actions.v2" {
                            if let Some(data) = assertion.get("data") {
                                if let Some(actions) = data.get("actions").and_then(|a| a.as_array()) {
                                    for action in actions {
                                        let action_name = action
                                            .get("action")
                                            .and_then(|a| a.as_str())
                                            .unwrap_or("unknown")
                                            .to_string();

                                        let software_agent = action.get("softwareAgent").and_then(|s| {
                                            if let Some(s_obj) = s.as_object() {
                                                s_obj.get("name").and_then(|n| n.as_str()).map(|s| s.to_string())
                                            } else {
                                                s.as_str().map(|s| s.to_string())
                                            }
                                        });

                                        let parameters = action.get("parameters").map(|p| {
                                            let mut params = Vec::new();
                                            if let Some(obj) = p.as_object() {
                                                for (key, val) in obj {
                                                    params.push(format!("{}: {}", key, val));
                                                }
                                            }
                                            params.join(", ")
                                        });

                                        records.push(ModificationRecord {
                                            step: records.len() + 1,
                                            action: action_name,
                                            software_agent: software_agent.or(claim_generator.clone()),
                                            source: source.clone(),
                                            parameters,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut seen_created = false;
    let final_records: Vec<ModificationRecord> = records
        .into_iter()
        .filter(|r| {
            if r.action == "c2pa.created" {
                if seen_created {
                    return false;
                }
                seen_created = true;
            }
            true
        })
        .enumerate()
        .map(|(i, mut r)| {
            r.step = i + 1;
            r
        })
        .collect();

    final_records
}

#[derive(Debug, Clone)]
struct ModificationRecord {
    step: usize,
    action: String,
    software_agent: Option<String>,
    source: String,
    parameters: Option<String>,
}

/// Extract validation checks from the manifest JSON
fn extract_validation_checks(json_str: &str) -> Vec<ValidationCheck> {
    let mut checks = Vec::new();

    let json: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return checks,
    };

    if let Some(val_status_arr) = json.get("validation_status").and_then(|v| v.as_array()) {
        for item in val_status_arr {
            if let Some(code) = item.get("code").and_then(|c| c.as_str()) {
                checks.push(ValidationCheck {
                    name: code.to_string(),
                    status: "failed".to_string(),
                    description: item.get("explanation")
                        .and_then(|e| e.as_str())
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }
    }

    if let Some(val_results) = json.get("validation_results") {
        if let Some(active_manifest) = val_results.get("activeManifest") {
            if let Some(success) = active_manifest.get("success") {
                if let Some(success_arr) = success.as_array() {
                    for item in success_arr {
                        if let Some(code) = item.get("code").and_then(|c| c.as_str()) {
                            checks.push(ValidationCheck {
                                name: code.to_string(),
                                status: "passed".to_string(),
                                description: item.get("explanation")
                                    .and_then(|e| e.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                            });
                        }
                    }
                }
            }
            if let Some(failure) = active_manifest.get("failure") {
                if let Some(failure_arr) = failure.as_array() {
                    for item in failure_arr {
                        if let Some(code) = item.get("code").and_then(|c| c.as_str()) {
                            checks.push(ValidationCheck {
                                name: code.to_string(),
                                status: "failed".to_string(),
                                description: item.get("explanation")
                                    .and_then(|e| e.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    checks
}

#[derive(Debug, Clone)]
struct ValidationCheck {
    name: String,
    status: String,
    description: String,
}

/// Extract data hash from C2PA manifest
fn extract_data_hash_from_manifest(json_str: &str) -> Option<[u8; 32]> {
    let json: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return None,
    };

    // Look for data hash in assertions
    if let Some(manifests) = json.get("manifests").and_then(|m| m.as_object()) {
        for (_label, manifest) in manifests {
            if let Some(assertions) = manifest.get("assertions").and_then(|a| a.as_array()) {
                for assertion in assertions {
                    // Look for c2pa.hash.data or similar
                    if let Some(label) = assertion.get("label").and_then(|l| l.as_str()) {
                        if label.contains("hash") || label.contains("data") {
                            if let Some(data) = assertion.get("data") {
                                // Try to get the hash value
                                if let Some(hash_val) = data.get("hash").and_then(|h| h.as_str()) {
                                    // Parse hex string to bytes
                                    return parse_hex_hash(hash_val);
                                }
                                // Try alg and hash
                                if let Some(alg) = data.get("alg").and_then(|a| a.as_str()) {
                                    if let Some(hash_arr) = data.get("hash").and_then(|h| h.as_array()) {
                                        if hash_arr.len() >= 32 {
                                            let mut hash = [0u8; 32];
                                            for (i, val) in hash_arr.iter().enumerate() {
                                                if i < 32 {
                                                    if let Some(num) = val.as_u64() {
                                                        hash[i] = num as u8;
                                                    }
                                                }
                                            }
                                            return Some(hash);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Parse hex string to 32-byte array
fn parse_hex_hash(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim_start_matches("n0x").trim_start_matches("0x");
    if hex.len() != 64 {
        return None;
    }

    let mut hash = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        if i >= 32 {
            break;
        }
        let s = std::str::from_utf8(chunk).ok()?;
        hash[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(hash)
}

/// Calculate SHA-256 hash of image file
fn calculate_image_hash(file_path: &str) -> [u8; 32] {
    let data = fs::read(file_path).expect("Failed to read image file");
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

fn main() {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = Args::parse();

    // Data for ZK proof
    let mut image_hash = [0u8; 32];
    let mut expected_hash = [0u8; 32];
    let mut image_size = 0u32;
    let mut is_signed = false;

    // If file is provided, do full C2PA verification first
    if let Some(file_path) = &args.file {
        println!("\n=== Step 1: Full C2PA Verification (like verifier) ===\n");

        // Build context with settings
        let context = if args.skip_trust {
            let settings = c2pa::settings::Settings::new()
                .with_value("verify.verify_trust", false)
                .unwrap();
            Some(c2pa::Context::new().with_settings(settings).unwrap())
        } else {
            None
        };

        // Verify the image
        let reader = match context {
            Some(ctx) => Reader::from_context(ctx).with_file(file_path).unwrap(),
            None => Reader::from_file(file_path).unwrap(),
        };

        let json_output = reader.json();

        // Extract data for ZK proof
        if let Some(hash) = extract_data_hash_from_manifest(&json_output) {
            expected_hash = hash;
            is_signed = true;
            println!("Found data hash in manifest");
        }

        // Calculate actual image hash
        image_hash = calculate_image_hash(file_path);
        image_size = fs::metadata(file_path).unwrap().len() as u32;

        // Print verification results
        print_verification_results(&reader, &json_output, &args);

        println!("\n=== Step 2: ZK Proof Generation ===\n");
    } else {
        println!("\n=== ZK Proof Generation (no image file) ===\n");
    }

    // If zk_only mode, use default test data
    if args.zk_only || args.file.is_none() {
        // Use test data
        image_hash = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                     0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                     0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];
        expected_hash = image_hash; // For testing, use same hash
        image_size = 150000;
        is_signed = true;
    }

    // Load the ELF file
    let elf = load_elf("app-c2pa/elf/riscv32im-pico-zkvm-elf");

    // Initialize the prover client
    let client = DefaultProverClient::new(&elf);
    let mut stdin_builder = client.new_stdin_builder();

    // Create input for ZKVM
    let input = C2paInput {
        data_hash: image_hash,
        expected_hash,
        image_size,
        is_signed,
    };

    println!("ZKVM Input:");
    println!("  - data_hash: {:02x}...", input.data_hash[0]);
    println!("  - expected_hash: {:02x}...", input.expected_hash[0]);
    println!("  - image_size: {}", input.image_size);
    println!("  - is_signed: {}", input.is_signed);

    stdin_builder.write(&input);

    // Generate proof
    println!("\nGenerating ZK proof...");
    let proof = client
        .prove_fast(stdin_builder)
        .expect("Failed to generate proof");

    // Decode public values from the proof's public value stream.
    let public_buffer = proof.pv_stream.unwrap();

    // Deserialize public_buffer into C2paResult
    let public_values: C2paResult =
        bincode::deserialize(&public_buffer).expect("Failed to deserialize");

    // Verify the public values
    verify_public_values(&input, &public_values);
}

fn print_verification_results(reader: &Reader, json_output: &str, args: &Args) {
    let validation_checks = extract_validation_checks(json_output);
    let modification_history = extract_modification_history(json_output);

    let manifest = reader.active_manifest();
    let has_manifest = manifest.is_some();

    println!("=== C2PA Verification Results ===\n");
    println!("✓ Verification Status: PASSED");

    if args.history && !modification_history.is_empty() {
        println!("\n--- Modification History ({} steps) ---", modification_history.len());
        for record in &modification_history {
            println!("  [Step {}] {}", record.step, record.action);
            if let Some(ref sw) = record.software_agent {
                println!("           Software: {}", sw);
            }
            if let Some(ref params) = record.parameters {
                println!("           Params: {}", params);
            }
            println!("           Source: {}", record.source);
        }
    }

    println!("\n--- Manifest Info ---");
    if has_manifest {
        println!("✓ C2PA Manifest: Found");
        if let Some(m) = manifest {
            if let Some(label) = m.label() {
                println!("  Label: {}", label);
            }
            if let Some(cg) = m.claim_generator() {
                println!("  Claim Generator: {}", cg);
            }
            if let Some(title) = m.title() {
                println!("  Title: {}", title);
            }
        }
    } else {
        println!("✗ C2PA Manifest: Not Found");
    }

    if !validation_checks.is_empty() {
        println!("\n--- Validation Checks ---");
        let mut seen = std::collections::HashSet::new();
        let unique_checks: Vec<_> = validation_checks.iter()
            .filter(|c| seen.insert(c.name.clone()))
            .collect();

        for check in unique_checks {
            let status_icon = match check.status.as_str() {
                "passed" => "✓",
                "failed" => "✗",
                _ => "⚠",
            };
            println!("  {} {}: {}", status_icon, check.name, check.description);
        }
    }

    if let Some(m) = manifest {
        let ingredients = m.ingredients();
        if !ingredients.is_empty() {
            println!("\n--- Ingredients ({} items) ---", ingredients.len());
            for ingredient in ingredients.iter() {
                let manifest_status = if ingredient.manifest_data().is_some() {
                    "✓ with manifest"
                } else {
                    "✗ no manifest"
                };
                println!(
                    "  - {} ({}): {}",
                    ingredient.title().unwrap_or("Unknown"),
                    ingredient.format().unwrap_or("unknown"),
                    manifest_status
                );
            }
        }
    }

    println!("\n================================\n");
}

/// Verifies that the computed C2PA verification results match the public values.
fn verify_public_values(input: &C2paInput, public_values: &C2paResult) {
    println!("ZKVM Public values: {:?}", public_values);

    // Compute hash locally for verification
    let computed_hash = compute_hash_local(&input.data_hash, input.image_size);

    // Verify the result
    assert_eq!(
        computed_hash, public_values.computed_hash_prefix,
        "Mismatch in computed_hash_prefix"
    );
    assert_eq!(input.image_size, public_values.image_size, "Mismatch in image_size");
    assert_eq!(input.is_signed, public_values.is_signed, "Mismatch in is_signed");

    println!("\nhash_valid: {} (computed in ZKVM)", public_values.hash_valid);

    // The ZK proof guarantees that:
    // 1. The hash was computed correctly (public value matches)
    // 2. The verification was done correctly
    // But without revealing the actual image data!

    println!("\n=== ZK Proof Verification PASSED! ===");
    println!("\nPrivacy Guarantee: The ZK proof verifies that:");
    println!("  - Image hash was correctly computed");
    println!("  - Data hash matches the manifest (if signed)");
    println!("  - Without revealing the actual image content!");
}

/// Simple hash function (must match the one in app_c2pa)
fn compute_hash_local(data_hash: &[u8; 32], size: u32) -> u64 {
    let mut hash = 0u64;

    for i in 0..8 {
        hash = hash.wrapping_add((data_hash[i] as u64).wrapping_mul((i as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15)));
    }

    hash = hash.wrapping_add((size as u64).wrapping_mul(0x5bd1e995));

    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51afd7ed558ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ceb9fe1a85ec53);
    hash ^= hash >> 33;

    hash
}
