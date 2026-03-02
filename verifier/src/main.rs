//! C2PA Signature Verification Tool
//!
//! This program verifies C2PA-signed images and displays validation results.

use base64::{engine::general_purpose::STANDARD, Engine};
use c2pa::{Reader, Result};
use clap::Parser;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::Value;
use std::io::Cursor;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "verifier")]
#[command(about = "C2PA Signature Image Verifier", long_about = None)]
struct Args {
    /// Path to the image file to verify
    #[arg(short, long, value_name = "FILE")]
    file: Option<PathBuf>,

    /// Base64 encoded image data to verify
    #[arg(long, value_name = "BASE64")]
    base64: Option<String>,

    /// Path to a trust settings file (optional)
    #[arg(short, long, value_name = "FILE")]
    settings: Option<PathBuf>,

    /// Path to a trust anchors PEM file (optional)
    #[arg(short, long, value_name = "FILE")]
    trust_anchors: Option<PathBuf>,

    /// Skip trust verification (don't check if signing certificate is trusted)
    #[arg(long, default_value = "false")]
    skip_trust: bool,

    /// Show modification history (actions)
    #[arg(long, default_value = "false")]
    history: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerificationResult {
    pub is_valid: bool,
    pub has_manifest: bool,
    pub manifest_info: Option<ManifestInfo>,
    pub ingredients: Vec<IngredientInfo>,
    pub json_output: Option<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub modification_history: Vec<ModificationRecord>,
    pub validation_checks: Vec<ValidationCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCheck {
    pub name: String,
    pub status: String,  // "passed", "failed", "warning"
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ManifestInfo {
    pub label: Option<String>,
    pub claim_generator: Option<String>,
    pub title: Option<String>,
    pub json: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IngredientInfo {
    pub title: Option<String>,
    pub format: Option<String>,
    pub has_manifest: bool,
}

/// Represents a single modification record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModificationRecord {
    pub step: usize,
    pub action: String,
    pub software_agent: Option<String>,
    pub source: String,  // "active_manifest" or ingredient title
    pub parameters: Option<String>,
}

fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = Args::parse();

    // Check if we have either file or base64 input
    let has_file = args.file.is_some();
    let has_base64 = args.base64.is_some();

    if !has_file && !has_base64 {
        eprintln!("Error: No image file or base64 data specified");
        eprintln!("Usage: verifier --file <image_file>");
        eprintln!("   or: verifier --base64 <base64_data>");
        std::process::exit(1);
    }

    if has_file && has_base64 {
        eprintln!("Error: Cannot specify both --file and --base64");
        std::process::exit(1);
    }

    let verification_result = if let Some(base64_data) = &args.base64 {
        // Verify from base64 input
        info!("Starting C2PA verification from base64 input");
        verify_from_base64(base64_data, &args)?
    } else {
        // Verify from file
        let file = args.file.as_ref().unwrap();
        if !file.exists() {
            error!("File not found: {:?}", file);
            std::process::exit(1);
        }
        info!("Starting C2PA verification for: {:?}", file);
        verify_from_file(&args, file)?
    };

    // Print results
    print_results(&verification_result, args.verbose, args.history);

    // Exit with appropriate code
    if verification_result.is_valid {
        info!("Verification PASSED");
        std::process::exit(0);
    } else {
        error!("Verification FAILED");
        std::process::exit(1);
    }
}

/// Verify C2PA signature from base64 encoded image data
pub fn verify_from_base64(base64_data: &str, args: &Args) -> Result<VerificationResult> {
    // Decode base64 data
    let image_bytes = decode_base64(base64_data)?;

    // Determine format from magic bytes
    let format = detect_image_format(&image_bytes);

    // Create reader from stream
    let reader = match create_reader_from_stream(args, &format, image_bytes) {
        Ok(r) => r,
        Err(e) => {
            // Handle case where no C2PA manifest is found (not an error, just no manifest)
            let error_str = format!("{:?}", e);
            if error_str.contains("JumbfNotFound") || error_str.contains("UnsupportedType") {
                // Return a verification result indicating no manifest found
                return Ok(VerificationResult {
                    is_valid: true,
                    has_manifest: false,
                    manifest_info: None,
                    ingredients: Vec::new(),
                    json_output: None,
                    errors: Vec::new(),
                    warnings: vec!["No C2PA manifest found in the image".to_string()],
                    modification_history: Vec::new(),
                    validation_checks: Vec::new(),
                });
            }
            return Err(e);
        }
    };

    // Perform verification
    Ok(verify_image(&reader, false))
}

/// Verify C2PA signature from image file
fn verify_from_file(args: &Args, file: &PathBuf) -> Result<VerificationResult> {
    let reader = match create_reader_from_file(args, file) {
        Ok(r) => r,
        Err(e) => {
            // Handle case where no C2PA manifest is found (not an error, just no manifest)
            let error_str = format!("{:?}", e);
            if error_str.contains("JumbfNotFound") || error_str.contains("UnsupportedType") {
                // Return a verification result indicating no manifest found
                return Ok(VerificationResult {
                    is_valid: true,
                    has_manifest: false,
                    manifest_info: None,
                    ingredients: Vec::new(),
                    json_output: None,
                    errors: Vec::new(),
                    warnings: vec!["No C2PA manifest found in the image".to_string()],
                    modification_history: Vec::new(),
                    validation_checks: Vec::new(),
                });
            }
            return Err(e);
        }
    };
    Ok(verify_image(&reader, false))
}

/// Decode base64 string to bytes
fn decode_base64(data: &str) -> Result<Vec<u8>> {
    // Try standard base64 first
    if let Ok(bytes) = STANDARD.decode(data) {
        return Ok(bytes);
    }

    // Try URL-safe base64
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(data) {
        return Ok(bytes);
    }

    // Try standard base64 with padding
    let padded = if !data.contains('=') {
        // Add padding if needed
        let remainder = data.len() % 4;
        if remainder > 0 {
            format!("{}{}", data, "=".repeat(4 - remainder))
        } else {
            data.to_string()
        }
    } else {
        data.to_string()
    };

    STANDARD.decode(&padded).map_err(|e| {
        c2pa::Error::BadParam(format!("Failed to decode base64: {}", e))
    })
}

/// Detect image format from magic bytes
fn detect_image_format(bytes: &[u8]) -> &'static str {
    if bytes.len() < 4 {
        return "application/octet-stream";
    }

    // JPEG: FF D8 FF
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return "image/jpeg";
    }

    // PNG: 89 50 4E 47
    if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        return "image/png";
    }

    // WebP: RIFF....WEBP
    if bytes.starts_with(b"RIFF") && bytes.len() >= 12 && &bytes[8..12] == b"WEBP" {
        return "image/webp";
    }

    // GIF: 47 49 46 38
    if bytes.starts_with(b"GIF") {
        return "image/gif";
    }

    // AVIF: ftypavif or ftypavis
    if bytes.len() >= 12 {
        let ftyp = &bytes[4..8];
        if ftyp == b"avif" || ftyp == b"avis" {
            return "image/avif";
        }
    }

    "application/octet-stream"
}

/// Create reader from file
fn create_reader_from_file(args: &Args, file: &PathBuf) -> Result<Reader> {
    // Build context with settings if provided
    let context = build_context(args)?;

    let reader = match context {
        Some(ctx) => Reader::from_context(ctx).with_file(file)?,
        None => Reader::from_file(file)?,
    };

    Ok(reader)
}

/// Create reader from stream with base64 decoded bytes
fn create_reader_from_stream(
    args: &Args,
    format: &str,
    image_bytes: Vec<u8>,
) -> Result<Reader> {
    // Build context with settings if provided
    let context = build_context(args)?;

    let cursor = Cursor::new(image_bytes);
    let reader = match context {
        Some(ctx) => Reader::from_context(ctx).with_stream(format, cursor)?,
        None => Reader::from_stream(format, cursor)?,
    };

    Ok(reader)
}

/// Build context from settings if provided
fn build_context(args: &Args) -> Result<Option<c2pa::Context>> {
    // If skip_trust is set, configure settings to skip trust verification
    if args.skip_trust {
        let settings = c2pa::settings::Settings::new()
            .with_value("verify.verify_trust", false)?;
        return Ok(Some(c2pa::Context::new().with_settings(settings)?));
    }

    if let Some(settings_path) = &args.settings {
        let settings_content = std::fs::read_to_string(settings_path)?;
        return Ok(Some(c2pa::Context::new().with_settings(settings_content)?));
    }

    if let Some(trust_anchors_path) = &args.trust_anchors {
        let trust_pem = std::fs::read_to_string(trust_anchors_path)?;
        let settings = c2pa::settings::Settings::new()
            .with_value("trust.trust_anchors", trust_pem)?;
        return Ok(Some(c2pa::Context::new().with_settings(settings)?));
    }

    Ok(None)
}

/// Extract modification history from the manifest JSON
fn extract_modification_history(json_str: &str) -> Vec<ModificationRecord> {
    let mut records = Vec::new();

    // Parse the JSON
    let json: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return records,
    };

    // Get the manifests object
    let manifests = match json.get("manifests").and_then(|m| m.as_object()) {
        Some(m) => m,
        None => return records,
    };

    // Process each manifest (they are ordered from oldest to newest)
    for (_label, manifest_value) in manifests {
        let manifest_obj = match manifest_value.as_object() {
            Some(obj) => obj,
            None => continue,
        };

        // Get title for this manifest (to identify the source)
        let source = manifest_obj
            .get("title")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Get claim generator
        let claim_generator = manifest_obj
            .get("claim_generator")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());

        // Get actions from this manifest
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

                                        // Get software agent
                                        let software_agent = action
                                            .get("softwareAgent")
                                            .and_then(|s| {
                                                if let Some(s_obj) = s.as_object() {
                                                    s_obj.get("name").and_then(|n| n.as_str()).map(|s| s.to_string())
                                                } else {
                                                    s.as_str().map(|s| s.to_string())
                                                }
                                            });

                                        // Get parameters as pretty string
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

    // Remove duplicate "created" actions - keep only the first one (original creation)
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
            // Chronological order: oldest first
            // Since records are collected oldest-to-newest, step = i + 1
            r.step = i + 1;
            r
        })
        .collect();

    final_records
}

/// Extract validation checks from the manifest JSON
fn extract_validation_checks(json_str: &str) -> Vec<ValidationCheck> {
    let mut checks = Vec::new();

    // Parse the JSON
    let json: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return checks,
    };

    // Check top-level validation_status array
    if let Some(val_status_arr) = json.get("validation_status").and_then(|v| v.as_array()) {
        for item in val_status_arr {
            if let Some(code) = item.get("code").and_then(|c| c.as_str()) {
                checks.push(ValidationCheck {
                    name: code.to_string(),
                    status: "failed".to_string(),  // validation_status at top level means failure
                    description: item.get("explanation")
                        .and_then(|e| e.as_str())
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }
    }

    // Also check validation_results for success/failure
    if let Some(val_results) = json.get("validation_results") {
        if let Some(active_manifest) = val_results.get("activeManifest") {
            // Check success
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
            // Check failure
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

fn verify_image(reader: &Reader, verbose: bool) -> VerificationResult {
    let mut result = VerificationResult {
        is_valid: false,
        has_manifest: false,
        manifest_info: None,
        ingredients: Vec::new(),
        json_output: None,
        errors: Vec::new(),
        warnings: Vec::new(),
        modification_history: Vec::new(),
        validation_checks: Vec::new(),
    };

    // Get JSON representation
    let json_output = reader.json();
    result.json_output = Some(json_output.clone());

    // Extract modification history
    result.modification_history = extract_modification_history(&json_output);

    // Extract validation checks from JSON
    result.validation_checks = extract_validation_checks(&json_output);

    if verbose {
        info!("Manifest JSON:\n{}", json_output);
    }

    // Check if there is an active manifest
    match reader.active_manifest() {
        Some(manifest) => {
            result.has_manifest = true;
            info!("Found C2PA Manifest");

            // Build manifest info
            let manifest_info = ManifestInfo {
                label: manifest.label().map(|s| s.to_string()),
                claim_generator: manifest.claim_generator().map(|s| s.to_string()),
                title: manifest.title().map(|s| s.to_string()),
                json: None,
            };

            result.manifest_info = Some(manifest_info);

            // Get ingredients
            for ingredient in manifest.ingredients() {
                result.ingredients.push(IngredientInfo {
                    title: ingredient.title().map(|s| s.to_string()),
                    format: ingredient.format().map(|s| s.to_string()),
                    has_manifest: ingredient.manifest_data().is_some(),
                });
            }

            // If we got here, the manifest was read successfully
            // Note: Full signature verification requires trust settings
            result.is_valid = true;

            if verbose {
                if let Some(label) = manifest.label() {
                    info!("Manifest label: {}", label);
                }
                if let Some(cg) = manifest.claim_generator() {
                    info!("Claim generator: {}", cg);
                }
            }
        }
        None => {
            result.warnings.push("No C2PA manifest found in the image".to_string());
            warn!("No active manifest found");
        }
    }

    // Check for validation errors from the reader
    if let Some(validation_status) = reader.validation_status() {
        for status in validation_status {
            let status_str = format!("{:?}", status);
            if status_str.contains("error") || status_str.contains("invalid") {
                result.errors.push(status_str);
            } else if status_str.contains("warning") || status_str.contains("untrusted") {
                result.warnings.push(status_str);
            }
        }

        // Update validity based on errors only (not warnings or untrusted)
        if !result.errors.is_empty() {
            result.is_valid = false;
        }
    }

    result
}

fn print_results(result: &VerificationResult, verbose: bool, show_history: bool) {
    println!("\n=== C2PA Verification Results ===\n");

    // Overall status
    if result.is_valid {
        println!("✓ Verification Status: PASSED");
    } else {
        println!("✗ Verification Status: FAILED");
    }

    // Modification history
    if show_history && !result.modification_history.is_empty() {
        println!("\n--- Modification History ({} steps) ---", result.modification_history.len());
        for record in &result.modification_history {
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

    // Manifest presence
    println!("\n--- Manifest Info ---");
    if result.has_manifest {
        println!("✓ C2PA Manifest: Found");

        if let Some(ref manifest) = result.manifest_info {
            if let Some(ref label) = manifest.label {
                println!("  Label: {}", label);
            }
            if let Some(ref cg) = manifest.claim_generator {
                println!("  Claim Generator: {}", cg);
            }
            if let Some(ref title) = manifest.title {
                println!("  Title: {}", title);
            }
        }
    } else {
        println!("✗ C2PA Manifest: Not Found");
    }

    // Validation Checks
    if !result.validation_checks.is_empty() {
        // Deduplicate by name
        let mut seen = std::collections::HashSet::new();
        let unique_checks: Vec<_> = result.validation_checks.iter()
            .filter(|c| seen.insert(c.name.clone()))
            .collect();

        if !unique_checks.is_empty() {
            println!("\n--- Validation Checks ---");
            for check in unique_checks {
                let status_icon = match check.status.as_str() {
                    "passed" => "✓",
                    "failed" => "✗",
                    _ => "⚠",
                };
                println!("  {} {}: {}", status_icon, check.name, check.description);
            }
        }
    }

    // Ingredients
    if !result.ingredients.is_empty() {
        println!("\n--- Ingredients ({} items) ---", result.ingredients.len());
        for ingredient in &result.ingredients {
            let manifest_status = if ingredient.has_manifest {
                "✓ with manifest"
            } else {
                "✗ no manifest"
            };
            println!(
                "  - {} ({}): {}",
                ingredient.title.as_deref().unwrap_or("Unknown"),
                ingredient.format.as_deref().unwrap_or("unknown"),
                manifest_status
            );
        }
    }

    // Errors
    if !result.errors.is_empty() {
        println!("\n--- Errors ---");
        for error in &result.errors {
            println!("  ✗ {}", error);
        }
    }

    // Warnings
    if !result.warnings.is_empty() {
        println!("\n--- Warnings ---");
        for warning in &result.warnings {
            println!("  ⚠ {}", warning);
        }
    }

    // Verbose JSON output
    if verbose {
        println!("\n--- Full Manifest JSON ---");
        if let Some(ref json) = result.json_output {
            println!("{}", json);
        }
    }

    println!("\n================================\n");
}

#[cfg(test)]
mod verifier_test;
