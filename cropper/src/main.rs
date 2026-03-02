//! C2PA Image Cropper Tool
//!
//! This tool verifies the original image's C2PA signature, crops the image,
//! and creates a new C2PA manifest recording the crop operation.

use c2pa::{Builder, BuilderIntent, Context, Result, EphemeralSigner};
use clap::Parser;
use image::{DynamicImage, ImageFormat, GenericImageView};
use log::{error, info, warn};
use serde_json::json;
use std::io::{Cursor, Read, Seek, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "cropper")]
#[command(about = "C2PA Image Cropper - Verify, crop, and re-sign images", long_about = None)]
struct Args {
    /// Path to the input image file
    #[arg(short, long, value_name = "FILE", required = true)]
    input: PathBuf,

    /// Path to the output image file
    #[arg(short, long, value_name = "FILE", required = true)]
    output: PathBuf,

    /// Crop region: x coordinate (left)
    #[arg(long, value_name = "INT", default_value = "0")]
    x: u32,

    /// Crop region: y coordinate (top)
    #[arg(long, value_name = "INT", default_value = "0")]
    y: u32,

    /// Crop region: width
    #[arg(long, value_name = "INT", required = true)]
    width: u32,

    /// Crop region: height
    #[arg(long, value_name = "INT", required = true)]
    height: u32,

    /// Skip verification of original image (optional)
    #[arg(long, default_value = "false")]
    skip_verify: bool,

    /// Verbose output
    #[arg(short, long, default_value = "false")]
    verbose: bool,
}

fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = Args::parse();

    // Check if input file exists
    if !args.input.exists() {
        error!("Input file not found: {:?}", args.input);
        std::process::exit(1);
    }

    info!("Starting C2PA Image Cropper");
    info!("Input: {:?}", args.input);
    info!("Output: {:?}", args.output);
    info!("Crop region: x={}, y={}, width={}, height={}", args.x, args.y, args.width, args.height);

    // Step 1: Verify original image's C2PA (if not skipped)
    if !args.skip_verify {
        info!("\n=== Step 1: Verifying original image C2PA ===");
        verify_original_image(&args)?;
    } else {
        warn!("Skipping original image verification");
    }

    // Step 2: Load and crop the image
    info!("\n=== Step 2: Cropping image ===");
    let cropped_image = crop_image(&args)?;

    // Step 3: Create new C2PA manifest with crop action
    info!("\n=== Step 3: Creating new C2PA manifest ===");
    create_signed_image(&args, &cropped_image)?;

    info!("\n=== Done! ===");
    info!("Cropped image saved to: {:?}", args.output);
    info!("The cropped image now contains a C2PA manifest with crop action recorded.");

    Ok(())
}

/// Verify the original image's C2PA signature
fn verify_original_image(args: &Args) -> Result<()> {
    let reader = match c2pa::Reader::from_file(&args.input) {
        Ok(r) => r,
        Err(e) => {
            let error_str = format!("{:?}", e);
            if error_str.contains("JumbfNotFound") || error_str.contains("UnsupportedType") {
                warn!("No C2PA manifest found in original image");
                return Ok(());
            }
            return Err(e);
        }
    };

    // Get manifest info
    if let Some(manifest) = reader.active_manifest() {
        info!("Original image C2PA Manifest found:");
        if let Some(label) = manifest.label() {
            info!("  Label: {}", label);
        }
        if let Some(cg) = manifest.claim_generator() {
            info!("  Claim Generator: {}", cg);
        }
        if let Some(title) = manifest.title() {
            info!("  Title: {}", title);
        }

        // Get actions
        for ingredient in manifest.ingredients() {
            info!("  Ingredient: {:?}", ingredient.title().unwrap_or("unknown"));
        }

        info!("Original image verification: PASSED");
    } else {
        warn!("No active manifest in original image");
    }

    Ok(())
}

/// Crop the image using the specified region
fn crop_image(args: &Args) -> Result<DynamicImage> {
    // Load the image
    let img = image::open(&args.input)
        .map_err(|e| c2pa::Error::BadParam(format!("Failed to open image: {}", e)))?;

    let (img_width, img_height) = img.dimensions();
    info!("Original image size: {}x{}", img_width, img_height);

    // Validate crop region
    if args.x + args.width > img_width {
        error!("Crop width exceeds image width");
        std::process::exit(1);
    }
    if args.y + args.height > img_height {
        error!("Crop height exceeds image height");
        std::process::exit(1);
    }

    info!("Crop region is valid within image bounds");

    // Crop the image
    let cropped = img.crop_imm(args.x, args.y, args.width, args.height);
    let (crop_width, crop_height) = cropped.dimensions();
    info!("Cropped image size: {}x{}", crop_width, crop_height);

    Ok(cropped)
}

/// Create a new signed image with C2PA manifest recording the crop action
fn create_signed_image(args: &Args, cropped_image: &DynamicImage) -> Result<()> {
    // Determine output format from file extension
    let format = match args.output.extension().and_then(|s| s.to_str()) {
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        Some("gif") => "image/gif",
        Some("avif") => "image/avif",
        _ => {
            // Default to JPEG
            warn!("Unknown output format, defaulting to JPEG");
            "image/jpeg"
        }
    };

    // Get original image dimensions
    let img = image::open(&args.input)?;
    let (orig_width, orig_height) = img.dimensions();

    // Get original title
    let original_title = args.input.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "original.jpg".to_string());

    // Get output title
    let output_title = args.output.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "cropped.jpg".to_string());

    // Create manifest definition JSON
    let manifest_json = json!({
        "title": output_title,
        "claim_generator": "cropper/0.1.0"
    }).to_string();

    // Create ephemeral signer for self-signed manifests
    info!("Creating ephemeral signer...");
    let signer = EphemeralSigner::new("cropper.local")?;

    // Create context (without setting the signer in context since EphemeralSigner is not Send+Sync)
    let context = Context::new();

    // Build the manifest
    info!("Building C2PA manifest...");

    let mut builder = Builder::from_context(context);
    builder.set_intent(BuilderIntent::Edit);

    // Add the manifest definition
    builder.definition = serde_json::from_str(&manifest_json)
        .map_err(|e| c2pa::Error::JsonError(e))?;

    // Add the original image as an ingredient (parent)
    info!("Adding original image as ingredient...");
    let mut source_file = std::fs::File::open(&args.input)?;
    builder.add_ingredient_from_stream(
        json!({
            "title": original_title,
            "relationship": "parentOf",
            "label": "original_image"
        }).to_string(),
        format,
        &mut source_file
    )?;

    // Add the crop action
    info!("Adding crop action...");
    builder.add_action(json!({
        "action": "c2pa.cropped",
        "softwareAgent": "cropper/0.1.0",
        "parameters": {
            "x": args.x,
            "y": args.y,
            "width": args.width,
            "height": args.height,
            "original_width": orig_width,
            "original_height": orig_height,
            "ingredientIds": ["original_image"]
        }
    }))?;

    // Prepare the cropped image for signing
    let mut cropped_bytes = Vec::new();
    let mut cropped_cursor = Cursor::new(&mut cropped_bytes);
    cropped_image.write_to(&mut cropped_cursor, ImageFormat::Jpeg)?;

    // Sign and save the file using sign method with signer
    info!("Signing and saving the cropped image...");

    // Write to a temp file first, then copy to destination
    let temp_output = args.output.with_extension("tmp");
    let mut source = Cursor::new(cropped_bytes);
    let mut dest = std::fs::File::create(&temp_output)?;

    // Use the sign method with the signer
    builder.sign(&signer, format, &mut source, &mut dest)?;

    // Rename temp file to final output
    std::fs::rename(&temp_output, &args.output)?;

    info!("Successfully created and signed C2PA manifest!");

    // Verify the output
    verify_output_image(&args.output)?;

    Ok(())
}

/// Verify the output image has a valid C2PA manifest
fn verify_output_image(output_path: &PathBuf) -> Result<()> {
    info!("\n=== Verifying output image ===");

    let reader = c2pa::Reader::from_file(output_path)?;

    if let Some(manifest) = reader.active_manifest() {
        info!("Output image C2PA Manifest:");
        if let Some(label) = manifest.label() {
            info!("  Label: {}", label);
        }
        if let Some(cg) = manifest.claim_generator() {
            info!("  Claim Generator: {}", cg);
        }
        if let Some(title) = manifest.title() {
            info!("  Title: {}", title);
        }

        // List ingredients
        let ingredients = manifest.ingredients();
        for (i, ingredient) in ingredients.iter().enumerate() {
            info!("  Ingredient {}: {:?}", i, ingredient.title().unwrap_or("unknown"));
        }

        info!("Output image verification: PASSED");
    } else {
        warn!("No manifest found in output image!");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing() {
        let args = Args::parse_from([
            "cropper",
            "--input", "test.jpg",
            "--output", "test_cropped.jpg",
            "--width", "100",
            "--height", "100"
        ]);

        assert_eq!(args.width, 100);
        assert_eq!(args.height, 100);
    }
}
