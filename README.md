# brevis-c2pa-verifier

C2PA Image Signature Verification Project based on Pico ZKVM.

## Project Overview

This project implements C2PA (Coalition for Content Provenance and Authenticity) image signature verification functionality.

### What is C2PA?

C2PA is an open standard for recording and verifying digital content provenance and authenticity:

- **Provenance Tracking**: Determine the creator/device of an image
- **Integrity Verification**: Detect if an image has been tampered with
- **Authenticity Proof**: Verify content was created by the claimed source

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      brevis-c2pa-verifier                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐                          │
│  │    verifier   │    │   app-c2pa   │                          │
│  │  (Host Tool)  │    │ (Pico ZKVM)  │                          │
│  └──────────────┘    └──────────────┘                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Modules

| Module | Description |
|--------|-------------|
| `verifier` | C2PA verification tool running on host machine |
| `app-c2pa` | C2PA verification app for Pico ZKVM (compiles to ELF) |

## Requirements

- Rust 2024 edition
- Pico SDK (via `cargo pico` toolchain)
- Nightly Rust toolchain

## Quick Start

### 1. Install Pico Toolchain

```bash
cargo install cargo-pico
```

### 2. Clone Project

```bash
git clone <your-repo-url>
cd brevis-c2pa-verifier
```

### 3. Build Project

```bash
cargo build
```

## Usage

### verifier: Host-based Verification Tool

```bash
# Verify from file
cargo run -p verifier -- --file <image-path>

# Example
cargo run -p verifier -- --file ./verifier/src/DSC00050.JPG

# Verbose output (show full JSON)
cargo run -p verifier -- --file <image-path> --verbose

# Verify from base64
cargo run -p verifier -- --base64 "<base64-string>"
```

### app-c2pa: Pico ZKVM Application

```bash
cd app-c2pa
cargo pico build
```

Generated ELF: `app-c2pa/elf/riscv32im-pico-zkvm-elf`

## Command Reference

```bash
cargo run -p verifier -- [OPTIONS]

Options:
  -f, --file <FILE>           Image file path
      --base64 <BASE64>        Base64 encoded image data
  -s, --settings <FILE>       Trust settings file (optional)
  -t, --trust-anchors <FILE>  Trust anchors PEM file (optional)
  -v, --verbose               Verbose output mode
  -h, --help                  Help information
```

## Output Examples

### Verification Success (with C2PA manifest)

```
=== C2PA Verification Results ===

✓ Verification Status: PASSED

--- Manifest Info ---
✓ C2PA Manifest: Found
  Label: urn:uuid:4d7c9981-d887-4005-829a-033422a7e865
  Claim Generator: SONY_CAMERA
  Title: DSC00050.JPG

================================
```

### Verification Success (no C2PA manifest)

```
=== C2PA Verification Results ===

✓ Verification Status: PASSED

--- Manifest Info ---
✗ C2PA Manifest: Not Found

--- Warnings ---
  ⚠ No C2PA manifest found in the image

================================
```

## Project Structure

```
brevis-c2pa-verifier/
├── Cargo.toml              # Workspace configuration
├── README.md               # Project documentation
├── app-c2pa/              # C2PA verification app (Pico ZKVM)
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── elf/               # Compiled ELF
├── verifier/               # C2PA verification tool
│   ├── Cargo.toml
│   ├── README.md
│   └── src/
│       ├── main.rs
│       └── verifier_test.rs
└── openspec/              # OpenSpec configuration
```

## Run Tests

```bash
cargo test -p verifier
```

## Notes

1. Images without C2PA manifest will show a warning
2. Full signature verification requires trust anchors file
3. Supported image formats: JPEG, PNG, WebP, GIF, AVIF

## Related Links

- [C2PA Official Website](https://c2pa.org/)
- [Pico SDK Documentation](https://docs.brevis.network/)
- [C2PA Rust SDK](https://github.com/contentauth/c2pa-rust)

## License

MIT License
