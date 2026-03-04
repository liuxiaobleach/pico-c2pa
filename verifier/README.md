# brevis-c2pa-verifier

A Zero Knowledge Proof project for C2PA image signature verification based on Pico ZKVM.

## Project Overview

This project implements a C2PA (Coalition for Content Provenance and Authenticity) image signature verification system using Zero Knowledge Proofs.

### System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      brevis-c2pa-verifier                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    │
│  │    verifier   │    │   app-c2pa   │    │ prover-c2pa  │    │
│  │ (Host Tool)  │    │ (Pico ZKVM)  │    │(Generate Proof)│ │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    │
│         │                    │                    │              │
│         ▼                    ▼                    ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ C2PA Signature│    │  ELF Binary │    │  ZK Proof   │      │
│  │ Verification  │    │  (RISC-V)   │    │  + Public   │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Module Description

| Module | Description |
|--------|-------------|
| `verifier` | C2PA verification tool running on host, directly verifies image C2PA signatures |
| `app-c2pa` | C2PA verification app running on Pico ZKVM |
| `prover-c2pa` | Generates ZK Proof, verifies app-c2pa execution results |

## Requirements

- Rust 2024 edition
- Pico SDK (via `cargo pico` toolchain)
- Nightly Rust toolchain

## Quick Start

### 1. Install Pico Toolchain

```bash
cargo install cargo-pico
```

### 2. Build Project

```bash
# Build all packages
cargo build
```

## Usage

### Method 1: Using verifier (Host Tool)

Directly verify image C2PA signatures without zero knowledge proofs.

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

### Method 2: Using Pico ZKVM + Prover

Verify C2PA signatures via zero knowledge proofs for privacy protection.

#### Step 1: Build app-c2pa

```bash
cd app-c2pa
cargo pico build
```

This generates the ELF file: `app-c2pa/elf/riscv32im-pico-zkvm-elf`

#### Step 2: Run prover to generate Proof

```bash
cargo run -p prover-c2pa
```

This executes app-c2pa on Pico ZKVM and generates a zero knowledge proof.

## Command Reference

### verifier Command

```bash
cargo run -p verifier -- [OPTIONS]

Options:
  -f, --file <FILE>           Image file path
      --base64 <BASE64>       Base64 encoded image data
  -s, --settings <FILE>      Trust settings file (optional)
  -t, --trust-anchors <FILE> Trust anchor PEM file (optional)
  -v, --verbose              Verbose output mode
  -h, --help                 Help information
```

### app-c2pa Build

```bash
cd app-c2pa
cargo pico build

# Specify output directory
cargo pico build --output-directory <directory>
```

### prover-c2pa Run

```bash
cargo run -p prover-c2pa
```

## Running Tests

```bash
# Run verifier tests
cargo test -p verifier
```

## Output Examples

### verifier Output (with C2PA signature)

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

### prover-c2pa Output

```
Input: image_hash=1311768467294899695, expected_hash=1311768467294899695, size=150000, is_signed=true
[DEBUG] postprocess: accessed_addrs len: 14758
Public values: C2paResult {
    hash_valid: false,
    computed_hash: 17407...,
    image_hash: 13117...,
    expected_hash: 13117...,
    image_size: 150000,
    is_signed: true
}
hash_valid: false (computed in ZKVM)
Verification PASSED!
```

## Public Value Explanation

**Public Values** are the part of the proof data that is revealed to the outside after executing the program in the ZKVM.

Characteristics:
- Publicly visible - anyone can view these values
- Verifiable - can verify computation correctness without knowing original inputs
- Privacy protected - original inputs (image data) remain private inside ZKVM

## Project Structure

```
brevis-c2pa-verifier/
├── Cargo.toml              # Workspace configuration
├── app/                   # Original Fibonacci app
├── app-c2pa/              # C2PA verification app (Pico ZKVM)
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── elf/               # Compiled ELF
├── lib/                   # Common library
├── prover/                # Original Fibonacci prover
├── prover-c2pa/           # C2PA prover
│   ├── Cargo.toml
│   └── src/main.rs
├── verifier/              # C2PA verification tool
│   ├── Cargo.toml
│   ├── README.md
│   └── src/
│       ├── main.rs
│       └── verifier_test.rs
└── openspec/              # OpenSpec configuration
```

## Notes

1. Images without C2PA manifest will be marked as "PASSED" but will show warnings
2. Full signature verification requires providing trust anchor files
3. Supported image formats: JPEG, PNG, WebP, GIF, AVIF

## Related Links

- [C2PA Official Documentation](https://c2pa.org/)
- [Pico SDK Documentation](https://docs.brevis.network/)
- [C2PA Rust SDK](https://github.com/contentauth/c2pa-rust)
