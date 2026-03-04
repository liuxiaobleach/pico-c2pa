# brevis-c2pa-verifier Project Memory

## Project Overview

This is a **C2PA (Coalition for Content Provenance and Authenticity) image signature verification Zero Knowledge Proof project** based on **Pico ZKVM**.

- **Purpose**: Implement privacy-preserving C2PA image signature verification (via Zero Knowledge Proofs)
- **Language**: Rust 2024 edition (nightly)
- **Core Framework**: Pico ZKVM, c2pa-rust

## Project Structure

```
/Users/liuxiao/code/tour/Fibonacci/
├── Cargo.toml                  # Workspace configuration
├── rust-toolchain              # nightly-2025-08-04
├── README.md                   # Project documentation
├── verifier/                   # Host C2PA verification tool
│   ├── Cargo.toml
│   ├── src/main.rs
│   ├── src/verifier_test.rs
│   └── src/DSC00050.JPG        # Test image (taken by Sony camera)
├── app-c2pa/                   # Pico ZKVM app
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── elf/riscv32im-pico-zkvm-elf  # Compiled ELF
├── prover-c2pa/                # ZK Proof generator
│   ├── Cargo.toml
│   └── src/main.rs
├── cropper/                    # C2PA image cropping tool
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── sigcert.p12            # Device certificate (if available)
└── openspec/                   # OpenSpec configuration
```

## Core Modules

### 1. verifier (Host Verification Tool)
- Directly verifies image C2PA signatures
- Supports file input and base64 input
- Uses `c2pa-rust` library (v0.76)
- Supported formats: JPEG, PNG, WebP, GIF, AVIF
- **New Features**: `--history` displays modification history, `--skip-trust` skips certificate trust verification

### 2. app-c2pa (Pico ZKVM App)
- Runs on RISC-V architecture (riscv32im-pico-zkvm-elf)
- Performs simplified C2PA hash verification
- Input: image_hash, expected_hash, image_size, is_signed
- Output: computed_hash, hash_valid, public values

### 3. prover-c2pa (ZK Proof Generator)
- Loads ELF from app-c2pa
- Executes app-c2pa on Pico ZKVM
- Generates zero knowledge proof and verifies public values

### 4. cropper (Image Cropping Tool)
- Verifies original image C2PA signature
- Crops image
- Creates new C2PA manifest recording the crop operation

## Common Commands

```bash
# Build all packages
cargo build

# Run verifier (direct verification)
cargo run -p verifier -- --file <image-path>
cargo run -p verifier -- --file ./verifier/src/DSC00050.JPG --skip-trust

# Display modification history
cargo run -p verifier -- --file <image-path> --skip-trust --history

# Build Pico ZKVM app
cd app-c2pa && cargo pico build

# Run prover (ZK verification)
cargo run -p prover-c2pa

# Run cropper (crop image)
cd cropper && cargo build
./target/debug/cropper --input <original-image> --output <output> --width 1000 --height 1000

# Run tests
cargo test -p verifier
```

## verifier Output Explanation

### Validation Checks

| Validation Item | Status | Description |
|--------|------|------|
| `timeStamp.validated` | ✅ | Timestamp message digest matched |
| `timeStamp.trusted` | ✅ | Timestamp certificate trusted |
| `claimSignature.validated` | ✅ | Claim signature valid |
| `claimSignature.insideValidity` | ✅ | Signature within validity period |
| `assertion.dataHash.match` | ✅ | **Image content not modified** |
| `signingCredential.untrusted` | ⚠️ | Signing certificate not in trust list |

### Modification History

```
--- Modification History (3 steps) ---
  [Step 1] c2pa.created           # Camera creation
           Software: SONY_CAMERA

  [Step 2] c2pa.opened            # Image opened

  [Step 3] c2pa.cropped           # Crop operation
           Params: width: 1000, height: 1000, x: 0, y: 0
```

### Important Notes

**Why can we ignore `signingCredential.untrusted`?**

- These are two independent verifications:
  1. **Signature valid** = Signed with private key, can be decrypted with public key
  2. **Certificate trust** = Whether certificate is in Adobe AATL trust list

- Even without knowing if the signer is trustworthy (certificate untrusted), we can still guarantee image authenticity through:
  - `assertion.dataHash.match` = Image content not modified ✅
  - `claimSignature.validated` = Signature valid ✅

## Dependencies

- **c2pa-rust**: v0.76 - C2PA signature verification
- **pico-sdk**: v1.3.0 - Pico ZKVM SDK
- **clap**: v4.5 - CLI argument parsing
- **serde**: v1.0.205 - Serialization
- **log, env_logger**: Logging
- **image**: v0.25 - Image processing (used by cropper)

## Environment Requirements

- Rust nightly-2025-08-04
- cargo-pico toolchain
- Pico SDK

## Notes

1. Using `--skip-trust` can skip certificate trust verification to avoid `signingCredential.untrusted` warning
2. Images without C2PA manifest will show PASSED but with warnings
3. Full signature verification requires trust anchor files
4. ZK method protects image data privacy, only revealing verification results
