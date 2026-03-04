# brevis-c2pa-verifier

A Zero Knowledge Proof project for C2PA image signature verification based on Pico ZKVM.

## Project Overview

This project implements a C2PA (Coalition for Content Provenance and Authenticity) image signature verification system using Zero Knowledge Proofs.

### What is C2PA?

C2PA is an open standard for recording and verifying the origin and authenticity of digital content. It enables:

- **Provenance Tracking**: Determine the creator/device of an image
- **Integrity Verification**: Detect if an image has been tampered with
- **Authenticity Proof**: Verify that content was created by the claimed source

### What is Zero Knowledge Proof?

Zero Knowledge Proof (ZKP) allows one party (the prover) to prove to another party (the verifier) that a statement is true without revealing any additional information.

In this project:
- **Private**: The original image data
- **Public**: The verification result

This allows proving "the C2PA signature verification result for this image" without exposing the image content.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      brevis-c2pa-verifier                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    │
│  │    verifier   │    │   app-c2pa   │    │ prover-c2pa  │    │
│  │ (Host Tool)  │    │ (Pico ZKVM)  │    │ (Generate Proof)│ │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    │
│         │                    │                    │              │
│         ▼                    ▼                    ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ C2PA Signature│    │  ELF Binary │    │  ZK Proof   │      │
│  │ Verification  │    │  (RISC-V)   │    │ + Public     │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│                                                                  │
│  Method 1            Method 2 (ZK Privacy Protection)           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Module Description

| Module | Description |
|--------|-------------|
| `verifier` | C2PA verification tool running on host, directly verifies image C2PA signatures |
| `app-c2pa` | C2PA verification app running on Pico ZKVM |
| `prover-c2pa` | Generates ZK Proof, verifies app-c2pa execution results |
| `cropper` | C2PA image cropping tool, verifies original image before cropping and re-signing |
| `c2pa-service | Backend service, provides REST API to receive images and return ZK Proofs |
| `c2pa-frontend` | Frontend page, uploads images and displays Proof results |

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

### Method 2: Using Pico ZKVM + Prover (Zero Knowledge Proof)

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
      --skip-trust           Skip certificate trust verification (recommended)
      --history              Display modification history (actions)
  -v, --verbose              Verbose output mode
  -h, --help                 Help information
```

### cropper Command

```bash
cd cropper
cargo build
./target/debug/cropper [OPTIONS]

Options:
  -i, --input <FILE>        Input image file path (required)
  -o, --output <FILE>       Output image file path (required)
      --x <INT>              Crop region x coordinate (default 0)
      --y <INT>              Crop region y coordinate (default 0)
      --width <INT>          Crop region width (required)
      --height <INT>         Crop region height (required)
      --skip-verify          Skip original image verification
  -v, --verbose              Verbose output mode
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

--- Validation Checks ---
  ✗ signingCredential.untrusted: signing certificate untrusted
  ✓ timeStamp.validated: timestamp message digest matched
  ✓ timeStamp.trusted: timestamp cert trusted
  ✓ claimSignature.validated: claim signature valid
  ✓ assertion.dataHash.match: data hash valid

================================
```

### verifier --history Output (Modification History)

```
--- Modification History (3 steps) ---
  [Step 1] c2pa.created
           Software: SONY_CAMERA
           Source: DSC00050.JPG

  [Step 2] c2pa.opened
           Source: cropped.jpg

  [Step 3] c2pa.cropped
           Software: cropper/0.1.0
           Params: width: 1000, height: 1000, x: 0, y: 0
           Source: cropped.jpg
```

### verifier --verbose Output (Full JSON)

```json
{
  "active_manifest": "urn:uuid:4d7c9981-d887-4005-829a-033422a7e865",
  "manifests": {
    "urn:uuid:4d7c9981-d887-4005-829a-033422a7e865": {
      "claim_generator": "SONY_CAMERA",
      "title": "DSC00050.JPG",
      "format": "image/jpeg",
      "signature_info": {
        "alg": "Es256",
        "time": "2026-03-02T02:22:47+00:00"
      }
    }
  },
  "validation_state": "Valid"
}
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

## C2PA Manifest Details

When verifier successfully verifies an image, it displays the following information:

| Field | Description |
|-------|-------------|
| **Label** | Unique identifier for the manifest (UUID) |
| **Claim Generator** | Software/device that created this manifest (e.g., SONY_CAMERA) |
| **Title** | File name |
| **format** | Image format (image/jpeg) |

### Validation Status (Validation Checks)

| Status | Description |
|--------|-------------|
| ✅ timeStamp.validated | Timestamp message digest matched |
| ✅ timeStamp.trusted | Timestamp certificate trusted |
| ✅ claimSignature.validated | Claim signature valid |
| ✅ claimSignature.insideValidity | Signature within validity period |
| ✅ assertion.dataHash.match | **Image content not modified** |
| ⚠️ signingCredential.untrusted | Signing certificate not in trust list |

### Validation Explanation

**Why can we ignore `signingCredential.untrusted`?**

These are two independent verifications:
1. **Signature valid** - Signed with private key, can be decrypted with public key
2. **Certificate trust** - Whether certificate is in Adobe AATF trust list

Even without knowing if the signer is trustworthy (certificate untrusted), we can still guarantee image authenticity through:
- `assertion.dataHash.match` = Image content not modified ✅
- `claimSignature.validated` = Signature valid ✅

### Modification History (Actions)

C2PA records all operation history for an image:

| Action | Description |
|--------|-------------|
| `c2pa.created` | First creation (camera capture) |
| `c2pa.opened` | Image opened |
| `c2pa.cropped` | Crop operation |
| `c2pa.edited` | Edit operation |
| `c2pa.filtered` | Filter/effect applied |

## Public Value Explanation

**Public Values** are the part of the proof data that is revealed to the outside after executing the program in the ZKVM.

### Meaning in This Project

```
┌─────────────────────────────────────────────┐
│           ZKVM Execution (app-c2pa)         │
│                                             │
│  Input (Private - Not公开):                    │
│    - image_hash                             │
│    - expected_hash                          │
│    - image_size                             │
│    - is_signed                              │
│                                             │
│  Output (Public Values - 公开):               │
│    ✓ hash_valid                             │
│    ✓ computed_hash                          │
│    ✓ image_hash                             │
│    ✓ expected_hash                          │
│    ✓ image_size                             │
│    ✓ is_signed                              │
└─────────────────────────────────────────────┘
```

### Characteristics

1. **Publicly Visible** - Anyone can see these values
2. **Verifiable** - Can verify computation correctness without knowing original inputs
3. **Privacy Protected** - Original inputs (image data) remain private inside ZKVM

## Project Structure

```
brevis-c2pa-verifier/
├── Cargo.toml              # Workspace configuration
├── app-c2pa/              # C2PA verification app (Pico ZKVM)
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── elf/               # Compiled ELF
├── prover-c2pa/            # C2PA prover
│   ├── Cargo.toml
│   └── src/main.rs
├── verifier/               # C2PA verification tool
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── verifier_test.rs
│       └── DSC00050.JPG   # Test image
├── cropper/                # C2PA image cropping tool
│   ├── Cargo.toml
│   └── src/main.rs
├── c2pa-service/          # Backend service (REST API)
│   ├── Cargo.toml
│   └── src/main.rs
├── c2pa-frontend/         # Frontend page
│   ├── index.html
│   ├── styles.css
│   ├── app.js
│   ├── query.html
│   └── query.js
└── openspec/              # OpenSpec configuration
```

## Backend Service (c2pa-service)

c2pa-service is an Axum-based backend service that provides a REST API to receive images and return ZK Proofs.

### Start Service

```bash
# Start service (default listening on 0.0.0.0:8080)
cargo run -p c2pa-service
```

### API Endpoints

#### 1. Health Check

```bash
POST /health
```

Response Example:
```json
{
  "status": "healthy",
  "service": "c2pa-proof-service"
}
```

#### 2. Generate Proof

```bash
POST /api/v1/proof
Content-Type: multipart/form-data
```

Request Parameters:
| Parameter | Type | Description |
|-----------|------|-------------|
| image | file | Image file (JPEG, PNG, etc.) |

Response Example:
```json
{
  "success": true,
  "error": null,
  "proofGenerated": true,
  "publicValues": {
    "hashValid": true,
    "computedHashPrefix": 123456789,
    "isSigned": true,
    "imageSize": 150000,
    "actionCount": 3,
    "actionsValid": true
  }
}
```

#### 3. Query Task Status

```bash
GET /api/v1/proof/:task_id
```

#### 4. Verify Proof

```bash
GET /api/v1/verify/:task_id
```

#### 5. Download Proof

```bash
GET /proofs/:task_id.json
```

### Usage Examples

```bash
# Upload image via curl
curl -X POST http://localhost:8080/api/v1/proof \
  -F "image=@./verifier/src/DSC00050.JPG"

# Health check
curl -X POST http://localhost:8080/health

# Query task status
curl http://localhost:8080/api/v1/proof/<task_id>

# Verify proof
curl http://localhost:8080/api/v1/verify/<task_id>
```

### Public Values Field Description

| Field | Type | Description |
|-------|------|-------------|
| `hashValid` | bool | Whether image data hash verification passed |
| `computedHashPrefix` | u64 | Computed hash prefix |
| `isSigned` | bool | Whether image has C2PA signature |
| `imageSize` | u32 | Image size (bytes) |
| `actionCount` | u8 | Number of modification history records |
| `actionsValid` | bool | Whether modification history is valid |

## Frontend Page (c2pa-frontend)

c2pa-frontend is a simple frontend page that can upload images to the backend service and display Proof results.

### Startup Steps

1. First start the backend service:

```bash
cargo run -p c2pa-service
```

2. Then open the frontend page in your browser:

```bash
# Method 1: Open HTML file directly in browser
open c2pa-frontend/index.html

# Method 2: Use a simple HTTP server
cd c2pa-frontend
python3 -m http.server 8081
# Then visit http://localhost:8081
```

### Features

- Drag & drop or click to upload images
- Image preview
- Call backend API to generate Proof
- Intuitive display of verification results

### UI Preview

```
┌─────────────────────────────────────────────┐
│           C2PA Proof Generator              │
│    Zero-Knowledge Proof Based Image         │
│         Provenance Verification             │
├─────────────────────────────────────────────┤
│                                              │
│    ┌─────────────────────────────────┐      │
│    │      Drop image here            │      │
│    │    or click to select          │      │
│    └─────────────────────────────────┘      │
│                                              │
│            [ Generate Proof ]                │
│                                              │
│    ┌─────────────────────────────────┐      │
│    │  ✓ Proof Generated Successfully │      │
│    │  ─────────────────────────────  │      │
│    │  Public Values:                 │      │
│    │  • Hash Valid: Yes             │      │
│    │  • Is Signed: Yes              │      │
│    │  • Image Size: 150 KB          │      │
│    │  • Action Count: 3             │      │
│    └─────────────────────────────────┘      │
└─────────────────────────────────────────────┘
```

### Query Page

The query page allows you to query proof status by Task ID and download proofs.

Access: `http://localhost:8081/query.html`

## Running Tests

```bash
# Run verifier tests
cargo test -p verifier
```

## Notes

1. Images without C2PA manifest will be marked as "PASSED" but will show warnings
2. Full signature verification requires providing trust anchor files
3. Supported image formats: JPEG, PNG, WebP, GIF, AVIF

## Related Links

- [C2PA Official Website](https://c2pa.org/)
- [Pico SDK Documentation](https://docs.brevis.network/)
- [C2PA Rust SDK](https://github.com/contentauth/c2pa-rust)
- [Pico ZKVM Quick Start](https://pico-docs.brevis.network/getting-started/quick-start)

## License

MIT License
