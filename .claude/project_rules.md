# brevis-c2pa-verifier Project Rules

## Project Overview

This is a C2PA image signature verification project based on Pico ZKVM.

## Project Structure

```
brevis-c2pa-verifier/
├── Cargo.toml
├── app-c2pa/           # C2PA verification app for Pico ZKVM
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── elf/            # Compiled ELF
└── verifier/            # C2PA verification tool for host
    ├── Cargo.toml
    ├── README.md
    └── src/
        ├── main.rs
        └── verifier_test.rs
```

## Common Commands

### Build and run verifier
```bash
cargo run -p verifier -- --file <image-path>
cargo run -p verifier -- --file <image-path> --verbose
```

### Build app-c2pa
```bash
cd app-c2pa && cargo pico build
```

### Run tests
```bash
cargo test -p verifier
```

## Notes

- Use `cargo pico build` for Pico ZKVM compilation
- ELF output is in `app-c2pa/elf/`
- verifier supports `--base64` parameter for direct base64 image input
