# xtask - Russignol Build Automation

Rust-based build system for the Russignol project.

## Quick Start

```bash
cargo xtask host-utility           # Build host utility
cargo xtask rpi-signer             # Build RPi signer
cargo xtask release                # Full release build
cargo xtask validate               # Check build environment
cargo xtask test                   # Run tests
cargo xtask clean                  # Remove artifacts
```

## Commands

### `rpi-signer`
Build the Raspberry Pi signer for ARM64 (Cortex-A53).

```bash
cargo xtask rpi-signer
cargo xtask rpi-signer --dev       # Debug build
```

**Prerequisites:** `aarch64-linux-gnu-gcc`, Rust target `aarch64-unknown-linux-gnu`

### `host-utility`
Build the host utility for x86_64 and ARM64 Linux.

```bash
cargo xtask host-utility
```

### `image`
Build the bootable SD card image via buildroot.

```bash
cargo xtask image                  # Hardened build
cargo xtask image --dev            # Development build (SSH enabled)
```

**Prerequisites:** Buildroot in `./buildroot/`, ~10GB disk space

### `release`
Full release build: bump version, test, build all artifacts, and tag.

```bash
cargo xtask release                # Build and tag locally
cargo xtask release --clean        # Clean before building
cargo xtask release --github       # Also publish to GitHub
cargo xtask release --website      # Also publish website
```

Version is automatically bumped based on conventional commits (feat → minor, fix → patch, breaking → major). A local git tag is created to prevent duplicate releases.

### `publish`
Publish existing release artifacts without rebuilding.

```bash
cargo xtask publish --github       # Publish to GitHub releases
cargo xtask publish --website      # Publish website to Cloudflare Pages
cargo xtask publish --github --website  # Both
```

### `test`
Run test suites.

```bash
cargo xtask test
cargo xtask test --no-fuzz         # Skip proptest fuzzing
```

### `clean`
Remove build artifacts.

```bash
cargo xtask clean
cargo xtask clean --buildroot      # Also clean buildroot output
```

### `validate`
Check build environment prerequisites.

```bash
cargo xtask validate
```

## Troubleshooting

### "Command not found: cargo xtask"
Make sure you're in the project directory (alias defined in `.cargo/config.toml`).

### "Failed to execute: aarch64-linux-gnu-gcc"
```bash
sudo apt install gcc-aarch64-linux-gnu
```

### "Target not installed"
```bash
rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu
```

Run `cargo xtask validate` to check all prerequisites.
