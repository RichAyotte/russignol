# russignol-signer Rust

High-performance BLS12-381 signer for Tezos, optimized for **Raspberry Pi Zero 2W** (ARM Cortex-A53).

This is a minimal, lightweight port of the Tezos `russignol-signer` from OCaml to Rust, focusing exclusively on BLS12-381 signatures with Tenderbake consensus support.

## Documentation

📖 **[USAGE.md](USAGE.md)** - CLI usage guide
⚡ **[QUICKREF.md](QUICKREF.md)** - Quick command reference
🔧 **[DEVELOPMENT.md](DEVELOPMENT.md)** - Development guide and testing
📋 **[PROTOCOL_SPECIFICATION.md](PROTOCOL_SPECIFICATION.md)** - Wire protocol details

## TCP Signer Server ⭐ NEW

Full TCP server implementation compatible with OCaml octez-client protocol:

```bash
# Production: Launch with CLI (loads all your keys)
russignol-signer gen keys my_baker --sig bls
russignol-signer launch socket signer \
  --address 127.0.0.1 \
  --port 7732 \
  --magic-bytes 0x11,0x12,0x13 \
  --check-high-watermark

# Or for testing: Start demo server (with test keys)
cargo run --example tcp_server_demo

# Test it
cargo run --example tcp_client_test
```

**Features:**
- ✅ Production-ready CLI: `russignol-signer launch socket signer`
- ✅ All request types (Sign, PublicKey, KnownKeys, etc.)
- ✅ High watermark protection (prevents double-signing)
- ✅ Magic byte filtering (Tenderbake consensus)
- ✅ Async I/O with Tokio (concurrent connections)

See **[PROTOCOL_SPECIFICATION.md](PROTOCOL_SPECIFICATION.md)** for protocol details.

## Features

- **BLS12-381 Only**: Focused implementation for modern Tezos consensus
- **Tenderbake Magic Bytes**: Only signs blocks (0x11), preattestations (0x12), and attestations (0x13)
- **ARM Cortex-A53 Optimized**: NEON SIMD acceleration, cache-aligned memory access
- **Minimal Binary Size**: Aggressive LTO and size optimizations
- **Low Latency**: Stack-allocated buffers, minimal heap allocations
- **Constant-Time**: Side-channel resistant cryptographic operations
- **1:1 OCaml Port**: Direct mapping from OCaml Tezos signer

## OCaml Compatibility

This implementation is fully compatible with the OCaml `russignol-signer`, including:

- ✅ **Key file format**: Reads/writes same three files (`public_key_hashs`, `public_keys`, `secret_keys`)
- ✅ **High watermark format**: Uses same three files (`block_high_watermarks`, `attestation_high_watermarks`, `preattestation_high_watermarks`)
- ✅ **TCP protocol**: Binary-compatible with `octez-client` remote signer protocol
- ✅ **Base58check encoding**: Identical encoding for keys, signatures, and hashes

### Important: Out-of-Range Secret Keys

The BLST library strictly validates that secret keys must be in range `[0, r)` where `r` is the BLS12-381 scalar field order. However, some existing Tezos key files contain keys with values >= r.

**This implementation handles this automatically** by reducing out-of-range keys modulo r, matching OCaml's lenient behavior. This ensures:
- Existing key files work without modification
- Keys are cryptographically equivalent after reduction
- No manual intervention needed

**Example**: A key like `BLsk2snGqdSb7qBDhKbc62AxbZXJycDvA5QmeYYhB7Nb3wFuMMbq9x` (value `0xb5...`) is automatically reduced to a valid key (value `0x41...`) when loaded.

See the bls module documentation for technical details.

## Quick Start

### Build and Install

```bash
# Clone and build
cd russignol-signer-rust
cargo build --release

# Run tests
cargo test

# The CLI binary is at:
./target/release/russignol-signer
```

### Key Management (CLI)

The signer includes a command-line interface matching the OCaml russignol-signer:

```bash
# Generate a new BLS12-381 key
./target/release/russignol-signer gen keys my_baker --sig bls

# List all keys
./target/release/russignol-signer list known addresses

# Show key details
./target/release/russignol-signer show address my_baker

# Import existing key
./target/release/russignol-signer import secret key imported_key BLsk...

# Use custom directory (OCaml compatible)
./target/release/russignol-signer --base-dir ~/.tezos-signer gen keys my_key --sig bls
```

**📖 See [USAGE.md](USAGE.md) for complete CLI documentation**

### Cross-Compile for Raspberry Pi Zero 2W

#### Prerequisites

```bash
# Install cross-compilation toolchain
sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

# Add Rust target
rustup target add aarch64-unknown-linux-gnu
```

#### Build for Pi Zero 2W

```bash
# Build optimized for size (smaller binary, faster load times)
cargo build --release --target=aarch64-unknown-linux-gnu

# Build optimized for speed (maximum performance)
cargo build --profile=fast --target=aarch64-unknown-linux-gnu

# Binary location
ls -lh target/aarch64-unknown-linux-gnu/release/russignol-signer
```

#### Deploy to Raspberry Pi Zero 2W

```bash
# Copy to Pi Zero 2W
scp target/aarch64-unknown-linux-gnu/release/russignol-signer pi@raspberrypi.local:~/

# SSH and run
ssh pi@raspberrypi.local
chmod +x russignol-signer
./russignol-signer
```

## Performance Benchmarks

Run benchmarks on your platform:

```bash
# Native benchmarks
cargo bench

# Cross-compile and run on Pi Zero 2W
cargo build --release --target=aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/russignol-signer pi@raspberrypi.local:~/
ssh pi@raspberrypi.local './russignol-signer --help'
```

### Expected Performance (Pi Zero 2W @ 1GHz)

| Operation | Time (est.) | Notes |
|-----------|-------------|-------|
| BLS12-381 Sign (32 bytes) | ~5-10 ms | With NEON acceleration |
| BLS12-381 Verify | ~8-15 ms | Pairing computation |
| Key Generation | ~5-10 ms | From 32-byte seed |
| Proof of Possession | ~5-10 ms | BLS signature |
| Deterministic Nonce | ~50 μs | HMAC-SHA256 |
| Base58Check Encode | ~10 μs | PKH/PK/SK |

**Note**: Actual performance depends on CPU frequency, thermal throttling, and system load.

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
russignol-signer = { path = "../russignol-signer-rust" }
```

Example code:

```rust
use russignol_signer::{UnencryptedSigner, SignerHandler};

// Generate BLS12-381 keypair
let signer = UnencryptedSigner::generate(None).unwrap();

// Create handler with Tenderbake-only magic bytes (0x11, 0x12, 0x13)
let handler = SignerHandler::new_tenderbake_only(signer);

// Sign Tenderbake block
let block_data = b"\x11\x00\x00\x00\x01...";  // Magic byte 0x11 + block data
let signature = handler.sign(block_data, None, None).unwrap();

// Get tz4 address
let pkh = handler.public_key_hash();
println!("Address: {}", pkh.to_b58check());

// Prove possession
let proof = handler.bls_prove_possession(None).unwrap();
```

## Magic Byte Filtering

Only the following Tenderbake consensus operations are signed:

| Magic Byte | Operation | Description |
|------------|-----------|-------------|
| `0x11` | Tenderbake Block | Block proposal |
| `0x12` | Tenderbake Preattestation | Pre-vote on block |
| `0x13` | Tenderbake Attestation | Final vote on block |

Legacy Emmy operations (`0x01`, `0x02`) are **rejected** by default.

## Testing

```bash
# Run all unit tests
cargo test

# Run with verbose output
cargo test -- --nocapture
```

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Raspberry Pi Zero 2W (ARM Cortex-A53) | ✅ Primary Target | Full NEON optimization |
| Raspberry Pi 3/4 (ARM Cortex-A53/A72) | ✅ Supported | Better performance |
| ARM64 Generic | ✅ Supported | Portable build |
| x86_64 Linux | ✅ Supported | Development/testing |
| macOS (Apple Silicon) | ⚠️ Untested | M1/M2 chips |
| Windows x86_64 | ⚠️ Untested | Should work |

## Binary Size

The Rust implementation produces a significantly smaller binary than the OCaml version due to LTO and size optimizations.

## Security Considerations

### Constant-Time Operations

- BLS12-381 field arithmetic uses constant-time implementations from `blst`
- HMAC-SHA256 for deterministic nonces (RFC 6979 style)
- No data-dependent branches in cryptographic code paths

### Key Storage

Keys are stored in JSON format:

**Default Location:**
- Linux: `~/.local/share/signer/keys.json`
- macOS (untested): `~/Library/Application Support/org.tezos.signer/keys.json`
- Windows: `%APPDATA%\tezos\signer\keys.json`

**OCaml Compatible Mode:**
```bash
# Use same directory as OCaml russignol-signer
russignol-signer --base-dir ~/.tezos-signer gen keys my_key --sig bls
```

**Security Notes:**
- Keys are stored **unencrypted** in plaintext JSON
- Set restrictive file permissions: `chmod 600 ~/.local/share/signer/keys.json`
- For production use, consider:
  - Hardware Security Modules (HSM)
  - Encrypted key storage
  - Air-gapped signing systems

### Side-Channel Resistance

- Cache-timing attacks: `blst` uses constant-time operations
- Power analysis: Consider hardware countermeasures on embedded platforms
- Fault injection: Use ECC memory on critical systems

## Real-Time Performance Tuning (Pi Zero 2W)

For lowest latency on Raspberry Pi Zero 2W:

```bash
# Set CPU governor to performance mode
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable CPU frequency scaling
sudo systemctl disable ondemand

# Increase process priority
sudo nice -n -20 ./russignol-signer

# Pin to specific CPU core
taskset -c 0 ./russignol-signer
```

## Power Consumption

Estimated power consumption on Pi Zero 2W:

- Idle: ~100 mA @ 5V (0.5W)
- Signing (peak): ~200-300 mA @ 5V (1.0-1.5W)
- Average (1 sign/sec): ~120 mA @ 5V (0.6W)

Suitable for battery-powered applications with proper power management.

## Troubleshooting

### Cross-Compilation Errors

```bash
# If linker fails, install:
sudo apt-get install gcc-aarch64-linux-gnu

# If Rust target missing:
rustup target add aarch64-unknown-linux-gnu
```

### Runtime Errors on Pi Zero 2W

```bash
# Check architecture
uname -m  # Should output: aarch64

# Check for missing libraries
ldd ./russignol-signer

# If libgcc_s.so.1 missing:
sudo apt-get install libgcc-10-dev
```

### Performance Issues

```bash
# Check CPU frequency
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq

# Monitor thermal throttling
vcgencmd measure_temp
vcgencmd get_throttled

# Ensure adequate cooling (heatsink recommended)
```

## CLI Command Reference

### Available Commands

| Command | Description |
|---------|-------------|
| `gen keys <name>` | Generate new BLS12-381 keypair |
| `list known addresses` | List all stored keys |
| `show address <name>` | Display key details |
| `import secret key <name> <BLsk...>` | Import existing secret key |

### Global Options

| Option | Description |
|--------|-------------|
| `--base-dir <PATH>`, `-d` | Custom signer data directory |
| `--help`, `-h` | Show help message |
| `--version`, `-V` | Show version |

### Command Options

| Command | Option | Description |
|---------|--------|-------------|
| `gen keys` | `--sig <ALGORITHM>` | Signature algorithm (default: bls) |
| `gen keys` | `--force`, `-f` | Overwrite existing key |
| `show address` | `--show-secret`, `-S` | Display secret key |
| `import secret key` | `--force`, `-f` | Overwrite existing key |

**📖 See [USAGE.md](USAGE.md) for detailed examples and workflows**

## Development Workflow

```bash
# Format code
cargo fmt

# Lint
cargo clippy -- -D warnings

# Run tests
cargo test

# Run benchmarks
cargo bench

# Build documentation
cargo doc --open

# Test CLI
cargo run --release -- gen keys test_key --sig bls
cargo run --release -- list known addresses

# Profile (requires `perf` on Linux)
cargo build --release --target=aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/russignol-signer pi@raspberrypi.local:~/
ssh pi@raspberrypi.local 'perf record -g ./russignol-signer'
```

## Contributing

This is a strict 1:1 port of the OCaml implementation. When making changes:

1. **Preserve semantics**: Maintain exact behavioral equivalence
2. **Add tests**: Port OCaml tests to Rust with same inputs/outputs
3. **Benchmark**: Verify performance on Pi Zero 2W hardware

## License

MIT License (matching Tezos OCaml codebase)

## References

- [Tezos Octez Signer](https://tezos.gitlab.io/introduction/howtouse.html#signer)
- [BLS12-381 Specification](https://github.com/cfrg/draft-irtf-cfrg-bls-signature)
- [Tenderbake Consensus](https://research-development.nomadic-labs.com/tenderbake.html)
- [BLST Library](https://github.com/supranational/blst)
- [Raspberry Pi Zero 2 W](https://www.raspberrypi.com/products/raspberry-pi-zero-2-w/)

