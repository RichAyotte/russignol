# russignol-signer Rust

High-performance BLS12-381 signer for Tezos, optimized for **Raspberry Pi Zero 2W** (ARM Cortex-A53).

This is a minimal, lightweight port of the Tezos `octez-signer` from OCaml to Rust, focusing exclusively on BLS12-381 signatures with Tenderbake consensus support.

## Documentation

📖 **[USAGE.md](USAGE.md)** - CLI usage guide
⚡ **[QUICKREF.md](QUICKREF.md)** - Quick command reference
🔧 **[DEVELOPMENT.md](DEVELOPMENT.md)** - Development guide and testing
📋 **[PROTOCOL_SPECIFICATION.md](PROTOCOL_SPECIFICATION.md)** - Wire protocol details

## TCP Signer Server

Full TCP server implementation compatible with the OCaml octez-client protocol:

```bash
# Production: launch with the CLI (loads keys from an OCaml-format wallet directory)
russignol-signer-lib --base-dir ~/.tezos-signer launch socket signer \
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
- ✅ CLI: `russignol-signer-lib launch socket signer`
- ✅ All request types (Sign, PublicKey, KnownKeys, etc.; KnownKeys and proof-of-possession require `--allow-list-known-keys` / `--allow-to-prove-possession`)
- ✅ High watermark protection (prevents double-signing; watermarks must be initialized before the first signature)
- ✅ Magic byte filtering (Tenderbake consensus)
- ✅ Synchronous TCP server, one thread per connection (default limit: 4 concurrent connections)

See **[PROTOCOL_SPECIFICATION.md](PROTOCOL_SPECIFICATION.md)** for protocol details.

## Features

- **BLS12-381 Only**: Focused implementation for modern Tezos consensus
- **Tenderbake Magic Bytes**: Filter that only signs blocks (0x11), preattestations (0x12), and attestations (0x13)
- **ARM Cortex-A53 Optimized**: NEON SIMD acceleration, cache-aligned memory access
- **Minimal Binary Size**: Aggressive LTO and size optimizations
- **Low Latency**: Stack-allocated buffers, minimal heap allocations
- **Constant-Time**: Side-channel resistant cryptographic operations
- **1:1 OCaml Port**: Direct mapping from the OCaml Tezos signer

## OCaml Compatibility

This implementation is compatible with the OCaml `octez-signer`:

- ✅ **Key file format**: Reads the same three files (`public_key_hashs`, `public_keys`, `secret_keys`); writes only the two public files — secret keys are never written to disk by this library
- ✅ **TCP protocol**: Binary-compatible with the `octez-client` remote signer protocol
- ✅ **Base58check encoding**: Identical encoding for keys, signatures, and hashes
- ⚠️ **High watermark storage**: Rust-specific format — per-key directories of 40-byte binary files (see [DEVELOPMENT.md](DEVELOPMENT.md)); not shared with OCaml watermark files

### Secret Key Byte Order and Out-of-Range Keys

Tezos stores BLS12-381 secret keys as little-endian scalars, while the BLST library expects big-endian bytes; keys are byte-reversed on load. The most significant byte of a stored key is therefore the *last* byte — a key file beginning `0xb5...` is not necessarily out of range.

If a key's little-endian value is >= `r` (the BLS12-381 scalar field order), it is rejected on load, matching octez.

See the bls module documentation for technical details.

## Quick Start

### Build and Install

```bash
# From the workspace root
cargo build --release -p russignol-signer-lib

# Run tests
cargo test -p russignol-signer-lib

# The CLI binary is at:
./target/release/russignol-signer-lib
```

### Key Management (CLI)

The CLI reads keys from an OCaml-format wallet directory (`public_key_hashs`, `public_keys`, `secret_keys`). Key material is provisioned externally — for example generated with `octez-client` — and is not created by this CLI.

```bash
# List all keys
./target/release/russignol-signer-lib list known addresses

# Show key details (public data only)
./target/release/russignol-signer-lib show address my_baker

# Use the OCaml wallet directory
./target/release/russignol-signer-lib --base-dir ~/.tezos-signer list known addresses

# Launch the TCP signer
./target/release/russignol-signer-lib --base-dir ~/.tezos-signer launch socket signer
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
# Release build (LTO + size optimizations from the workspace profile)
cargo build --release --target=aarch64-unknown-linux-gnu

# Binary location
ls -lh target/aarch64-unknown-linux-gnu/release/russignol-signer-lib
```

#### Deploy to Raspberry Pi Zero 2W

```bash
# Copy to Pi Zero 2W
scp target/aarch64-unknown-linux-gnu/release/russignol-signer-lib pi@raspberrypi.local:~/

# SSH and run
ssh pi@raspberrypi.local
chmod +x russignol-signer-lib
./russignol-signer-lib --help
```

## Performance Benchmarks

Run benchmarks on your platform:

```bash
# Native benchmarks
cargo bench

# Cross-compile and run on Pi Zero 2W
cargo build --release --target=aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/russignol-signer-lib pi@raspberrypi.local:~/
ssh pi@raspberrypi.local './russignol-signer-lib --help'
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
russignol-signer-lib = { path = "libs/signer" }
```

Example code:

```rust
use russignol_signer_lib::signer::{Unencrypted, Handler};

// Generate a BLS12-381 keypair (random seed)
let signer = Unencrypted::generate(None).unwrap();

// Create handler with Tenderbake-only magic bytes (0x11, 0x12, 0x13)
let handler = Handler::new_tenderbake_only(signer);

// Sign Tenderbake block
let block_data = b"\x11\x00\x00\x00\x01...";  // Magic byte 0x11 + block data
let signature = handler.sign(block_data, None, None).unwrap();

// Get tz4 address
let pkh = handler.public_key_hash();
println!("Address: {}", pkh.to_b58check());

// Prove possession
let proof = handler.bls_prove_possession(None).unwrap();
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for an overview of the library API (modules, server configuration, callbacks).

## Magic Byte Filtering

When the Tenderbake magic-byte filter is enabled (`--magic-bytes 0x11,0x12,0x13` on the CLI, or `Handler::new_tenderbake_only` in the library), only the following consensus operations are signed:

| Magic Byte | Operation | Description |
|------------|-----------|-------------|
| `0x11` | Tenderbake Block | Block proposal |
| `0x12` | Tenderbake Preattestation | Pre-vote on block |
| `0x13` | Tenderbake Attestation | Final vote on block |

Legacy Emmy operations (`0x01`, `0x02`) are rejected when the filter is enabled. Without a filter, all magic bytes are allowed.

## High Watermark Protection

With `--check-high-watermark`, the signer refuses to sign a consensus operation at or below the last signed level/round for that key and operation type (block, preattestation, attestation): the level must be strictly higher, or the round strictly higher at the same level.

Watermarks must be initialized before the first signature — a sign request for a key/operation with no existing watermark entry is rejected. A corrupt watermark file prevents the signer from starting (manual re-initialization required). The library additionally supports large level-gap detection (rejecting requests more than 4 cycles ahead of the current watermark) when configured with a gap callback.

See [DEVELOPMENT.md](DEVELOPMENT.md) for the on-disk watermark format.

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

Keys are stored in the OCaml-compatible wallet format: three JSON files in the base directory.

| File | Contents |
|------|----------|
| `public_key_hashs` | `[{"name": "<alias>", "value": "tz4..."}]` |
| `public_keys` | `[{"name": "<alias>", "value": {"locator": "unencrypted:BLpk...", "key": "BLpk..."}}]` |
| `secret_keys` | `[{"name": "<alias>", "value": "unencrypted:BLsk..."}]` |

**Default base directory:**
- Linux: `~/.local/share/signer/`
- macOS (untested): `~/Library/Application Support/org.tezos.signer/`
- Windows (untested): `%APPDATA%\tezos\signer\data\`

**OCaml Compatible Mode:**
```bash
# Use the same directory as octez-client / octez-signer
russignol-signer-lib --base-dir ~/.tezos-signer list known addresses
```

**Security Notes:**
- Secret keys in `secret_keys` are plaintext (`unencrypted:BLsk...`); `encrypted:` entries are skipped on load
- This library reads `secret_keys` but never writes it — persisting secret keys (encrypted) is the caller's responsibility
- Set restrictive file permissions: `chmod 600 ~/.tezos-signer/secret_keys`
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
sudo nice -n -20 ./russignol-signer-lib

# Pin to specific CPU core
taskset -c 0 ./russignol-signer-lib
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
ldd ./russignol-signer-lib

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
| `list known addresses` | List all stored keys |
| `show address <name>` | Display key details (public data only) |
| `launch socket signer` | Start the TCP signer server |

### Global Options

| Option | Description |
|--------|-------------|
| `--base-dir <PATH>`, `-d` | Signer data directory |
| `--help`, `-h` | Show help message |
| `--version`, `-V` | Show version |

### `launch socket signer` Options

| Option | Description |
|--------|-------------|
| `-a, --address <ADDRESS>` | Listen address (default: `localhost`) |
| `-p, --port <PORT>` | Listen port (default: `7732`) |
| `-M, --magic-bytes <BYTES>` | Magic byte filter, comma-separated hex (e.g. `0x11,0x12,0x13`) |
| `-W, --check-high-watermark` | Enable high watermark protection |
| `--allow-list-known-keys` | Allow the KnownKeys request |
| `--allow-to-prove-possession` | Allow BLS proof-of-possession requests |
| `-A, --require-authentication` | Require authentication (not yet implemented) |
| `-t, --timeout <SECONDS>` | Connection timeout in seconds |
| `-P, --pidfile <PATH>` | Write PID to file |

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

# Test CLI (against an existing wallet directory)
cargo run --release -- --base-dir ~/.tezos-signer list known addresses
cargo run --release -- --base-dir ~/.tezos-signer show address my_baker

# Profile (requires `perf` on Linux)
cargo build --release --target=aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/russignol-signer-lib pi@raspberrypi.local:~/
ssh pi@raspberrypi.local 'perf record -g ./russignol-signer-lib'
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
