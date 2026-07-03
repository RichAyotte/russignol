# russignol-signer Quick Reference

Fast reference guide for common commands.

The binary is `russignol-signer-lib`. It has no key generation or import commands — key material is provisioned externally (e.g. with `octez-client`) as OCaml-format wallet files (`public_key_hashs`, `public_keys`, `secret_keys`).

## Quick Commands

```bash
# List all keys
russignol-signer-lib list known addresses

# Show key details (public data only)
russignol-signer-lib show address <NAME>

# Use custom directory
russignol-signer-lib --base-dir <PATH> <COMMAND>

# Launch TCP signer server
russignol-signer-lib --base-dir ~/.tezos-signer launch socket signer
```

## Common Workflows

### First Time Setup
```bash
# Build
cargo build --release -p russignol-signer-lib

# Provision a key with octez-client (or copy an existing wallet)
octez-client --base-dir ~/.tezos-signer gen keys my_baker --sig bls

# Show tz4 address
./target/release/russignol-signer-lib --base-dir ~/.tezos-signer show address my_baker
```

### OCaml Compatibility
```bash
# Use OCaml directory
russignol-signer-lib --base-dir ~/.tezos-signer list known addresses
russignol-signer-lib --base-dir ~/.tezos-signer show address my_baker
```

### Backup Keys
```bash
# Backup the three wallet files
cp ~/.tezos-signer/{public_key_hashs,public_keys,secret_keys} ~/backup/

# Restore
cp ~/backup/{public_key_hashs,public_keys,secret_keys} ~/.tezos-signer/
```

### Raspberry Pi Deploy
```bash
# Build for ARM
cargo build --release --target=aarch64-unknown-linux-gnu

# Copy to Pi
scp target/aarch64-unknown-linux-gnu/release/russignol-signer-lib pi@raspberrypi.local:~/

# SSH and use
ssh pi@raspberrypi.local
./russignol-signer-lib --base-dir ~/.tezos-signer list known addresses
```

## TCP Signer Server

### Production CLI

```bash
# Launch the TCP signer server (keys must already exist in the base dir)
russignol-signer-lib --base-dir ~/.tezos-signer launch socket signer \
  --address 127.0.0.1 \
  --port 7732 \
  --magic-bytes 0x11,0x12,0x13 \
  --check-high-watermark

# Server loads all keys and starts listening:
# Loading 1 key(s)...
#   ✓ Loaded key: my_baker (JSON: tz4..., Derived: tz4...)
# ✓ High watermark protection enabled
# 🚀 Starting signer server on 127.0.0.1:7732

# Options:
# -a, --address <ADDRESS>         Listen address (default: localhost)
# -p, --port <PORT>               Listen port (default: 7732)
# -M, --magic-bytes <BYTES>       Filter by magic bytes (e.g., 0x11,0x12,0x13)
# -W, --check-high-watermark      Enable high watermark protection
#     --allow-list-known-keys     Allow the KnownKeys request
#     --allow-to-prove-possession Allow BLS proof-of-possession requests
# -A, --require-authentication    Require authentication (not yet implemented)
# -t, --timeout <SECONDS>         Connection timeout in seconds
# -P, --pidfile <PATH>            Write PID to file
```

Without `--allow-list-known-keys` / `--allow-to-prove-possession`, KnownKeys and proof-of-possession requests are refused.

### Start Demo Server
```bash
# Start server on localhost:8080 (with 2 test keys)
cargo run --example tcp_server_demo

# Server output:
# 🌐 Starting TCP server on 127.0.0.1:8080
# 📡 Waiting for connections...
```

### Test Server
```bash
# Terminal 1: Start server
cargo run --example tcp_server_demo

# Terminal 2: Run the test client
cargo run --example tcp_client_test

# Exercises 6 scenarios:
# ✓ Get public key
# ✓ List known keys
# ✗ Sign at level 100 — rejected: the demo server does not initialize
#   watermarks, and watermarks must exist before the first signature
# ✗ Sign at level 99 — rejected (same reason)
# ✗ Sign at level 101 — rejected (same reason)
# ✓ Check deterministic nonce support
```

### Manual Testing
```bash
# Connect with netcat
nc 127.0.0.1 8080

# Or use telnet
telnet 127.0.0.1 8080
```

### Server Features
- ✅ All request types (Sign, PublicKey, KnownKeys, etc.); KnownKeys and proof-of-possession are gated behind `--allow-*` flags (the demo enables both)
- ✅ High watermark protection (prevents double-signing; requires initialized watermarks)
- ✅ Magic byte filtering (Tenderbake-only: 0x11, 0x12, 0x13)
- ✅ Concurrent connections (one thread per connection, default limit: 4)
- ✅ Thread-safe key access

## Key Formats

| Format | Prefix | Example | Description |
|--------|--------|---------|-------------|
| Address | `tz4` | `tz4VkfT...` | Public key hash |
| Public Key | `BLpk` | `BLpk1uZk...` | BLS public key |
| Secret Key | `BLsk` | `BLsk2Ab7...` | BLS secret key |

## Storage Locations

| Platform | Default Path |
|----------|--------------|
| Linux | `~/.local/share/signer/` |
| macOS (untested) | `~/Library/Application Support/org.tezos.signer/` |
| Windows (untested) | `%APPDATA%\tezos\signer\data\` |
| OCaml Mode | `~/.tezos-signer/` (with `--base-dir`) |

Keys live in three files in the base directory: `public_key_hashs`, `public_keys`, `secret_keys` (see [USAGE.md](USAGE.md) for the format).

## Options Reference

### Global Options
- `-d, --base-dir <PATH>` - Custom directory
- `-h, --help` - Show help
- `-V, --version` - Show version

### launch socket signer Options
- `-a, --address <ADDRESS>` - Listen address (default: localhost)
- `-p, --port <PORT>` - Listen port (default: 7732)
- `-M, --magic-bytes <BYTES>` - Magic byte filter
- `-W, --check-high-watermark` - Enable high watermark protection
- `--allow-list-known-keys` - Allow KnownKeys requests
- `--allow-to-prove-possession` - Allow proof-of-possession requests
- `-A, --require-authentication` - Not yet implemented
- `-t, --timeout <SECONDS>` - Connection timeout
- `-P, --pidfile <PATH>` - Write PID to file

## Error Messages

| Error | Solution |
|-------|----------|
| No keys found | Provision wallet files in the base dir (see [USAGE.md](USAGE.md)) |
| Key '...' not found | Check the alias with `list known addresses` and the `--base-dir` |
| Watermark not initialized | Initialize watermark files before the first signature |
| Listing known keys is not authorized | Launch with `--allow-list-known-keys` |
| Proof of possession is not authorized | Launch with `--allow-to-prove-possession` |

## Security Checklist

- [ ] Secret keys stored in plaintext - secure file permissions
- [ ] Set `chmod 600 ~/.tezos-signer/secret_keys`
- [ ] Backup keys to secure location
- [ ] Never share secret keys (BLsk)

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_key_generation

# Run benchmarks
cargo bench

# Workspace-wide (from the repo root)
cargo xtask test
```

## Getting Help

```bash
# Main help
russignol-signer-lib --help

# Command help
russignol-signer-lib list --help
russignol-signer-lib show --help
russignol-signer-lib launch --help
```

## Documentation

- **Full Usage Guide**: [USAGE.md](USAGE.md)
- **Technical Details**: [README.md](README.md)
