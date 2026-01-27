# russignol-signer Quick Reference

Fast reference guide for common commands.

## Quick Commands

```bash
# Generate new key
russignol-signer gen keys <NAME> --sig bls

# List all keys
russignol-signer list known addresses

# Show key details
russignol-signer show address <NAME>

# Show with secret key
russignol-signer show address <NAME> --show-secret

# Import key
russignol-signer import secret key <NAME> <BLsk...>

# Use custom directory
russignol-signer --base-dir <PATH> <COMMAND>
```

## Common Workflows

### First Time Setup
```bash
# Build
cargo build --release

# Generate key
./target/release/russignol-signer gen keys my_baker --sig bls

# Show tz4 address
./target/release/russignol-signer show address my_baker
```

### OCaml Compatibility
```bash
# Use OCaml directory
russignol-signer --base-dir ~/.tezos-signer gen keys my_key --sig bls
russignol-signer --base-dir ~/.tezos-signer list known addresses
```

### Backup Keys
```bash
# Backup
cp ~/.local/share/signer/keys.json ~/backup/

# Restore
cp ~/backup/keys.json ~/.local/share/signer/
```

### Raspberry Pi Deploy
```bash
# Build for ARM
cargo build --release --target=aarch64-unknown-linux-gnu

# Copy to Pi
scp target/aarch64-unknown-linux-gnu/release/russignol-signer pi@raspberrypi.local:~/

# SSH and use
ssh pi@raspberrypi.local
./russignol-signer gen keys pi_baker --sig bls
```

## TCP Signer Server

### Production CLI

```bash
# 1. Generate a BLS key first
russignol-signer gen keys my_baker --sig bls

# 2. Launch the TCP signer server
russignol-signer launch socket signer \
  --address 127.0.0.1 \
  --port 7732 \
  --magic-bytes 0x11,0x12,0x13 \
  --check-high-watermark

# Server will load all keys and start listening:
# Loading 1 key(s)...
#   ✓ Loaded key: my_baker (tz4...)
# ✓ High watermark protection enabled
# 🚀 Starting signer server on 127.0.0.1:7732

# Options:
# -a, --address <ADDRESS>         Listen address (default: localhost)
# -p, --port <PORT>               Listen port (default: 7732)
# -M, --magic-bytes <BYTES>       Filter by magic bytes (e.g., 0x11,0x12,0x13)
# -W, --check-high-watermark      Enable high watermark protection
# -t, --timeout <SECONDS>         Connection timeout in seconds
# -P, --pidfile <PATH>            Write PID to file
```

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

# Terminal 2: Run automated tests
cargo run --example tcp_client_test

# Tests 6 scenarios:
# ✓ Get public key
# ✓ List known keys
# ✓ Sign at level 100
# ✓ Reject signing at level 99 (watermark)
# ✓ Sign at level 101
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
- ✅ All request types (Sign, PublicKey, KnownKeys, etc.)
- ✅ High watermark protection (prevents double-signing)
- ✅ Magic byte filtering (Tenderbake-only: 0x11, 0x12, 0x13)
- ✅ Concurrent connections (Tokio async tasks)
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
| Linux | `~/.local/share/signer/keys.json` |
| macOS (untested) | `~/Library/Application Support/org.tezos.signer/keys.json` |
| Windows | `%APPDATA%\tezos\signer\keys.json` |
| OCaml Mode | `~/.tezos-signer/` (with `--base-dir`) |

## Options Reference

### Global Options
- `-d, --base-dir <PATH>` - Custom directory
- `-h, --help` - Show help
- `-V, --version` - Show version

### gen keys Options
- `--sig <ALGORITHM>` - Algorithm (default: bls)
- `-f, --force` - Overwrite existing

### show address Options
- `-S, --show-secret` - Display secret key

### import secret key Options
- `-f, --force` - Overwrite existing

## Error Messages

| Error | Solution |
|-------|----------|
| Key already exists | Use `--force` flag |
| Failed to import | Check BLsk format |
| Permission denied | Run `chmod 755 ~/.local/share/signer` |
| Invalid secret key | Regenerate or verify BLsk string |

## Security Checklist

- [ ] Keys stored in plaintext - secure file permissions
- [ ] Set `chmod 600 ~/.local/share/signer/keys.json`
- [ ] Backup keys to secure location
- [ ] Never share secret keys (BLsk)
- [ ] Use `--show-secret` only when needed

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_key_generation

# Run benchmarks
cargo bench
```

## Getting Help

```bash
# Main help
russignol-signer --help

# Command help
russignol-signer gen --help
russignol-signer list --help
russignol-signer show --help
russignol-signer import --help
```

## Documentation

- **Full Usage Guide**: [USAGE.md](USAGE.md)
- **Technical Details**: [README.md](README.md)

