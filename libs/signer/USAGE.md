# russignol-signer Usage Guide

Complete guide to using the `russignol-signer-lib` CLI for BLS12-381 signing on Tezos.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Key Provisioning](#key-provisioning)
- [Storage Locations](#storage-locations)
- [Common Workflows](#common-workflows)
- [Examples](#examples)
- [Compatibility](#compatibility)
- [Troubleshooting](#troubleshooting)

## Installation

### Build from Source

```bash
# From the workspace root
cargo build --release -p russignol-signer-lib

# Binary location
./target/release/russignol-signer-lib

# Optional: install to the cargo bin directory (installs as `russignol-signer-lib`)
cargo install --path libs/signer
```

### Cross-Compile for Raspberry Pi

```bash
# Install ARM toolchain
sudo apt-get install gcc-aarch64-linux-gnu
rustup target add aarch64-unknown-linux-gnu

# Build for ARM64
cargo build --release --target=aarch64-unknown-linux-gnu

# Deploy to Raspberry Pi
scp target/aarch64-unknown-linux-gnu/release/russignol-signer-lib pi@raspberrypi.local:~/
```

## Quick Start

Provision a key with `octez-client` (this CLI does not generate keys):

```bash
octez-client --base-dir ~/.tezos-signer gen keys my_baker --sig bls
```

List your keys:

```bash
./target/release/russignol-signer-lib --base-dir ~/.tezos-signer list known addresses
```

Show key details:

```bash
./target/release/russignol-signer-lib --base-dir ~/.tezos-signer show address my_baker
```

Launch the TCP signer:

```bash
./target/release/russignol-signer-lib --base-dir ~/.tezos-signer launch socket signer
```

## Command Reference

### Global Options

These options can be used with any command:

```bash
--base-dir <PATH>, -d <PATH>
    Specify custom signer data directory
    Default: ~/.local/share/signer/ on Linux
    (falls back to ~/.tezos-signer if the platform directory lookup fails)

    Example:
    russignol-signer-lib --base-dir ~/.tezos-signer list known addresses

--help, -h
    Show help message

--version, -V
    Show version information
```

### Commands

#### `list known addresses` - List All Keys

Display all stored keys.

```bash
russignol-signer-lib list known addresses
```

**Examples:**

```bash
# List all keys
russignol-signer-lib list known addresses

# List keys from custom directory
russignol-signer-lib --base-dir ~/.tezos-signer list known addresses
```

**Output:**

```
Known keys:
Alias                Address
============================================================
my_baker             tz4VkfTGTaaVPjcXRniznS9vKVR6JZZbE8mj
validator1           tz4GQqkKCM1m5uQEBMyrKQiREjCM1QmMM3HQ
```

#### `show address` - Show Key Details

Display details for a specific key. Only public data is shown — the CLI never displays secret keys.

```bash
russignol-signer-lib show address <NAME>
```

**Arguments:**
- `<NAME>` - Alias of the key to show (required)

**Output:**

```
Key: my_baker
  Public Key Hash: tz4VkfTGTaaVPjcXRniznS9vKVR6JZZbE8mj
  Public Key:      BLpk1uZkN...
```

#### `launch socket signer` - Start the TCP Signer Server

Load all keys from the base directory and serve the octez remote-signer TCP protocol.

```bash
russignol-signer-lib [--base-dir <PATH>] launch socket signer [OPTIONS]
```

**Options:**
- `-a, --address <ADDRESS>` - Listen address (default: `localhost`)
- `-p, --port <PORT>` - Listen port (default: `7732`)
- `-M, --magic-bytes <BYTES>` - Magic byte filter, comma-separated hex (e.g. `0x11,0x12,0x13`); without it, all magic bytes are allowed
- `-W, --check-high-watermark` - Enable high watermark protection
- `--allow-list-known-keys` - Allow the KnownKeys request (refused otherwise)
- `--allow-to-prove-possession` - Allow BLS proof-of-possession requests (refused otherwise)
- `-A, --require-authentication` - Require authentication (not yet implemented; the server refuses to start with this flag)
- `-t, --timeout <SECONDS>` - Connection read/write timeout
- `-P, --pidfile <PATH>` - Write PID to file

**Example:**

```bash
russignol-signer-lib --base-dir ~/.tezos-signer launch socket signer \
  --address 127.0.0.1 --port 7732 \
  --magic-bytes 0x11,0x12,0x13 \
  --check-high-watermark
```

**Notes:**
- Only keys with an `unencrypted:` entry in `secret_keys` are loaded; `encrypted:` entries are skipped
- With `-W`, watermarks must be initialized before the first signature; signing with no existing watermark entry is rejected (see [README.md](README.md) for the watermark semantics)

## Key Provisioning

This CLI has no key generation or import commands. Provision keys externally:

- **`octez-client`**: generate or import keys into a shared base directory (e.g. `octez-client --base-dir ~/.tezos-signer gen keys my_baker --sig bls`), then point this signer at the same directory with `--base-dir`
- **Copy an existing wallet**: place the three wallet files in the base directory

For programmatic use, the library exposes `wallet::KeyManager::gen_keys_in_memory`, which generates a keypair without writing anything to disk; `save_public_keys_only` persists only the two public files. Secret keys are never written to disk by this crate — persisting them (encrypted) is the caller's responsibility.

### Key Generation Properties

Keys generated by the library use cryptographically secure randomness (via the `getrandom` crate):

- **Algorithm**: BLS12-381 (MinPk variant with proof-of-possession)
- **Key Size**: 32 bytes (256 bits) of entropy
- **Address Format**: tz4 (Tezos BLS public key hash)

### Storage Format

Keys are stored in the OCaml-compatible wallet format: three JSON files in the base directory.

**`public_key_hashs`:**
```json
[{"name": "my_baker", "value": "tz4VkfTGTaaVPjcXRniznS9vKVR6JZZbE8mj"}]
```

**`public_keys`:**
```json
[{"name": "my_baker", "value": {"locator": "unencrypted:BLpk1uZkN...", "key": "BLpk1uZkN..."}}]
```

**`secret_keys`:**
```json
[{"name": "my_baker", "value": "unencrypted:BLsk2Ab7h..."}]
```

`encrypted:` values in `secret_keys` are skipped when loading.

### Security Considerations

⚠️ **Important Security Notes:**

1. **Unencrypted Storage**: `unencrypted:` secret keys are plaintext
2. **File Permissions**: Ensure restrictive permissions on the secret key file:
   ```bash
   chmod 600 ~/.tezos-signer/secret_keys
   ```
3. **Backup**: Always backup your keys securely:
   ```bash
   cp ~/.tezos-signer/{public_key_hashs,public_keys,secret_keys} /secure/backup/location/
   ```
4. **Production Use**: For production, consider:
   - Hardware Security Modules (HSM)
   - Encrypted key storage
   - Air-gapped signing systems

## Storage Locations

### Default Directories (Platform-Specific)

| Platform | Default Location |
|----------|------------------|
| Linux | `~/.local/share/signer/` |
| macOS (untested) | `~/Library/Application Support/org.tezos.signer/` |
| Windows (untested) | `C:\Users\<USER>\AppData\Roaming\tezos\signer\data\` |

### OCaml Compatibility Mode

The wallet format is identical to `octez-client` / `octez-signer` — to share a wallet, just point `--base-dir` at the same directory:

```bash
russignol-signer-lib --base-dir ~/.tezos-signer list known addresses
```

### Directory Structure

```
~/.tezos-signer/
├── public_key_hashs               # [{"name": ..., "value": "tz4..."}]
├── public_keys                    # [{"name": ..., "value": {"locator": ..., "key": ...}}]
├── secret_keys                    # [{"name": ..., "value": "unencrypted:BLsk..."}]
└── tz4.../                        # per-key watermark directory (with --check-high-watermark)
    ├── block_watermark            # 40-byte binary: level + round + Blake3
    ├── preattestation_watermark
    └── attestation_watermark
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for the watermark file format.

## Common Workflows

### 1. Setting Up a New Baker

```bash
# Generate the baker key with octez-client in a shared directory
octez-client --base-dir ~/.tezos-signer gen keys my_baker --sig bls

# Show the tz4 address
russignol-signer-lib --base-dir ~/.tezos-signer show address my_baker

# Launch the signer for the baker
russignol-signer-lib --base-dir ~/.tezos-signer launch socket signer \
  --magic-bytes 0x11,0x12,0x13 --check-high-watermark
```

### 2. Using an Existing OCaml Wallet

No migration is needed — the wallet format is the same:

```bash
russignol-signer-lib --base-dir ~/.tezos-signer list known addresses
russignol-signer-lib --base-dir ~/.tezos-signer show address my_baker
```

### 3. Backup and Restore

**Backup:**
```bash
# Backup the wallet files (and watermark directories, if any)
tar -czf signer-backup-$(date +%Y%m%d).tar.gz -C ~ .tezos-signer
```

**Restore:**
```bash
tar -xzf signer-backup-20250114.tar.gz -C ~

# Verify restored keys
russignol-signer-lib --base-dir ~/.tezos-signer list known addresses
```

### 4. Using Custom Directory for Different Networks

```bash
# Mainnet keys
russignol-signer-lib --base-dir ~/.tezos-signer-mainnet list known addresses

# Testnet keys
russignol-signer-lib --base-dir ~/.tezos-signer-ghostnet list known addresses
```

## Examples

### Example 1: Complete Setup

```bash
# Build the signer
cargo build --release -p russignol-signer-lib

# Create an alias for convenience
alias russignol-signer-lib="./target/release/russignol-signer-lib"

# Provision a key
octez-client --base-dir ~/.tezos-signer gen keys my_first_key --sig bls

# View the address
russignol-signer-lib --base-dir ~/.tezos-signer show address my_first_key

# List all keys
russignol-signer-lib --base-dir ~/.tezos-signer list known addresses
```

### Example 2: Raspberry Pi Deployment

```bash
# On development machine
cargo build --release --target=aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/russignol-signer-lib pi@raspberrypi.local:~/

# On Raspberry Pi (wallet files already provisioned)
ssh pi@raspberrypi.local
chmod +x russignol-signer-lib
./russignol-signer-lib --base-dir ~/.tezos-signer list known addresses
./russignol-signer-lib --base-dir ~/.tezos-signer launch socket signer -W
```

### Example 3: Serving a Baker

```bash
# Terminal 1: launch the signer
russignol-signer-lib --base-dir ~/.tezos-signer launch socket signer \
  --address 127.0.0.1 --port 7732 --magic-bytes 0x11,0x12,0x13 -W

# Terminal 2: register the remote key with octez-client
octez-client import secret key my_baker tcp://127.0.0.1:7732/tz4...
```

## Compatibility

### OCaml octez-signer Compatibility

The Rust implementation is compatible with the OCaml `octez-signer` for:

✅ **Compatible:**
- BLS12-381 key format (BLsk, BLpk, tz4)
- Base58Check encoding
- Key derivation from seed
- Proof of possession
- Signature format
- Wallet file format (`public_key_hashs`, `public_keys`, `secret_keys`)
- TCP remote signer protocol

⚠️ **Differences:**
- No key generation or import commands (use `octez-client`)
- Secret keys are never written to disk by this signer
- High watermark storage uses a Rust-specific binary format (not shared with OCaml watermark files)
- No HTTP interface

### Command Comparison

| OCaml Command | Rust Command | Status |
|---------------|--------------|--------|
| `octez-client list known addresses` | `russignol-signer-lib list known addresses` | ✅ Compatible |
| `octez-client show address <name>` | `russignol-signer-lib show address <name>` | ✅ Compatible (public data only) |
| `octez-signer launch socket signer` | `russignol-signer-lib launch socket signer` | ✅ Compatible |
| `octez-client gen keys <name> --sig bls` | Not implemented (use `octez-client`) | ❌ |
| `octez-client import secret key <name> <sk>` | Not implemented (use `octez-client`) | ❌ |
| `octez-signer launch http signer` | Not implemented | ❌ |

## Troubleshooting

### Error: "No keys found"

The base directory has no wallet files. Provision keys first (see [Key Provisioning](#key-provisioning)) and check `--base-dir` points at the right directory.

### Error: "Key '<name>' not found"

```bash
# Check which aliases exist and in which directory
russignol-signer-lib --base-dir ~/.tezos-signer list known addresses
```

### Error: "Failed to load key"

The key's `secret_keys` entry is missing or `encrypted:` (encrypted entries are skipped). Provide an `unencrypted:BLsk...` entry.

### Error: watermark "not initialized"

With `--check-high-watermark`, a key/operation with no existing watermark entry cannot sign. Initialize the watermark files before the first signature (see [DEVELOPMENT.md](DEVELOPMENT.md) for the file format).

### Keys not showing up

```bash
# Check the correct directory
russignol-signer-lib --base-dir ~/.tezos-signer list known addresses

# Verify public_key_hashs exists and is valid JSON
cat ~/.tezos-signer/public_key_hashs
```

Note: if `public_key_hashs` contains invalid JSON, the key list is empty.

## Getting Help

### Built-in Help

```bash
# Main help
russignol-signer-lib --help

# Command-specific help
russignol-signer-lib list --help
russignol-signer-lib show --help
russignol-signer-lib launch --help
```

### Additional Resources

- **GitHub Issues**: Report bugs and request features
- **Documentation**: See `README.md` for technical details
- **OCaml Reference**: [Tezos Octez Documentation](https://tezos.gitlab.io/)

## Version Information

```bash
# Show version
russignol-signer-lib --version

# Output: russignol-signer 0.6.4
```
