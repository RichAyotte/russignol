# russignol-signer Usage Guide

Complete guide to using the Rust implementation of russignol-signer for BLS12-381 key management and signing on Tezos.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Key Management](#key-management)
- [Storage Locations](#storage-locations)
- [Common Workflows](#common-workflows)
- [Examples](#examples)
- [Compatibility](#compatibility)

## Installation

### Build from Source

```bash
# Clone the repository
cd russignol-signer-rust

# Build for your platform
cargo build --release

# Binary location
./target/release/russignol-signer

# Optional: Install to system PATH
cargo install --path .
```

### Cross-Compile for Raspberry Pi

```bash
# Install ARM toolchain
sudo apt-get install gcc-aarch64-linux-gnu
rustup target add aarch64-unknown-linux-gnu

# Build for ARM64
cargo build --release --target=aarch64-unknown-linux-gnu

# Deploy to Raspberry Pi
scp target/aarch64-unknown-linux-gnu/release/russignol-signer pi@raspberrypi.local:~/
```

## Quick Start

Generate your first key pair:

```bash
# Generate a new BLS12-381 key
./target/release/russignol-signer gen keys my_baker --sig bls

# Output:
# Generating new BLS12-381 keypair...
#
# Generated key: my_baker
#   Public Key Hash (tz4): tz4...
#   Public Key (BLpk):     BLpk...
```

List your keys:

```bash
./target/release/russignol-signer list known addresses
```

Show key details:

```bash
./target/release/russignol-signer show address my_baker
```

## Command Reference

### Global Options

These options can be used with any command:

```bash
--base-dir <PATH>, -d <PATH>
    Specify custom signer data directory
    Default: ~/.local/share/signer/

    Example:
    russignol-signer --base-dir ~/.tezos-signer gen keys my_key --sig bls

--help, -h
    Show help message

--version, -V
    Show version information
```

### Commands

#### `gen keys` - Generate New Keypair

Generate a new BLS12-381 keypair.

```bash
russignol-signer gen keys <NAME> [OPTIONS]
```

**Arguments:**
- `<NAME>` - Alias for the new key (required)

**Options:**
- `--sig <ALGORITHM>` - Signature algorithm (default: `bls`, only BLS12-381 supported)
- `--force`, `-f` - Overwrite existing key with same name

**Examples:**

```bash
# Generate a new key
russignol-signer gen keys my_baker --sig bls

# Overwrite existing key
russignol-signer gen keys my_baker --sig bls --force

# Generate with custom base directory
russignol-signer --base-dir /secure/keys gen keys validator1 --sig bls
```

**Output:**

```
Generating new BLS12-381 keypair...

Generated key: my_baker
  Public Key Hash (tz4): tz4VkfTGTaaVPjcXRniznS9vKVR6JZZbE8mj
  Public Key (BLpk):     BLpk1uZk...
```

#### `list known addresses` - List All Keys

Display all stored keypairs.

```bash
russignol-signer list known addresses
```

**No arguments or options**

**Examples:**

```bash
# List all keys
russignol-signer list known addresses

# List keys from custom directory
russignol-signer --base-dir ~/.tezos-signer list known addresses
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

Display details for a specific key.

```bash
russignol-signer show address <NAME> [OPTIONS]
```

**Arguments:**
- `<NAME>` - Alias of the key to show (required)

**Options:**
- `--show-secret`, `-S` - Display the secret key (BLsk...)

**Examples:**

```bash
# Show public key information
russignol-signer show address my_baker

# Show including secret key (⚠️ sensitive!)
russignol-signer show address my_baker --show-secret
```

**Output (without --show-secret):**

```
Key: my_baker
  Public Key Hash: tz4VkfTGTaaVPjcXRniznS9vKVR6JZZbE8mj
  Public Key:      BLpk1uZkN...
```

**Output (with --show-secret):**

```
Key: my_baker
  Public Key Hash: tz4VkfTGTaaVPjcXRniznS9vKVR6JZZbE8mj
  Public Key:      BLpk1uZkN...
  Secret Key:      BLsk2Ab7h...
```

#### `import secret key` - Import Existing Key

Import a BLS12-381 secret key.

```bash
russignol-signer import secret key <NAME> <SK_URI> [OPTIONS]
```

**Arguments:**
- `<NAME>` - Alias for the imported key (required)
- `<SK_URI>` - Base58-encoded secret key starting with `BLsk` (required)

**Options:**
- `--force`, `-f` - Overwrite existing key with same name

**Examples:**

```bash
# Import a secret key
russignol-signer import secret key imported_baker BLsk2Ab7hN...

# Import and overwrite existing
russignol-signer import secret key my_baker BLsk2Ab7hN... --force

# Import to custom directory
russignol-signer --base-dir /secure/keys import secret key backup_key BLsk2Ab7hN...
```

**Output:**

```
Importing secret key...

Imported key: imported_baker
  Public Key Hash (tz4): tz4VkfTGTaaVPjcXRniznS9vKVR6JZZbE8mj
  Public Key (BLpk):     BLpk1uZkN...
```

## Key Management

### Key Generation

Keys are generated using cryptographically secure random number generation (via `getrandom` crate):

- **Algorithm**: BLS12-381 (MinPk variant with proof-of-possession)
- **Key Size**: 32 bytes (256 bits) of entropy
- **Address Format**: tz4 (Tezos BLS public key hash)

### Key Storage

Keys are stored in JSON format at:

**Default Location:**
```
~/.local/share/signer/keys.json
```

**Custom Location:**
```bash
russignol-signer --base-dir /path/to/keys gen keys my_key --sig bls
# Stores in: /path/to/keys/keys.json
```

**Storage Format:**

```json
{
  "my_baker": {
    "alias": "my_baker",
    "public_key_hash": "tz4VkfTGTaaVPjcXRniznS9vKVR6JZZbE8mj",
    "public_key": "BLpk1uZkN...",
    "secret_key": "BLsk2Ab7h..."
  }
}
```

### Security Considerations

⚠️ **Important Security Notes:**

1. **Unencrypted Storage**: Secret keys are stored in plaintext JSON
2. **File Permissions**: Ensure restrictive permissions on key files:
   ```bash
   chmod 600 ~/.local/share/signer/keys.json
   ```
3. **Backup**: Always backup your keys securely:
   ```bash
   cp ~/.local/share/signer/keys.json /secure/backup/location/
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
| Windows | `C:\Users\<USER>\AppData\Roaming\tezos\signer\` |

### OCaml Compatibility Mode

To use the same directory as the OCaml russignol-signer:

```bash
# Always specify --base-dir for OCaml compatibility
russignol-signer --base-dir ~/.tezos-signer gen keys my_key --sig bls
russignol-signer --base-dir ~/.tezos-signer list known addresses
```

**Note**: The Rust version uses a single `keys.json` file, while OCaml uses separate files for `secret_keys`, `public_keys`, and `public_key_hashs`.

### Directory Structure

```
~/.local/share/signer/
├── keys.json          # All keys stored here
├── public_keys/       # (reserved for future use)
└── secret_keys/       # (reserved for future use)
```

## Common Workflows

### 1. Setting Up a New Baker

```bash
# Generate baker key
russignol-signer gen keys my_baker --sig bls

# Show the tz4 address
russignol-signer show address my_baker

# Copy the tz4 address for baker registration
# tz4VkfTGTaaVPjcXRniznS9vKVR6JZZbE8mj
```

### 2. Migrating from OCaml Signer

```bash
# Export secret key from OCaml signer
octez-client show address my_baker --show-secret
# Copy the BLsk... secret key

# Import to Rust signer
russignol-signer import secret key my_baker BLsk2Ab7hN...

# Verify import
russignol-signer show address my_baker
```

### 3. Managing Multiple Keys

```bash
# Generate multiple keys
russignol-signer gen keys baker1 --sig bls
russignol-signer gen keys baker2 --sig bls
russignol-signer gen keys validator1 --sig bls

# List all keys
russignol-signer list known addresses

# Show specific key
russignol-signer show address baker1
```

### 4. Backup and Restore

**Backup:**
```bash
# Backup keys file
cp ~/.local/share/signer/keys.json ~/backup/keys-$(date +%Y%m%d).json

# Or backup entire directory
tar -czf signer-backup-$(date +%Y%m%d).tar.gz ~/.local/share/signer/
```

**Restore:**
```bash
# Restore from backup
cp ~/backup/keys-20250114.json ~/.local/share/signer/keys.json

# Verify restored keys
russignol-signer list known addresses
```

### 5. Using Custom Directory for Different Networks

```bash
# Mainnet keys
russignol-signer --base-dir ~/.tezos-signer-mainnet gen keys mainnet_baker --sig bls

# Testnet keys
russignol-signer --base-dir ~/.tezos-signer-ghostnet gen keys testnet_baker --sig bls

# List mainnet keys
russignol-signer --base-dir ~/.tezos-signer-mainnet list known addresses

# List testnet keys
russignol-signer --base-dir ~/.tezos-signer-ghostnet list known addresses
```

## Examples

### Example 1: Complete Setup

```bash
# Build the signer
cargo build --release

# Create an alias for convenience
alias russignol-signer="./target/release/russignol-signer"

# Generate your first key
russignol-signer gen keys my_first_key --sig bls

# View the generated address
russignol-signer show address my_first_key

# List all keys
russignol-signer list known addresses
```

### Example 2: Import and Verify

```bash
# Import existing key
russignol-signer import secret key imported_key BLsk2Y84M3vJhMTE8D...

# Verify it was imported correctly
russignol-signer show address imported_key

# Compare with original (optional)
russignol-signer show address imported_key --show-secret
```

### Example 3: Multiple Networks

```bash
#!/bin/bash
# setup-multi-network.sh

# Mainnet
export MAINNET_DIR=~/.tezos-signer-mainnet
russignol-signer --base-dir $MAINNET_DIR gen keys baker --sig bls
echo "Mainnet baker: $(russignol-signer --base-dir $MAINNET_DIR show address baker | grep 'Public Key Hash' | awk '{print $4}')"

# Ghostnet (testnet)
export GHOSTNET_DIR=~/.tezos-signer-ghostnet
russignol-signer --base-dir $GHOSTNET_DIR gen keys baker --sig bls
echo "Ghostnet baker: $(russignol-signer --base-dir $GHOSTNET_DIR show address baker | grep 'Public Key Hash' | awk '{print $4}')"
```

### Example 4: Raspberry Pi Deployment

```bash
# On development machine
cargo build --release --target=aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/russignol-signer pi@raspberrypi.local:~/

# On Raspberry Pi
ssh pi@raspberrypi.local
chmod +x russignol-signer
./russignol-signer gen keys pi_baker --sig bls
./russignol-signer show address pi_baker
```

### Example 5: Batch Key Generation

```bash
#!/bin/bash
# generate-batch-keys.sh

for i in {1..5}; do
    russignol-signer gen keys validator_$i --sig bls
    echo "Generated validator_$i"
done

# List all generated keys
russignol-signer list known addresses
```

## Compatibility

### OCaml russignol-signer Compatibility

The Rust implementation is compatible with OCaml russignol-signer for:

✅ **Compatible:**
- BLS12-381 key format (BLsk, BLpk, tz4)
- Base58Check encoding
- Key derivation from seed
- Proof of possession
- Signature format

⚠️ **Differences:**
- Default storage format (JSON vs OCaml's separate files; use `--base-dir ~/.tezos-signer` for OCaml compatibility)
- No HTTP interface yet (coming soon)

### Command Comparison

| OCaml Command | Rust Command | Status |
|---------------|--------------|--------|
| `octez-client gen keys <name> --sig bls` | `russignol-signer gen keys <name> --sig bls` | ✅ Compatible |
| `octez-client list known addresses` | `russignol-signer list known addresses` | ✅ Compatible |
| `octez-client show address <name>` | `russignol-signer show address <name>` | ✅ Compatible |
| `octez-client import secret key <name> <sk>` | `russignol-signer import secret key <name> <sk>` | ✅ Compatible |
| `octez-signer launch socket signer` | `russignol-signer launch socket signer` | ✅ Compatible |
| `octez-signer launch http signer` | Not implemented yet | ❌ Coming soon |

### Key Format Compatibility

Keys generated by the Rust signer can be used with OCaml tools:

```bash
# Generate key in Rust
russignol-signer gen keys my_key --sig bls
russignol-signer show address my_key --show-secret

# Copy the BLsk... secret key
# Import to OCaml client
octez-client import secret key my_key <BLsk...>
```

And vice versa:

```bash
# Generate in OCaml
octez-client gen keys my_key --sig bls
octez-client show address my_key --show-secret

# Copy the BLsk... secret key
# Import to Rust signer
russignol-signer import secret key my_key <BLsk...>
```

## Troubleshooting

### Error: "Key already exists"

```bash
# Use --force to overwrite
russignol-signer gen keys my_key --sig bls --force
```

### Error: "Failed to import secret key"

Check that your secret key:
- Starts with `BLsk`
- Is a valid Base58Check encoded string
- Was not truncated when copying

### Error: "Failed to create directories"

```bash
# Ensure you have write permissions
mkdir -p ~/.local/share/signer
chmod 755 ~/.local/share/signer
```

### Keys not showing up

```bash
# Check the correct directory
russignol-signer --base-dir ~/.local/share/signer list known addresses

# Verify keys.json exists
cat ~/.local/share/signer/keys.json
```

### Invalid secret key when generating

This usually means random generation failed. Check:
```bash
# Ensure /dev/urandom is accessible
ls -l /dev/urandom

# Try again - generation is probabilistic
russignol-signer gen keys my_key --sig bls
```

## Getting Help

### Built-in Help

```bash
# Main help
russignol-signer --help

# Command-specific help
russignol-signer gen --help
russignol-signer list --help
russignol-signer show --help
russignol-signer import --help
```

### Additional Resources

- **GitHub Issues**: Report bugs and request features
- **Documentation**: See `README.md` for technical details
- **OCaml Reference**: [Tezos Octez Documentation](https://tezos.gitlab.io/)

## Version Information

```bash
# Show version
russignol-signer --version

# Output: russignol-signer 0.6.4
```

