# Russignol Configuration System

## Overview

The Russignol host utility uses a persistent configuration system to manage custom Octez client directories, node directories, and RPC endpoints. This allows the utility to work seamlessly with multiple Tezos networks (mainnet, testnets like shadownet, tallinnnet, etc.) without hardcoding paths.

## Configuration File

**Location**: `~/.config/russignol/config.json` (XDG Base Directory compliant)

**Format**:
```json
{
  "version": 2,
  "octez_client_dir": "/home/user/.octez-client-shadownet",
  "octez_node_dir": null,
  "rpc_endpoint": "http://127.0.0.1:8733",
  "dal_node_endpoint": null,
  "signer_endpoint": null
}
```

**Fields**:
- `version` (u32): Configuration schema version for future migrations
- `octez_client_dir` (string): Path to octez-client directory (required)
  - Contains: `public_keys`, `secret_keys`, `public_key_hashs` files
  - Example: `~/.tezos-client`, `~/.octez-client-shadownet`
- `octez_node_dir` (string|null): Path to octez-node directory (optional)
  - Contains: `config.json`, `identity.json`
  - Currently unused but reserved for future features
- `rpc_endpoint` (string): RPC endpoint URL for octez-client (required)
  - Format: `http://HOST:PORT` or `https://HOST:PORT`
  - Example: `http://localhost:8732`, `http://127.0.0.1:8733`
  - Can be overridden per-command with `--endpoint <URL>`
- `signer_endpoint` (string|null): Remote signer endpoint (optional)
  - Format: `tcp://HOST:PORT`
  - Example: `tcp://192.168.1.50:7732`
  - When set, connects to a signer at this address instead of the default USB device
  - Skips local USB/network configuration when specified
  - Can be overridden per-command with `--signer-endpoint <URL>`

## Auto-Detection

The utility automatically detects configuration on first run:

### Detection Flow

1. **Client Directory Detection**:
   - Try default: `~/.tezos-client`
   - Search patterns: `~/.octez-client*`, `~/.tezos-client*`
   - Validate by checking for required files
   - If exactly one found: use automatically
   - If multiple found: present interactive selection menu
   - If none found: prompt user for manual entry

2. **RPC Endpoint Detection**:
   - Search for octez-node directories: `~/.tezos-node`, `~/.octez-node`, `~/.tezos-node-*`, `~/.octez-node-*`
   - Read `config.json` from each directory
   - Extract `rpc.listen-addrs` field
   - Convert to HTTP URL format (e.g., `127.0.0.1:8733` → `http://127.0.0.1:8733`)
   - If detected: use automatically without prompting
   - If not detected: prompt with default `http://localhost:8732`

3. **Save Configuration**:
   - Configuration saved to `~/.config/russignol/config.json`
   - Used for all subsequent runs

### Example Auto-Detection Output

```
Auto-detecting Octez configuration...
  ✓ Found client directory: /home/user/.octez-client-shadownet
  ✓ Detected RPC endpoint: http://127.0.0.1:8733
✓ Configuration saved to /home/user/.config/russignol/config.json
```

## CLI Commands

### View Configuration

```bash
russignol config show
```

**Output**:
```
Current configuration:
  Octez Client Directory: /home/user/.octez-client-shadownet
  Octez Node Directory:   (not set)
  RPC Endpoint:           http://127.0.0.1:8733
  DAL Node Endpoint:      (not set)
  Signer Endpoint:        (local USB signer)

Config file: /home/user/.config/russignol/config.json
```

### Set Configuration Values

```bash
russignol config set <key> <value>
```

**Available keys**:
- `octez-client-dir`: Set client directory path
- `octez-node-dir`: Set node directory path (optional)
- `rpc-endpoint`: Set RPC endpoint URL
- `dal-node-endpoint`: Set DAL node endpoint URL (optional, for bakers participating in DAL)
- `signer-endpoint`: Set remote signer endpoint (optional, for signers not connected via USB)

**Examples**:
```bash
# Set custom client directory
russignol config set octez-client-dir ~/.octez-client-shadownet

# Set custom RPC endpoint
russignol config set rpc-endpoint http://127.0.0.1:8733

# Set node directory
russignol config set octez-node-dir ~/.octez-node-shadownet

# Set remote signer endpoint (for signers not connected via USB)
russignol config set signer-endpoint tcp://192.168.1.50:7732
```

### Reset Configuration

```bash
russignol config reset
```

Deletes the configuration file and re-runs auto-detection. Prompts for confirmation unless `--yes` flag is used:

```bash
russignol config reset --yes
```

### Show Configuration File Path

```bash
russignol config path
```

**Output**: `/home/user/.config/russignol/config.json`

## How It Works

### Centralized Command Wrapper

All octez-client commands are executed through a centralized wrapper function that automatically adds configuration flags:

```rust
run_octez_client_command(&["list", "known", "addresses"], config)
```

**Equivalent to**:
```bash
octez-client --endpoint http://127.0.0.1:8733 --base-dir ~/.octez-client-shadownet list known addresses
```

### Flags Added Automatically

Every octez-client command receives:

1. **`--endpoint <RPC_URL>`**: Specifies which RPC endpoint to connect to
   - Ensures commands connect to the correct node
   - Critical when running multiple testnets on different ports

2. **`--base-dir <CLIENT_DIR>`**: Specifies which client directory to use
   - Determines which keys are available
   - Ensures operations use the correct network's keys
   - Prevents accidentally mixing keys between networks

### Benefits

- **No Manual Flags**: Users don't need to remember to add `--base-dir` or `--endpoint`
- **Consistent Behavior**: All operations use the same configuration
- **Multi-Network Support**: Easy to switch between mainnet and testnets
- **Error Prevention**: Can't accidentally use wrong keys or wrong endpoint

## Use Cases

### Working with Shadownet

```bash
# First run - auto-detects shadownet configuration
russignol setup

# Auto-detected configuration:
# - Client Dir: ~/.octez-client-shadownet
# - RPC Endpoint: http://127.0.0.1:8733 (from ~/.octez-node-shadownet/config.json)
```

### Working with Multiple Networks

**Switch to Tallinnnet**:
```bash
russignol config set octez-client-dir ~/.octez-client-tallinnnet
russignol config set rpc-endpoint http://127.0.0.1:8732
```

**Switch back to Shadownet**:
```bash
russignol config set octez-client-dir ~/.octez-client-shadownet
russignol config set rpc-endpoint http://127.0.0.1:8733
```

### Fresh Setup After Changes

If you change your octez-node or octez-client configuration:

```bash
russignol config reset --yes
```

This will re-detect your current setup and update the configuration.

## Troubleshooting

### Configuration Not Detected

**Symptom**: Utility prompts for manual path entry

**Causes**:
- Client directory doesn't contain required files (`public_keys`, `secret_keys`, `public_key_hashs`)
- Client directory name doesn't match search patterns
- Multiple directories found and auto-confirm not enabled

**Solution**:
```bash
# Manually specify the directory
russignol config set octez-client-dir /path/to/your/octez-client
```

### Wrong RPC Endpoint

**Symptom**: Errors like "Unable to connect to the node" or "ECONNREFUSED"

**Causes**:
- Node running on different port than detected
- Node not running
- Wrong endpoint in configuration

**Solution**:
```bash
# Check what port your node is using
cat ~/.octez-node-shadownet/config.json | grep listen-addrs

# Update the endpoint
russignol config set rpc-endpoint http://127.0.0.1:XXXX
```

### Keys Not Found

**Symptom**: "Keys not found in octez-client after import"

**Causes**:
- Wrong base-dir configured
- Keys imported to different directory

**Solution**:
```bash
# Verify which directory contains your keys
octez-client --base-dir ~/.octez-client-shadownet list known addresses

# Update configuration to match
russignol config set octez-client-dir ~/.octez-client-shadownet
```

### Multiple Directories Found

**Symptom**: Interactive menu appears asking which directory to use

**Action**: Select the correct directory for your current network

If you always want to use the same directory:
```bash
russignol config set octez-client-dir /path/to/preferred/directory
```

## Related Documentation

- [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html)
- [Octez Client Documentation](https://tezos.gitlab.io/introduction/howtouse.html#client)
- [Tezos Networks](https://teztnets.com/)
