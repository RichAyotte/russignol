# Automated Installation Guide

Install Russignol using the `russignol` host utility for automated setup.

## Prerequisites

### Hardware

See [Hardware Requirements](../README.md#hardware-requirements).

### Software

- [Octez](https://tezos.gitlab.io/introduction/howtoget.html) with a running, synced node
- `octez-client` with an existing baker key
- Linux host (Debian/Ubuntu recommended)

> **Note:** If `octez-client` is missing, `russignol setup` offers to install the official Octez static binaries (sha256-verified, installed to `~/.local/bin`, no root required).

Install required packages:

```bash
sudo apt install curl xz-utils iproute2 usbutils parted
```

## Step 1: Download

Download the latest release for your architecture:

**x86_64:**

```bash
curl -Lo russignol https://github.com/RichAyotte/russignol/releases/latest/download/russignol-amd64 && chmod +x russignol
```

**ARM64:**

```bash
curl -Lo russignol https://github.com/RichAyotte/russignol/releases/latest/download/russignol-aarch64 && chmod +x russignol
```

## Step 2: Install

Install the utility to `~/.local/bin/russignol`:

```bash
./russignol install
```

Ensure `~/.local/bin` is in your PATH.

## Step 3: Shell Completions

Generate shell completions (supports `bash`, `zsh`, `fish`):

```bash
russignol completions <SHELL>
```

To update the utility later, run `russignol upgrade` (use `--check` to only check for a new version, `--beta` to include pre-releases).

## Step 4: Flash SD Card

Insert an SD card and flash the Russignol image:

```bash
russignol image download-and-flash
```

This downloads and flashes in one step, auto-detecting your SD card.

This is the supported way to flash a card: it verifies the download checksum, guards against writing the wrong device, and — when restoring keys — verifies the result before reporting success. Flashing another way (see [manual installation](INSTALL_MANUAL.md)) skips those checks.

> **Note:** If your user lacks write access to the SD card device, the utility offers guided recovery: activating existing group membership, adding you to the device's owning group, or running the raw write steps with sudo.

The utility will:
1. Download the latest SD card image
2. Detect available SD cards
3. Prompt for confirmation
4. Flash and verify the image

### Reusing Keys from an Existing Card

Two options carry keys onto the new card during flashing (both also work with `russignol image flash`):

Preserve the keys and watermarks from an existing Russignol card:

```bash
russignol image download-and-flash --restore-keys
```

Migrate keys from a Nomadic Labs `tezos-rpi-bls-signer` card:

```bash
russignol image download-and-flash --migrate-keys
```

Both accept an optional source device (e.g. `--restore-keys /dev/sdd`) and auto-detect it when omitted. Migration accepts `--consensus-key` and `--companion-key` to choose which source key aliases become the consensus and companion keys.

A source card not flashed by the host utility (for example one written with `dd`) has no flash manifest; the restore reports it as such, still carries its keys over, and uses the partition-table UUID for the same-card swap guard. After writing, the new card's key and watermark partitions are re-read and verified before success is reported.

## Step 5: Boot and Initialize Device

1. Insert the flashed SD card into your Raspberry Pi Zero 2W
2. Connect the Pi to your baker host via USB data cable
3. Power on (USB provides power)
4. Follow the on-screen setup wizard:
   - **Create PIN**: Enter a 5-10 digit PIN (entered on the touchscreen)
   - **Generate Keys**: The device generates two BLS12-381 signing keys (consensus and companion)
   - **Confirm**: The device displays your new tz4 addresses

> **Note:** The PIN is entered directly on the e-ink touchscreen and never crosses the USB connection.

## Step 6: Run Automated Setup

Once the device is initialized and unlocked, run the setup utility:

```bash
russignol setup
```

The utility automatically:
1. **Detects the USB-connected signer** — validates device connectivity
2. **Configures udev rules** — persistent device naming
3. **Configures network** — host address `169.254.1.2/30` on the `russignol` interface (the signer is `169.254.1.1`)
4. **Auto-detects octez-client** — finds your baker configuration
5. **Verifies signer connectivity** — confirms the signer responds and reports both keys
6. **Imports keys** — adds signer keys as remote signers
7. **Assigns keys on-chain** — sets consensus and companion keys

If no Tezos node is reachable at the configured RPC endpoint, the utility interactively offers public RPC endpoints (Mainnet and long-running test networks) to select from.

### Setup Options

**Dry run** (simulation only):

```bash
russignol setup --dry-run
```

**Verbose output:**

```bash
russignol setup --verbose
```

**Non-interactive** (accept all prompts):

```bash
russignol setup --yes --baker-key <alias-or-address>
```

`--yes` requires `--baker-key` with your baker's alias or address, since there is no prompt to select one.

**Remote node** (use a different RPC endpoint):

```bash
russignol setup --endpoint http://192.168.1.100:8732
```

The `--endpoint` flag overrides the configured RPC endpoint for a single command. This is useful when your node runs on a different machine or port.

**Remote signer** (connect to a signer at a different address):

```bash
russignol setup --signer-endpoint tcp://192.168.1.50:7732 --skip-hardware-check
```

The `--signer-endpoint` flag connects to a signer at a custom network address instead of the default USB-connected device at `tcp://169.254.1.1:7732`. When specified, the utility skips local USB/network configuration. Add `--skip-hardware-check` when the signer is not attached to this host — USB hardware detection still runs by default and fails without a local device. This is useful when:
- The signer runs on a different machine on your network
- You have multiple signers and want to specify which one to use
- Testing with a remote signer setup

## Step 7: Verify Baker Connection

Confirm your baker can reach the signer.

Check the device is accessible:

```bash
ping -c 3 169.254.1.1
```

Verify keys are imported:

```bash
octez-client list known addresses | grep russignol
```

## Step 8: Start Baking

Start your baker with the hardware signer:

```bash
octez-baker run with local node ~/.tezos-node \
    russignol-consensus russignol-companion \
    --liquidity-baking-toggle-vote pass \
    --dal-node http://127.0.0.1:10732
```

See [Running Octez](https://octez.tezos.com/docs/introduction/howtorun.html) for all options.

## Configuration

The setup utility saves configuration to `~/.config/russignol/config.json`.

View current configuration:

```bash
russignol config show
```

Update settings:

```bash
russignol config set octez-client-dir ~/.octez-client-shadownet
russignol config set rpc-endpoint http://127.0.0.1:8733
```

See [CONFIGURATION.md](../host-utility/CONFIGURATION.md) for detailed configuration options.

## Troubleshooting

### Device Not Detected

Check USB connection:

```bash
lsusb -d 1d6b:0104
```

To confirm it is the Russignol device (and not another gadget with the same ID), check the device strings:

```bash
lsusb -v -d 1d6b:0104 2>/dev/null | grep -i russignol
```

Check kernel messages:

```bash
sudo dmesg -T | tail -20
```

### Network Unreachable

Verify link-local address:

```bash
ip addr show | grep 169.254
```

Re-run setup to reconfigure network:

```bash
russignol setup
```

### Keys Not Found

See [CONFIGURATION.md](../host-utility/CONFIGURATION.md#troubleshooting) for octez-client configuration issues.

## Next Steps

- [Device Operation](DEVICE_OPERATION.md) — Using the device after installation
- [Key Rotation](../host-utility/KEY_ROTATION.md) — Rotate to a new device
- [Manual Installation](INSTALL_MANUAL.md) — Advanced setup without the utility
