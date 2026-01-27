# Automated Installation Guide

Install Russignol using the `russignol` host utility for automated setup.

## Prerequisites

### Hardware

See [Hardware Requirements](../README.md#hardware-requirements).

### Software

- [Octez](https://tezos.gitlab.io/introduction/howtoget.html) with a running, synced node
- `octez-client` with an existing baker key
- Linux host (Debian/Ubuntu recommended)

Install required packages:

```bash
sudo apt install curl xz-utils iproute2 usbutils parted
```

## Step 1: Download

Download the latest release for your architecture:

**x86_64:**

```bash
curl -LO https://github.com/RichAyotte/russignol/releases/latest/download/russignol-amd64
chmod +x russignol-amd64
```

**ARM64:**

```bash
curl -LO https://github.com/RichAyotte/russignol/releases/latest/download/russignol-aarch64
chmod +x russignol-aarch64
```

## Step 2: Install

Install the utility to `~/.local/bin/russignol`:

```bash
./russignol-amd64 install
```

Ensure `~/.local/bin` is in your PATH.

## Step 3: Shell Completions

Generate shell completions (supports `bash`, `zsh`, `fish`):

```bash
russignol completions <SHELL>
```

## Step 4: Flash SD Card

Insert an SD card and flash the Russignol image:

```bash
russignol image download-and-flash
```

This downloads and flashes in one step, auto-detecting your SD card.

> **Note:** Your user must be a member of the `disk` group (or equivalent) to write to block devices without sudo.

The utility will:
1. Download the latest SD card image
2. Detect available SD cards
3. Prompt for confirmation
4. Flash and verify the image

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
3. **Configures network** — link-local address `169.254.1.1`
4. **Auto-detects octez-client** — finds your baker configuration
5. **Imports keys** — adds signer keys as remote signers
6. **Assigns keys on-chain** — sets consensus and companion keys
7. **Tests signing** — verifies end-to-end functionality

### Setup Options

**Dry run** (simulation only):

```bash
russignol setup --dry-run
```

**Verbose output:**

```bash
russignol setup --verbose
```

**Non-interactive** (accept defaults):

```bash
russignol setup --yes
```

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
lsusb | grep "Linux-USB Ethernet"
```

Check kernel messages:

```bash
sudo dmesg | tail -20
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

- [Key Rotation](../host-utility/KEY_ROTATION.md) — Rotate to a new device
- [Manual Installation](INSTALL_MANUAL.md) — Advanced setup without the utility
