# Manual Installation Guide

Manual setup for advanced users who prefer direct control over each step.

## Prerequisites

### Hardware

See [Hardware Requirements](../README.md#hardware-requirements).

### Software

- [Octez](https://tezos.gitlab.io/introduction/howtoget.html) with a running, synced node
- `octez-client` with an existing baker key
- Linux or macOS (untested) host
- `systemd-networkd` for network configuration (Linux)

**Linux** — install required packages:

```bash
sudo apt install curl xz-utils eject iproute2 usbutils
```

**macOS** — install required packages:

> **Warning:** macOS support has not been tested.

```bash
brew install xz
```

## Step 1: Download and Flash SD Card

> **Warning: Manual flashing skips critical security provisioning.**
>
> The [host utility](INSTALL_HOST_UTILITY.md) performs essential setup that manual flashing cannot replicate:
>
> - **No watermark initialization** — The host utility queries your live Tezos node and writes blockchain state to the boot partition. Without this, an attacker who obtains the image could modify watermark values to enable replay attacks or double-signing.
> - **No SD card wear leveling** — The host utility configures over-provisioning and TRIMs unpartitioned space for optimal flash wear leveling. Manual flashing skips this optimization, reducing SD card longevity.
> - **No image integrity verification** — Manual `dd` doesn't verify the SHA256 checksum; corrupted downloads go undetected.
> - **No device safety checks** — Risk of accidentally overwriting the wrong drive. The host utility validates removable devices and requires explicit confirmation.
> - **No node validation** — Manual process doesn't verify your node is running and synced before flashing.
>
> **Recommended:** Use the [host utility](INSTALL_HOST_UTILITY.md) instead.
>
> Proceeding with manual installation means accepting responsibility for these missing security features.

Download the latest SD card image:

```bash
curl -LO https://github.com/RichAyotte/russignol/releases/latest/download/russignol-pi-zero.img.xz
```

Flash to SD card:

**Linux** (replace `/dev/sdX` with your SD card device):

```bash
xzcat russignol-pi-zero.img.xz | sudo dd of=/dev/sdX bs=4M iflag=fullblock oflag=direct conv=fsync status=progress
sudo eject /dev/sdX
```

**macOS** (replace `/dev/diskN` with your SD card device):

> **Warning:** macOS support has not been tested.

```bash
diskutil list
diskutil unmountDisk /dev/diskN
xzcat russignol-pi-zero.img.xz | sudo dd of=/dev/rdiskN bs=4m conv=fsync
diskutil eject /dev/diskN
```

> **Warning:** Double-check the device path. `dd` will overwrite without confirmation.

> **Note:** Users in the `disk` group (Linux) can omit `sudo` for `dd` and `eject`.

## Step 2: Boot and Initialize Device

1. Insert the flashed SD card into your Raspberry Pi Zero 2W
2. Connect the Pi to your baker host via USB data cable
3. Power on (USB provides power)
4. Follow the on-screen setup wizard:
   - **Create PIN**: Enter a 5-10 digit PIN on the touchscreen
   - **Generate Keys**: The device generates two BLS12-381 signing keys (consensus and companion)
   - **Confirm**: Note your new tz4 addresses displayed on screen

## Step 3: Configure Network

### Create udev Rule

Create a persistent device name:

```bash
sudo tee /etc/udev/rules.d/20-russignol.rules << 'EOF'
SUBSYSTEM=="net", ACTION=="add", ATTRS{idVendor}=="1d6b", ATTRS{idProduct}=="0104", ATTRS{manufacturer}=="Russignol", NAME="russignol"
EOF

sudo udevadm control --reload-rules
```

### Configure Link-Local Address

The signer runs on `169.254.1.1`. Configure your host to reach it:

Create network configuration for systemd-networkd:

```bash
sudo tee /etc/systemd/network/80-russignol.network << 'EOF'
[Match]
Name=russignol

[Link]
RequiredForOnline=no

[Network]
Address=169.254.1.2/30
LinkLocalAddressing=no
IPv6AcceptRA=no
EOF

sudo systemctl restart systemd-networkd
```

Alternatively, configure manually each boot:

```bash
ip addr add 169.254.1.2/30 dev russignol
ip link set russignol up
```

### Verify Connectivity

```bash
ping -c 3 169.254.1.1
```

## Step 4: Import Keys

The signer exposes keys via a TCP remote signer at `169.254.1.1:7732`.

### Discover Key Address

Query the signer for available keys:

```bash
octez-client list known remote keys tcp://169.254.1.1:7732
```

This returns both tz4 addresses (consensus and companion).

### Import as Remote Signer

Import each key using its respective tz4 address.

Import consensus key:

```bash
octez-client import secret key russignol-consensus tcp://169.254.1.1:7732/<CONSENSUS_TZ4_ADDRESS>
```

Import companion key:

```bash
octez-client import secret key russignol-companion tcp://169.254.1.1:7732/<COMPANION_TZ4_ADDRESS>
```

### Verify Import

```bash
octez-client list known addresses | grep russignol
```

## Step 5: Assign Keys On-Chain

Register the signer keys with your delegate. This requires your delegate's secret key to sign.

Set consensus key:

```bash
octez-client set consensus key for <your-delegate-alias> to russignol-consensus
```

Set companion key:

```bash
octez-client set companion key for <your-delegate-alias> to russignol-companion
```

> **Note:** Key assignment takes effect after `consensus_rights_delay` cycles (~2-3 days).

## Step 6: Start Baking

Start your baker daemon:

```bash
octez-baker run with local node ~/.tezos-node \
    russignol-consensus russignol-companion \
    --liquidity-baking-toggle-vote pass \
    --dal-node http://127.0.0.1:10732
```

See [Running Octez](https://octez.tezos.com/docs/introduction/howtorun.html) for all options.

### Verify Signing

Check the signer is responding.

Watch baker logs for signing activity:

```bash
journalctl -u octez-baker -f | grep -i sign
```

You can also check the signer status via the e-ink display, which shows recent signing activity.

## Troubleshooting

### Device Not Appearing

Check USB connection:

```bash
lsusb | grep "Linux-USB Ethernet"
```

Check kernel messages:

```bash
sudo dmesg -T | tail -20
```

Verify cdc_ether module is loaded:

```bash
lsmod | grep cdc_ether
```

### Network Unreachable

Check interface exists:

```bash
ip link show russignol
```

Check address assigned:

```bash
ip addr show russignol | grep 169.254
```

Try manual configuration:

```bash
ip addr flush dev russignol
ip addr add 169.254.1.2/30 dev russignol
ip link set russignol up
```

### Key Import Fails

Verify signer is accessible:

```bash
octez-client list known remote keys tcp://169.254.1.1:7732
```

Check the device is unlocked by entering your PIN on the touchscreen.

## Next Steps

- [Automated Installation](INSTALL_HOST_UTILITY.md) — Simplified setup with host utility
- [Key Rotation](../host-utility/KEY_ROTATION.md) — Rotate to a new device
- [Configuration Reference](../host-utility/CONFIGURATION.md) — Multi-network setup
