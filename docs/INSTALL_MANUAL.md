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

> **Note:** macOS is operate-only. This guide gets a Mac through flashing,
> network configuration, key import, and baking — all via `octez-client` and
> `octez-baker`, which are cross-platform. But **watermark initialization
> (Step 1) and key rotation are performed by the
> [host utility](INSTALL_HOST_UTILITY.md), which runs only on Linux.** A Mac on
> its own cannot seed the high-watermark floor on a freshly flashed card or
> drive a key rotation; use a Linux host — a VM or container with USB
> passthrough works — for those steps.

## Step 1: Download and Flash SD Card

> **Warning: Manual flashing skips critical security provisioning.**
>
> The [host utility](INSTALL_HOST_UTILITY.md) performs essential setup that manual flashing cannot replicate:
>
> - **No watermark initialization** — The host utility queries your live Tezos node and writes blockchain state to the boot partition. Without this, an attacker who obtains the image could modify watermark values to enable replay attacks or double-signing.
> - **No image integrity verification** — Manual `dd` doesn't verify the SHA256 checksum; corrupted downloads go undetected.
> - **No device safety checks** — Risk of accidentally overwriting the wrong drive. The host utility validates removable devices and requires explicit confirmation.
> - **No node validation** — Manual process doesn't verify your node is running and synced before flashing.
> - **No flash manifest** — The host utility writes a card identity the swap guard uses to detect the *same card* during a key restore. A manually flashed card has none, so a later restore flags it as "not flashed by this tool" and falls back to the partition-table UUID for same-card detection.
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

**macOS** (replace `/dev/diskN` with your SD card device — identify it in
`diskutil list` as the `external, physical` disk matching the card's size):

> **Warning:** macOS support has not been tested.

```bash
diskutil list
diskutil unmountDisk /dev/diskN
xzcat russignol-pi-zero.img.xz | sudo dd of=/dev/rdiskN bs=4m
sync
diskutil eject /dev/diskN
```

> **Note:** macOS `dd` prints nothing while it runs; press `Ctrl+T` to see
> bytes written so far. If `dd` fails with `Operation not permitted` even
> under `sudo`, grant your terminal app Full Disk Access
> (System Settings → Privacy & Security → Full Disk Access) and retry.

> **Warning:** Double-check the device path. `dd` will overwrite without confirmation.

> **Note:** Users in the `disk` group (Linux) can omit `sudo` for `dd` and `eject`.

> **Note:** If the [host utility](INSTALL_HOST_UTILITY.md) is available on a Linux
> machine, seed the watermark floor after flashing:
>
> ```bash
> russignol watermark init --device /dev/sdX
> ```
>
> This performs the watermark initialization described in the warning above,
> querying your Tezos node and writing the current blockchain state to the
> card's boot partition.

## Step 2: Boot and Initialize Device

1. Insert the flashed SD card into your Raspberry Pi Zero 2W
2. Connect the Pi to your baker host via USB data cable
3. Power on (USB provides power)
4. Follow the on-screen setup wizard:
   - **Create PIN**: Enter a 5-10 digit PIN on the touchscreen
   - **Generate Keys**: The device generates two BLS12-381 signing keys (consensus and companion)
   - **Confirm**: Note your new tz4 addresses displayed on screen

## Step 3: Configure Network

Network configuration is OS-specific: Linux uses a udev rule plus
`systemd-networkd`; macOS configures the interface directly with
`networksetup`. Both ends share the same link-local subnet — the signer is
`169.254.1.1` and the host must be `169.254.1.2/30`.

### Linux

#### Create udev Rule

Create a persistent device name:

```bash
sudo tee /etc/udev/rules.d/20-russignol.rules << 'EOF'
SUBSYSTEM=="net", ACTION=="add", ATTRS{idVendor}=="1d6b", ATTRS{idProduct}=="0104", ATTRS{manufacturer}=="Russignol", NAME="russignol"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=net
```

#### Configure Link-Local Address

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

#### Exclude from NetworkManager

If NetworkManager is running, prevent it from managing the russignol interface:

```bash
sudo mkdir -p /etc/NetworkManager/conf.d
sudo tee /etc/NetworkManager/conf.d/unmanaged-russignol.conf << 'EOF'
[keyfile]
unmanaged-devices=interface-name:russignol
EOF

sudo systemctl restart NetworkManager
```

Skip this step if NetworkManager is not installed or not running (`systemctl is-active NetworkManager`).

#### Manual Configuration (Alternative)

Alternatively, configure manually each boot:

```bash
sudo ip addr add 169.254.1.2/30 dev russignol
sudo ip link set russignol up
```

### macOS

> **Warning:** macOS support has not been tested.

The signer presents a standard USB CDC-ECM ethernet interface, which macOS
recognizes without extra drivers. Identify the interface it created:

```bash
networksetup -listallhardwareports
```

macOS names the hardware port from the USB product string, so look for an
entry like:

```
Hardware Port: Russignol Ethernet
Device: en5
Ethernet Address: 02:xx:xx:xx:xx:xx
```

Note both the hardware port name and the `enN` device. If no port is named
`Russignol Ethernet`, compare `ifconfig -l` output with the device unplugged
and plugged in — the interface that appears is the signer.

macOS automatically creates a network service for the new interface. Find its
exact name (usually the same as the hardware port name):

```bash
networksetup -listallnetworkservices
```

If no matching service appears, run `sudo networksetup -detectnewhardware`
and list again.

Assign the static address `169.254.1.2/30` (netmask `255.255.255.252`).
Persistent, by network service name (case-sensitive):

```bash
sudo networksetup -setmanual "Russignol Ethernet" 169.254.1.2 255.255.255.252
```

Verify:

```bash
networksetup -getinfo "Russignol Ethernet"
```

Temporary (cleared on replug or reboot), by device name:

```bash
sudo ifconfig enN 169.254.1.2 255.255.255.252
```

> **Note:** The host address must be exactly `169.254.1.2`. The device pings
> the host and power-cycles the USB gadget after ~30 seconds of failed pings,
> so the automatic link-local address macOS would otherwise self-assign (a
> random `169.254.x.x`) makes the link flap. Confirm `ifconfig enN` shows
> `169.254.1.2` and no second self-assigned address.

> **Note:** macOS ties this configuration to the adapter's MAC address, and
> each Russignol derives its MAC from its CPU serial. The same device needs
> no reconfiguration across replugs and reboots, but a replacement device
> (e.g. after key rotation) appears as a new adapter with a fresh service
> defaulting to DHCP — repeat this step once for it.

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

Watch baker logs for signing activity — if the baker runs under systemd:

```bash
journalctl -u octez-baker -f | grep -i sign
```

Otherwise, watch the baker's stdout.

You can also check the signer status via the e-ink display, which shows recent signing activity.

## Troubleshooting

### Device Not Appearing

Check USB connection (Linux):

```bash
lsusb -d 1d6b:0104 -v 2>/dev/null | grep -i russignol
```

Expected output:

```
  iManufacturer           1 Russignol
  iProduct                2 Russignol Ethernet
```

Check kernel messages:

```bash
sudo dmesg -T | tail -20
```

Look for lines mentioning `cdc_ether` and `usb0` indicating the device was recognized.

Verify cdc_ether driver is available:

```bash
ls /sys/module/cdc_ether
```

Expected output:

```
coresize  drivers  holders  initsize  initstate  refcnt  taint  uevent
```

On macOS, check the USB device is enumerated:

```bash
system_profiler SPUSBDataType | grep -A 8 -i russignol
```

and confirm a matching hardware port exists
(`networksetup -listallhardwareports`).

### Network Unreachable

Check interface exists:

```bash
ip link show russignol
```

Expected output (state should be `UP`):

```
4: russignol: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether ...
```

Check address assigned:

```bash
ip addr show russignol | grep 169.254
```

Expected output:

```
    inet 169.254.1.2/30 brd 169.254.1.3 scope link russignol
```

Try manual configuration:

```bash
sudo ip addr flush dev russignol
sudo ip addr add 169.254.1.2/30 dev russignol
sudo ip link set russignol up
```

On macOS, check the interface address:

```bash
ifconfig enN
```

It must show `inet 169.254.1.2 netmask 0xfffffffc` and no second
self-assigned `169.254.x.x` address. If the address is wrong or missing,
re-run the `networksetup -setmanual` command from Step 3.

### Key Import Fails

Verify signer is accessible:

```bash
octez-client list known remote keys tcp://169.254.1.1:7732
```

Expected output (two tz4 addresses):

```
Tezos remote known keys:
  tz4xxxxxxxxx...
  tz4yyyyyyyyy...
```

If no output or connection refused, check the device is unlocked by entering your PIN on the touchscreen.

## Next Steps

- [Device Operation](DEVICE_OPERATION.md) — Using the device after installation
- [Automated Installation](INSTALL_HOST_UTILITY.md) — Simplified setup with host utility
- [Key Rotation](../host-utility/KEY_ROTATION.md) — Rotate to a new device
- [Configuration Reference](../host-utility/CONFIGURATION.md) — Multi-network setup
