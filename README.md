<img src="rpi-signer/assets/russignol-logo.svg" alt="Russignol" width="64" align="right">

# Russignol

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Hardware Signer for Tezos Baking on Raspberry Pi Zero 2W**

Russignol is a dedicated hardware signing device. Your validator keys stay on isolated hardware.

**Website:** [russignol.com](https://russignol.com) | **Demo:** [YouTube](https://www.youtube.com/watch?v=FO8th1GVkIg)

<p align="center">
  <img src="docs/images/russignol-status-display.jpg" alt="Russignol device showing e-ink status display with baker address, block level, and signing activity" width="600">
</p>

## Why?

[tz4 addresses](https://octez.tezos.com/docs/active/accounts.html#tz4-bls) (BLS signatures) enable [aggregated attestations](https://research-development.nomadic-labs.com/tallinn-announcement.html)—combining hundreds of signatures into one per block. This reduces consensus data by 63x (from ~900 MB/day to ~14 MB/day), allowing all bakers to attest every block instead of ~200 out of ~300. The result: stronger security through full participation, predictable rewards proportional to stake, and reduced overhead that supports further [block time improvements](https://research-development.nomadic-labs.com/tallinn-announcement.html).

Ledger Nano can't perform BLS signatures fast enough for 6-second blocks, and software signers store keys on internet-connected machines—exposing them to remote exploits and memory-scraping attacks.

## Features

- **[BLS12-381](https://octez.tezos.com/docs/active/accounts.html#tz4-bls) signing** — ~6ms via BLST
- **USB gadget ethernet only** — WiFi, Bluetooth, Ethernet compiled out of kernel
- **PIN-protected key storage** — AES-256-GCM encryption, PIN-derived key via Scrypt (256MB memory-hard)
- **Hardened kernel** — Kernel lockdown (integrity mode, enforced early), module signature enforcement, no core dumps, heap zeroed on free, locked accounts, no getty or SSH
- **High watermark protection** — Per-key watermarks for consensus and companion key signing, pre-set one level into the future so steady-state signing doesn't block on disk I/O, Blake3-hashed for corruption detection, persists across reboots
- **Touch-enabled e-ink display** — On-device PIN entry (never crosses USB), menu-based navigation with System, Activity, Blockchain, Watermarks, About, and Shutdown pages
- **Activity LED** — Visual indication of baker connection
- **CPU frequency scaling** — Idles at 600 MHz, boosts to 1000 MHz during signing and PIN entry
- **Flash-optimized storage** — F2FS with hardware-adaptive alignment, over-provisioning for wear leveling
- **Key restore across reflashes** — `russignol image flash --restore-keys` carries keys and watermarks over from an existing card
- **Key migration** — `russignol image flash --migrate-keys` imports keys from a Nomadic Labs [tezos-rpi-bls-signer](https://gitlab.com/nomadic-labs/tezos-rpi-bls-signer) card
- **Network mismatch detection** — Warns during key restore if the key's network doesn't match the connected node

## Hardware Requirements

| Component | Specification |
|-----------|---------------|
| **Board** | Raspberry Pi Zero 2W |
| **Display** | Waveshare 2.13" E-ink Touch |
| **Storage** | 8GB+ microSD (high-endurance recommended) |
| **Cable** | USB data cable (not power-only) |

## Getting Started

- [Automated Installation](docs/INSTALL_HOST_UTILITY.md) (recommended)
- [Manual Installation](docs/INSTALL_MANUAL.md)
- [LXC Container Setup](docs/INSTALL_LXC.md)

## Documentation

- [Device Operation](docs/DEVICE_OPERATION.md)
- [Security Audit](docs/SECURITY_AUDIT.md)
- [Watermark Crash Analysis](docs/security/watermark-crash-analysis.md)
- [Host Utility](host-utility/README.md)
- [Configuration](host-utility/CONFIGURATION.md)
- [Key Rotation](host-utility/KEY_ROTATION.md)

### Development

- [Build System](xtask/README.md)
- [Contributing](CONTRIBUTING.md)

## Credits & Attribution

- Inspired by [tezos-rpi-bls-signer](https://gitlab.com/nomadic-labs/tezos-rpi-bls-signer)
- Powered by [blst](https://github.com/supranational/blst)
- Logic ported from [Tezos octez-signer](https://gitlab.com/tezos/tezos/)
- Icons by [Mobirise Icons](https://mobiriseicons.com/)

## Support

[GitHub Issues](https://github.com/RichAyotte/russignol/issues)
