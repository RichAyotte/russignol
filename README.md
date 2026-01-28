<img src="rpi-signer/assets/russignol-logo.svg" alt="Russignol" width="64" align="right">

# Russignol

**Hardware Signer for Tezos Baking on Raspberry Pi Zero 2W**

Russignol is a dedicated hardware signing device. Your validator keys stay on isolated hardware.

## Why?

[tz4 addresses](https://octez.tezos.com/docs/active/accounts.html#tz4-bls) (BLS signatures) enable [aggregated attestations](https://research-development.nomadic-labs.com/tallinn-announcement.html)—combining hundreds of signatures into one per block. This reduces consensus data by 63x (from ~900 MB/day to ~14 MB/day), allowing all bakers to attest every block instead of ~200 out of ~300. The result: stronger security through full participation, predictable rewards proportional to stake, and reduced overhead that supports further [block time improvements](https://research-development.nomadic-labs.com/tallinn-announcement.html).

Ledger Nano can't perform BLS signatures fast enough for 6-second blocks, and software signers store keys on internet-connected machines—exposing them to remote exploits and memory-scraping attacks.

## Features

- **[BLS12-381](https://octez.tezos.com/docs/active/accounts.html#tz4-bls) signing** — ~6ms via BLST
- **USB gadget ethernet only** — WiFi, Bluetooth, Ethernet compiled out of kernel
- **PIN-protected key storage** — AES-256-GCM encryption, PIN-derived key via Scrypt (256MB memory-hard)
- **Hardened kernel** — Module signature enforcement, kernel lockdown, locked accounts
- **High watermark protection** — Refuses to sign at or below previous levels, persists across reboots
- **Touch-enabled e-ink display** — On-device PIN entry (never crosses USB), live signing activity
- **Flash-optimized storage** — F2FS with hardware-adaptive alignment, over-provisioning for wear leveling

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

## Documentation

- [Security Audit](docs/SECURITY_AUDIT.md)
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

## License

MIT — see [LICENSE](LICENSE).

## Support

[GitHub Issues](https://github.com/RichAyotte/russignol/issues)
