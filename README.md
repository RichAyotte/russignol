<img src="rpi-signer/assets/russignol-logo.svg" alt="Russignol" width="64" align="right">

# Russignol

**Hardware Signer for Tezos Baking on Raspberry Pi Zero 2W**

Russignol is a dedicated hardware signing device. Your validator keys stay on isolated hardware, connected to your baker only via ethernet-over-USB — no WiFi, no internet exposure.

## Why?

Tezos bakers benefit from [tz4 addresses](https://octez.tezos.com/docs/active/accounts.html#tz4-bls) (BLS signatures) — aggregatable signatures let all bakers attest in every block without bloat, enabling predictable rewards and shorter block times. But BLS signing is slow: Ledger takes ~10 seconds, making it unusable with 6-second blocks. Russignol signs in ~6ms.

Your private keys are also a high-value target. Traditional setups store keys on internet-connected machines, exposing them to remote exploits, compromised infrastructure, and memory-scraping attacks. One successful attack means losing your stake and your delegators' trust.

## Features

- **USB gadget ethernet only** — WiFi, Bluetooth, Ethernet compiled out of kernel
- **High watermark protection** — Refuses to sign at or below previous levels, persists across reboots
- **PIN-protected key storage** — AES-256-GCM encryption, PIN-derived key via Scrypt (256MB memory-hard)
- **[BLS12-381](https://octez.tezos.com/docs/active/accounts.html#tz4-bls) signing** — ~6ms via BLST; aggregatable signatures enable all bakers to attest without bloating blocks
- **Touch-enabled e-ink display** — On-device PIN entry (never crosses USB), live signing activity
- **Hardened kernel** — Module signature enforcement, kernel lockdown, locked accounts
- **Flash-optimized storage** — F2FS with hardware-adaptive alignment, over-provisioning for wear leveling

## Why Not Ledger?

Ledger Nano's BLS12-381 signing takes ~10 seconds per operation. With Tezos producing blocks every 6 seconds, you can't sign in time.

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
- [Contributing](CONTRIBUTING.md)
- [Build System](xtask/README.md)

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Support

- GitHub Issues: https://github.com/RichAyotte/russignol/issues
