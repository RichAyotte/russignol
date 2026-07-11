# Russignol Host Utility

CLI tool for configuring and managing a Russignol hardware signer from your baker host machine.

## Features

- Automated hardware detection and signer setup
- udev rules and network configuration
- Key discovery, import, and on-chain assignment
- SD card image flashing, with key restore and migration when re-flashing
  (including from Nomadic Labs RPI BLS signer cards)
- Key rotation with minimal downtime
- Interactive network selection menu (teztnets.com testnets, Mainnet, local, or custom)
- Self-install and self-upgrade

## Installation

See the [Installation Guide](../docs/INSTALL_HOST_UTILITY.md) for complete setup instructions.

Build from source:

```bash
cargo xtask host-utility
```

## Command Reference

```
russignol setup                     Run full setup wizard
russignol setup --dry-run           Simulate without changes
russignol setup --verbose           Detailed output
russignol setup --endpoint <URL>    Use remote node RPC endpoint
russignol setup --signer-endpoint <URL>     Use remote signer (skips USB/network config)
russignol setup --yes --baker-key <ALIAS>   Non-interactive setup

russignol image download-and-flash  Download and flash SD card
russignol image download            Download image only
russignol image download --beta     Download the latest beta image
russignol image flash <path>        Flash local image
russignol image flash <path> --restore-keys   Carry keys and watermarks over from an existing card
russignol image flash <path> --migrate-keys   Migrate keys from a Nomadic Labs RPI BLS signer card
russignol image list                List available images

russignol config show               View current configuration
russignol config set <key> <value>  Update configuration
russignol config reset              Re-run auto-detection
russignol config path               Show configuration file path

russignol rotate-keys               Start key rotation workflow
russignol rotate-keys --monitor     Check pending rotation status

russignol check disk                Diagnose an SD card and repair fixable issues
russignol check disk --dry-run      Report issues without repairing

russignol purge                     Remove system configuration and imported key aliases
russignol purge --dry-run           Simulate without changes

russignol check host                Check host, node, and device health
russignol check host --verbose      Detailed diagnostics
russignol check host --endpoint <URL>   Check health using remote node

russignol install                   Install russignol to ~/.local/bin
russignol upgrade                   Upgrade to the latest release
russignol upgrade --check           Check for updates only
russignol upgrade --beta            Upgrade to the latest beta

russignol completions <shell>       Install shell completions (bash/zsh/fish)
russignol completions <shell> --print   Print completions to stdout instead
```

All node-dependent commands (`setup`, `check host`, `check disk`, `rotate-keys`, `image flash`, `image download-and-flash`) support `--endpoint` to override the configured RPC endpoint.

## Documentation

- [Installation Guide](../docs/INSTALL_HOST_UTILITY.md) — Complete setup walkthrough
- [CONFIGURATION.md](CONFIGURATION.md) — Configuration system and multi-network support
- [KEY_ROTATION.md](KEY_ROTATION.md) — Key rotation workflow
