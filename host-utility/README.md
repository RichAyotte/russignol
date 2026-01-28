# Russignol Host Utility

CLI tool for configuring and managing a Russignol hardware signer from your baker host machine.

## Features

- Automated hardware detection and signer setup
- udev rules and network configuration
- Key discovery, import, and on-chain assignment
- SD card image flashing
- Key rotation with minimal downtime

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

russignol image download-and-flash  Download and flash SD card
russignol image download            Download image only
russignol image flash <path>        Flash local image
russignol image list                List available images

russignol config show               View current configuration
russignol config set <key> <value>  Update configuration
russignol config reset              Re-run auto-detection

russignol rotate-keys               Start key rotation workflow
russignol rotate-keys --monitor     Check pending rotation status

russignol status                    Check device connectivity
russignol status --endpoint <URL>   Check status using remote node
russignol completions <shell>       Install shell completions (bash/zsh/fish)
```

All node-dependent commands (`setup`, `status`, `rotate-keys`, `image flash`, `image download-and-flash`, `watermark init`) support `--endpoint` to override the configured RPC endpoint.

## Documentation

- [Installation Guide](../docs/INSTALL_HOST_UTILITY.md) — Complete setup walkthrough
- [CONFIGURATION.md](CONFIGURATION.md) — Configuration system and multi-network support
- [KEY_ROTATION.md](KEY_ROTATION.md) — Key rotation workflow
