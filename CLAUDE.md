# Device

- **SSH**: `sshpass -p russignol ssh russignol@russignol`
- **Hardware**: Raspberry Pi Zero 2W (BCM2710A1 / Cortex-A53, ARMv8.0-A)
- **Display**: Waveshare 2.13" Touch e-Paper HAT V4 (SPI: SSD1680Z8, I2C: GT1151Q)
- **Workload**: ~3 BLS12-381 signatures (~6ms each) every ~6 seconds; idle 99.9% of the time

# Build and Test

Use xtask for all build and test operations:

```sh
cargo xtask test              # Run tests (--no-fuzz skips proptest fuzzing)
cargo xtask rpi-signer        # Build RPi signer (--dev for debug build)
cargo xtask host-utility      # Build host utility
cargo xtask image             # Build SD card image
cargo xtask release           # Full release build (bumps version, builds, tags)
cargo xtask release --github  # Release and publish to GitHub
cargo xtask publish --github  # Publish existing build to GitHub (no rebuild)
cargo xtask publish --website # Publish website to Cloudflare Pages
cargo xtask deploy            # Build, deploy, and restart signer on device
cargo xtask deploy --dev      # Build and deploy debug binary
cargo xtask deploy --skip-build  # Deploy previously built binary
cargo xtask validate          # Validate build environment
cargo xtask clean             # Clean build artifacts
cargo xtask config buildroot nconfig   # Configure buildroot (ncurses menu)
cargo xtask config busybox menuconfig  # Configure busybox
cargo xtask config kernel nconfig      # Configure Linux kernel
```

# Pre-commit

```sh
cargo clippy --fix --allow-dirty --allow-staged
cargo fmt
```

# Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) format for all commit messages.

# Code Quality

- Fix warnings and clippy lints at the source; avoid `#[allow(...)]` suppression
- Use TDD: write failing test, implement minimum to pass, refactor
