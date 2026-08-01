# Device

- **SSH**: `sshpass -p russignol ssh russignol@russignol` (dev images only — hardened builds have no SSH)
- **Hardware**: Raspberry Pi Zero 2W (BCM2710A1 / Cortex-A53, ARMv8.0-A)
- **Display**: Waveshare 2.13" Touch e-Paper HAT V4 (SPI: SSD1680Z8, I2C: GT1151Q)
- **Workload**: ~3 BLS12-381 signatures (~6ms each) every ~6 seconds; idle 99.9% of the time

# Build and Test

Use xtask for all build and test operations:

```sh
cargo xtask test              # Run every test in the workspace
cargo xtask rpi-signer        # Build RPi signer (--dev for debug build)
cargo xtask host-utility      # Build host utility
cargo xtask image             # Build SD card image
cargo xtask release stable    # Full release build (bumps version, builds, tags); channel is beta|stable
cargo xtask release stable --github  # Release and publish to GitHub
cargo xtask publish --github  # Publish existing build to GitHub (no rebuild)
cargo xtask publish --website # Publish website to Cloudflare Pages
cargo xtask deploy            # Build, deploy, and restart signer on device
cargo xtask deploy --dev      # Build and deploy debug binary
cargo xtask deploy --skip-build  # Deploy previously built binary
cargo xtask coverage          # Code coverage report (--open, --lcov)
cargo xtask watermark-test    # Watermark E2E tests on a physical device
cargo xtask upgrade           # Upgrade dependencies, verify, and commit
cargo xtask upgrade --no-image   # Skip the image build (buildroot/kernel bumps stay uncommitted)
cargo xtask upgrade --no-verify  # Apply upgrades only (implies no commit)
cargo xtask deps              # Check for unused dependencies
cargo xtask validate          # Validate build environment
cargo xtask clean             # Clean build artifacts
cargo xtask config buildroot nconfig   # Configure buildroot (ncurses menu)
cargo xtask config busybox menuconfig  # Configure busybox
cargo xtask config kernel nconfig      # Configure Linux kernel
```

# Flashing

Always flash SD cards with the host utility, never raw `dd` or an imager:

```sh
russignol image flash buildroot/output/images/sdcard.img.xz
```

The host utility handles device auto-detection, mount/safety checks, decompression, and post-write partition re-read that a bare `dd` skips.

# Inspecting a card on the host (no sudo)

- **Mount**: `udisksctl mount -b /dev/sdXN` / `udisksctl unmount -b /dev/sdXN`. polkit auto-authorizes an active local session to mount removable media, so the root `udisks2` daemon performs the mount (lands under `/run/media/$USER/`). The `mount` command itself needs root; `udisksctl` does not. Works for the vfat boot partition and the f2fs keys/data partitions.
- **Raw read/write**: `disk`-group membership grants read+write on `/dev/sdX*`, so `strings`/`dd` can inspect a partition without mounting (e.g. read a staged `watermark-config.json`, confirm a build feature is compiled in). The `disk` group does not grant `mount(2)` (needs `CAP_SYS_ADMIN`) — hence mounting goes through `udisksctl`, not `mount`.

# Pre-commit

```sh
cargo clippy --workspace --all-targets
cargo fmt
```

Run clippy on the **whole workspace** every time. Do not narrow to a single
package (`-p …`) or target kind (`--lib` only): that skips binary crates such
as `russignol-signer` and misses lints that only fire on the non-test binary
compile unit (notably `dead_code` for helpers used solely from `#[cfg(test)]`).

- `--workspace` — every member (`libs/*`, `rpi-signer`, `host-utility`, …)
- `--all-targets` — lib, bins, tests, examples, and benches for each member

Do not confuse `--fix` with “all packages”: `--fix` auto-applies clippy
suggestions (and needs `--allow-dirty` / `--allow-staged` on a dirty tree).
Use it only when you intend to rewrite sources.

Treat warnings as defects and fix them at the source.

# Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) format for all commit messages.

# Code Quality

- Fix warnings and clippy lints at the source; avoid `#[allow(...)]` suppression
- Use TDD: write failing test, implement minimum to pass, refactor
