# xtask - Russignol Build Automation

Rust-based build system for the Russignol project.

## Quick Start

```bash
cargo xtask host-utility           # Build host utility
cargo xtask rpi-signer             # Build RPi signer
cargo xtask release stable         # Full release build
cargo xtask validate               # Check build environment
cargo xtask test                   # Run tests
cargo xtask clean                  # Remove artifacts
```

## Commands

### `rpi-signer`
Build the Raspberry Pi signer for ARM64 (Cortex-A53).

```bash
cargo xtask rpi-signer
cargo xtask rpi-signer --dev       # Debug build
```

**Prerequisites:** `aarch64-linux-gnu-gcc` (the Rust target `aarch64-unknown-linux-gnu` is installed automatically if missing)

### `host-utility`
Build the host utility for x86_64 and ARM64 Linux.

```bash
cargo xtask host-utility                 # All architectures, built in parallel
cargo xtask host-utility --arch x86-64   # Single architecture (x86-64 or aarch64)
cargo xtask host-utility --sequential    # Build architectures one at a time
cargo xtask host-utility --dev           # Debug build
```

### `image`
Build the bootable SD card image via buildroot.

```bash
cargo xtask image                  # Hardened build
cargo xtask image --dev            # Development build (SSH enabled)
cargo xtask image --clean          # Force clean build (ignore cached state)
```

**Prerequisites:** Buildroot in `./buildroot/`, ~10GB disk space

### `release`
Full release: bump version (commit, tag, and push), test, build all artifacts, and optionally publish.

The release channel is required: `beta` produces or increments a `-beta.N` pre-release; `stable` graduates the current pre-release or bumps by commit analysis.

```bash
cargo xtask release stable                           # Stable release
cargo xtask release beta                             # Beta pre-release
cargo xtask release stable --clean                   # Clean before building
cargo xtask release stable --github                  # Also publish to GitHub (requires gh CLI)
cargo xtask release stable --website                 # Also publish website (requires wrangler CLI)
cargo xtask release stable --component host-utility  # Release a single component
cargo xtask release stable --no-bump                 # Skip version bump (stable only)
```

Version is bumped based on conventional commits (feat → minor, fix → patch, breaking → major). The version bump is committed, tagged, and pushed (with upstream set) to origin. `--component` selects what to release: `signer`, `host-utility`, `signer-lib`, `ui`, `crypto`, `epd-display`, or `all` (the default); `--website` applies only to full releases.

GitHub release notes are generated from conventional commits and polished with the `claude` CLI when it is installed (10-minute timeout, falling back to the deterministic generator).

### `publish`
Publish existing release artifacts without rebuilding. At least one of `--github`/`--website` is required.

```bash
cargo xtask publish --github                           # Publish to GitHub releases
cargo xtask publish --website                          # Publish website to Cloudflare Pages
cargo xtask publish --github --website                 # Both
cargo xtask publish --github --component host-utility  # Single component
```

### `deploy`
Build, deploy, and restart the signer on a connected device at 169.254.1.1. Requires `sshpass` and a development image on the device.

```bash
cargo xtask deploy
cargo xtask deploy --dev           # Deploy a debug build
cargo xtask deploy --skip-build    # Deploy previously built binary
```

### `config`
Configure buildroot, BusyBox, or the Linux kernel. Add `--dev` for the development (non-hardened) configuration.

```bash
cargo xtask config buildroot nconfig   # buildroot: nconfig, menuconfig, load, update
cargo xtask config busybox menuconfig  # busybox: menuconfig, update
cargo xtask config kernel nconfig      # kernel: nconfig, update
cargo xtask config buildroot update    # Save changes back to the defconfig
```

### `test`
Run test suites.

```bash
cargo xtask test
cargo xtask test --no-fuzz         # Skip proptest fuzzing
```

### `coverage`
Generate a code coverage report. Requires `cargo-llvm-cov`.

```bash
cargo xtask coverage               # HTML report
cargo xtask coverage --open        # Open HTML report in browser
cargo xtask coverage --lcov        # LCOV output instead of HTML
```

### `watermark-test`
Run watermark protection E2E tests on a physical device.

```bash
cargo xtask watermark-test
cargo xtask watermark-test --category basic   # basic, multi, chain, or edge
```

Options: `--device <ip>` (default 169.254.1.1), `--port <port>` (default 7732), `--user <user>` (default russignol), `--clean` (clear watermarks first), `--restart` (restart device service first), `--verbose`.

### `upgrade`
Check for and apply dependency upgrades.

```bash
cargo xtask upgrade
```

### `deps`
Check for unused dependencies. Requires `cargo-machete`.

```bash
cargo xtask deps
```

### `clean`
Remove build artifacts.

```bash
cargo xtask clean
cargo xtask clean --buildroot      # Also clean buildroot output
cargo xtask clean --deep           # Also remove buildroot downloads and ccache
```

### `validate`
Check build environment prerequisites.

```bash
cargo xtask validate
```

## Troubleshooting

### "Command not found: cargo xtask"
Make sure you're in the project directory (alias defined in `.cargo/config.toml`).

### "Failed to execute: aarch64-linux-gnu-gcc"
```bash
sudo apt install gcc-aarch64-linux-gnu
```

### "Target not installed"
```bash
rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu
```

Run `cargo xtask validate` to check all prerequisites.
