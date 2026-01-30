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
