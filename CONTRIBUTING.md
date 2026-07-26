# Contributing

[Open an issue](https://github.com/RichAyotte/russignol/issues) before starting work on non-trivial changes.

Quality PRs are focused, small, and include tests.

## Requirements

Latest stable Rust (edition 2024)

Run `cargo xtask validate` to check your build environment.

## Before Submitting

```sh
cargo clippy --workspace --all-targets
cargo fmt
cargo xtask test
```

Always lint the full workspace (`--workspace`) and every target kind
(`--all-targets`: lib, bins, tests, …). Do not substitute a single-package
or `--lib`-only clippy run: binary crates (e.g. `russignol-signer`) are
checked separately from their unit tests, and test-only helpers otherwise
show up as `dead_code` on real builds (including the RPi image build) but
not when you only lint a library package.

`--fix` means “auto-apply suggestions,” not “all packages.” Only add it
(with `--allow-dirty` / `--allow-staged` on a dirty tree) when you intend
clippy to rewrite sources.
