# Contributing

[Open an issue](https://github.com/RichAyotte/russignol/issues) before starting work on non-trivial changes.

Quality PRs are focused, small, and include tests.

## Requirements

Latest stable Rust (edition 2024)

Run `cargo xtask validate` to check your build environment.

## Before Submitting

```sh
cargo clippy --fix --allow-dirty --allow-staged
cargo fmt
cargo xtask test
```
