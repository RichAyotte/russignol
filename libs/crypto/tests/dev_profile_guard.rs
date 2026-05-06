//! Regression guard for the dev-profile scrypt optimization.
//!
//! `scrypt::scrypt` is invoked on every PIN unlock and every keygen with
//! hardened parameters (`log_n=18`, 256 MB memory-hard). At the workspace
//! dev profile's default opt-level the inner mixing loop is slow enough on
//! a Raspberry Pi Zero 2W that the e-paper "Generating Keys" page never
//! visibly advances — the device looks frozen even though no panic occurred.
//!
//! Restoring `[profile.dev.package.scrypt] opt-level = 3` keeps the dev
//! image usable. This test fails if that override is dropped so the
//! regression cannot be reintroduced silently by a dependency-bump or
//! profile-cleanup commit.

use std::path::PathBuf;

#[test]
fn dev_profile_optimizes_scrypt() {
    let workspace_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("Cargo.toml");
    let manifest_str = std::fs::read_to_string(&workspace_manifest)
        .unwrap_or_else(|e| panic!("read {}: {e}", workspace_manifest.display()));
    let parsed: toml::Value = toml::from_str(&manifest_str).expect("parse workspace Cargo.toml");

    let opt_level = parsed
        .get("profile")
        .and_then(|v| v.get("dev"))
        .and_then(|v| v.get("package"))
        .and_then(|v| v.get("scrypt"))
        .and_then(|v| v.get("opt-level"))
        .and_then(toml::Value::as_integer);

    assert_eq!(
        opt_level,
        Some(3),
        "[profile.dev.package.scrypt] opt-level=3 missing from workspace Cargo.toml; \
         without it, scrypt runs unoptimized in dev builds and the keygen page on the \
         RPi Zero 2W appears to hang"
    );
}
