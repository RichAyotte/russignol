//! Where cargo puts what it builds.
//!
//! Asked of `cargo metadata` rather than assumed to be `target/`, because
//! `CARGO_TARGET_DIR` or a `build.target-dir` in any cargo config above the
//! checkout moves it, and a path xtask assumes then names a binary that was
//! never built there.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetDir(PathBuf);

impl TargetDir {
    pub fn resolve() -> Result<Self> {
        Self::query(Command::new("cargo"))
    }

    fn query(mut cargo: Command) -> Result<Self> {
        let output = cargo
            .args(["metadata", "--format-version", "1", "--no-deps"])
            .output()
            .context("Failed to run cargo metadata")?;
        if !output.status.success() {
            bail!(
                "cargo metadata failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Self::parse(&output.stdout)
    }

    fn parse(metadata: &[u8]) -> Result<Self> {
        let metadata: serde_json::Value =
            serde_json::from_slice(metadata).context("cargo metadata printed no JSON")?;
        let dir = metadata
            .get("target_directory")
            .and_then(serde_json::Value::as_str)
            .context("cargo metadata named no target_directory")?;
        Ok(Self(PathBuf::from(dir)))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn binary(&self, triple: &str, profile: &str, name: &str) -> PathBuf {
        self.0.join(triple).join(profile).join(name)
    }

    /// A target directory of its own for one architecture's build, because
    /// cargo locks a target directory for the length of a build and builds
    /// sharing one would run one after the other.
    pub fn for_arch(&self, arch: &str) -> Self {
        Self(self.0.join(format!("xtask-{arch}")))
    }
}

#[cfg(test)]
impl From<PathBuf> for TargetDir {
    fn from(path: PathBuf) -> Self {
        Self(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_directory_is_what_cargo_metadata_names() {
        let metadata = br#"{"packages":[],"target_directory":"/mnt/scratch/build","version":1}"#;
        assert_eq!(
            TargetDir::parse(metadata).unwrap(),
            TargetDir::from(PathBuf::from("/mnt/scratch/build"))
        );
    }

    #[test]
    fn metadata_naming_no_directory_is_an_error() {
        let err = TargetDir::parse(br#"{"packages":[]}"#).unwrap_err();
        assert!(err.to_string().contains("target_directory"), "{err}");
    }

    /// The override a developer sets in their environment reaches the query,
    /// so xtask reads binaries where the cargo it spawns writes them.
    #[test]
    fn the_query_follows_cargo_target_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cargo = Command::new("cargo");
        cargo.env("CARGO_TARGET_DIR", dir.path());

        assert_eq!(
            TargetDir::query(cargo).unwrap(),
            TargetDir::from(dir.path().to_path_buf())
        );
    }

    #[test]
    fn a_binary_sits_under_the_directory_in_cargos_layout() {
        let target = TargetDir::from(PathBuf::from("/mnt/scratch/build"));
        assert_eq!(
            target.binary("aarch64-unknown-linux-gnu", "release", "russignol-signer"),
            Path::new("/mnt/scratch/build/aarch64-unknown-linux-gnu/release/russignol-signer")
        );
    }

    #[test]
    fn each_architecture_builds_in_its_own_directory_under_it() {
        let target = TargetDir::from(PathBuf::from("/mnt/scratch/build"));
        let x86 = target.for_arch("x86_64");
        let arm = target.for_arch("aarch64");

        assert!(x86.path().starts_with(target.path()), "{x86:?}");
        assert!(arm.path().starts_with(target.path()), "{arm:?}");
        assert_ne!(x86, arm);
        assert_ne!(x86, target);
    }
}
