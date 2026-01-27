use crate::utils::{create_http_agent, http_get_json};
use anyhow::{Context, Result};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Current version (embedded at build time from Cargo.toml)
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// GitHub repository for releases
const GITHUB_REPO: &str = "RichAyotte/russignol";

/// GitHub API URL for latest release
const GITHUB_API_URL: &str = "https://api.github.com/repos/RichAyotte/russignol/releases/latest";

/// GitHub release asset download URL pattern
fn github_release_url(version: &str, filename: &str) -> String {
    format!("https://github.com/{GITHUB_REPO}/releases/download/v{version}/{filename}")
}

/// Version metadata for releases
#[derive(Debug, Deserialize, Serialize)]
pub struct VersionInfo {
    pub version: String,
    pub release_date: String,
    pub binaries: HashMap<String, BinaryInfo>,
    /// Optional SD card images (keyed by target, e.g., "pi-zero")
    #[serde(default)]
    pub images: HashMap<String, ImageInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BinaryInfo {
    pub filename: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Image metadata for SD card images
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ImageInfo {
    pub filename: String,
    pub sha256: String,
    /// Uncompressed image size in bytes
    pub size_bytes: u64,
    /// Compressed file size in bytes
    pub compressed_size_bytes: u64,
    /// Minimum SD card size in GB
    #[serde(default)]
    pub min_sd_size_gb: u64,
}

/// GitHub API response for a release
#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    published_at: String,
    assets: Vec<GitHubAsset>,
}

/// GitHub API response for a release asset
#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    size: u64,
}

/// Get current version
pub fn current_version() -> &'static str {
    VERSION
}

/// Get current architecture as string ("amd64" or "aarch64")
pub fn current_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "aarch64",
        arch => arch, // Fallback to the actual arch name
    }
}

/// Compare two version strings, returns true if latest is newer than current
pub fn is_newer(current: &str, latest: &str) -> Result<bool> {
    let current_ver = Version::parse(current)
        .with_context(|| format!("Failed to parse current version: {current}"))?;
    let latest_ver = Version::parse(latest)
        .with_context(|| format!("Failed to parse latest version: {latest}"))?;

    Ok(latest_ver > current_ver)
}

/// Fetch latest version info from GitHub releases API
pub fn fetch_latest_version() -> Result<VersionInfo> {
    let agent = create_http_agent(30);
    let json = http_get_json(&agent, GITHUB_API_URL)
        .with_context(|| format!("Failed to fetch release info from {GITHUB_API_URL}"))?;

    let release: GitHubRelease =
        serde_json::from_value(json).context("Failed to parse GitHub release response")?;

    // Parse version from tag (strip 'v' prefix)
    let version = release.tag_name.trim_start_matches('v').to_string();

    // Parse release date (extract date from ISO timestamp)
    let release_date = release
        .published_at
        .split('T')
        .next()
        .unwrap_or(&release.published_at)
        .to_string();

    // Build binaries map from assets
    let mut binaries = HashMap::new();
    let mut images = HashMap::new();

    for asset in &release.assets {
        if asset.name == "russignol-amd64" {
            binaries.insert(
                "amd64".to_string(),
                BinaryInfo {
                    filename: asset.name.clone(),
                    sha256: String::new(), // SHA256 not available from GitHub API
                    size_bytes: asset.size,
                },
            );
        } else if asset.name == "russignol-aarch64" {
            binaries.insert(
                "aarch64".to_string(),
                BinaryInfo {
                    filename: asset.name.clone(),
                    sha256: String::new(),
                    size_bytes: asset.size,
                },
            );
        } else if asset.name == "russignol-pi-zero.img.xz" {
            images.insert(
                "pi-zero".to_string(),
                ImageInfo {
                    filename: asset.name.clone(),
                    sha256: String::new(),
                    size_bytes: 0, // Uncompressed size not available
                    compressed_size_bytes: asset.size,
                    min_sd_size_gb: 8,
                },
            );
        }
    }

    Ok(VersionInfo {
        version,
        release_date,
        binaries,
        images,
    })
}

/// Get download URL for a specific architecture
pub fn get_download_url(version_info: &VersionInfo, arch: &str) -> Result<String> {
    let binary_info = version_info
        .binaries
        .get(arch)
        .with_context(|| format!("No binary available for architecture: {arch}"))?;

    Ok(github_release_url(
        &version_info.version,
        &binary_info.filename,
    ))
}

/// Get image download URL for a specific target (e.g., "pi-zero")
pub fn get_image_download_url(version_info: &VersionInfo, target: &str) -> Result<String> {
    let image_info = version_info
        .images
        .get(target)
        .with_context(|| format!("No image available for target: {target}"))?;

    Ok(github_release_url(
        &version_info.version,
        &image_info.filename,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_version() {
        let version = current_version();
        assert!(!version.is_empty());
        // Should be valid semver
        assert!(Version::parse(version).is_ok());
    }

    #[test]
    fn test_current_arch() {
        let arch = current_arch();
        assert!(arch == "amd64" || arch == "aarch64" || !arch.is_empty());
    }

    #[test]
    fn test_is_newer() {
        assert!(is_newer("0.1.0", "0.2.0").unwrap());
        assert!(is_newer("0.1.0", "1.0.0").unwrap());
        assert!(!is_newer("1.0.0", "0.9.0").unwrap());
        assert!(!is_newer("1.0.0", "1.0.0").unwrap());
    }

    #[test]
    fn test_version_info_deserialization() {
        let json = r#"{
            "version": "0.2.0",
            "release_date": "2025-11-27",
            "binaries": {
                "amd64": {
                    "filename": "russignol-amd64",
                    "sha256": "abc123",
                    "size_bytes": 3288232
                },
                "aarch64": {
                    "filename": "russignol-aarch64",
                    "sha256": "def456",
                    "size_bytes": 2825296
                }
            }
        }"#;

        let version_info: VersionInfo = serde_json::from_str(json).unwrap();
        assert_eq!(version_info.version, "0.2.0");
        assert_eq!(version_info.binaries.len(), 2);
        assert_eq!(version_info.binaries["amd64"].filename, "russignol-amd64");
    }
}
