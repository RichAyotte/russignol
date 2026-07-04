use crate::utils::{create_http_agent, http_get_json};
use anyhow::{Context, Result};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Current version (embedded at build time from Cargo.toml)
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// GitHub API URL for releases list
const GITHUB_RELEASES_URL: &str = "https://api.github.com/repos/RichAyotte/russignol/releases";

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
    /// Asset download URL as reported by the GitHub API
    pub download_url: String,
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
    /// Asset download URL as reported by the GitHub API
    pub download_url: String,
}

/// GitHub API response for a release
#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    published_at: String,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}

/// GitHub API response for a release asset
#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    size: u64,
    browser_download_url: String,
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

/// Parse checksums.txt content into a `HashMap`
///
/// Expects sha256sum format: "<hash>  <filename>" (two spaces between hash and filename).
/// Returns a `HashMap` mapping filename -> sha256 hash.
fn parse_checksums(content: &str) -> HashMap<String, String> {
    let mut checksums = HashMap::new();
    for line in content.lines() {
        // Skip empty lines
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Split on double-space (sha256sum format)
        if let Some((hash, filename)) = line.split_once("  ") {
            checksums.insert(filename.to_string(), hash.to_string());
        }
    }
    checksums
}

/// Fetch and parse checksums.txt from release assets
///
/// Returns a `HashMap` mapping filename -> sha256 hash.
/// Returns empty `HashMap` if checksums.txt is not found (backwards compatible with old releases).
fn fetch_checksums(agent: &ureq::Agent, assets: &[GitHubAsset]) -> HashMap<String, String> {
    // Find checksums.txt asset
    let checksums_asset = assets.iter().find(|a| a.name == "checksums.txt");

    let Some(asset) = checksums_asset else {
        log::debug!("checksums.txt not found in release assets");
        return HashMap::new();
    };

    // Fetch the checksums file
    let response = match agent.get(&asset.browser_download_url).call() {
        Ok(resp) => resp,
        Err(e) => {
            log::warn!("Failed to fetch checksums.txt: {e}");
            return HashMap::new();
        }
    };

    let content = match response.into_body().read_to_string() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Failed to read checksums.txt: {e}");
            return HashMap::new();
        }
    };

    let checksums = parse_checksums(&content);
    log::debug!("Loaded {} checksums from checksums.txt", checksums.len());
    checksums
}

/// Release asset class a caller needs; release selection only considers
/// releases that carry it
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredAsset {
    /// Host utility binaries (russignol-amd64 / russignol-aarch64)
    Binaries,
    /// SD card image (russignol-pi-zero.img.xz)
    Image,
}

fn has_required_asset(release: &GitHubRelease, required: RequiredAsset) -> bool {
    release.assets.iter().any(|a| match required {
        RequiredAsset::Binaries => a.name == "russignol-amd64" || a.name == "russignol-aarch64",
        RequiredAsset::Image => a.name == "russignol-pi-zero.img.xz",
    })
}

/// Parse the release version from a `v*` or `host-utility-v*` tag
fn parse_tag_version(tag: &str) -> Option<Version> {
    let version = tag
        .strip_prefix("host-utility-v")
        .or_else(|| tag.strip_prefix('v'))?;
    Version::parse(version).ok()
}

/// Tags of releases that pass the prerelease/asset filters but whose version
/// cannot be parsed, and would therefore be dropped from `latest` selection.
///
/// Surfaced as a warning so a newest release carrying an unexpected tag is not
/// silently ignored in favour of an older, parseable one.
fn unparsed_candidate_tags(
    releases: &[GitHubRelease],
    include_prerelease: bool,
    required: RequiredAsset,
) -> Vec<&str> {
    releases
        .iter()
        .filter(|r| include_prerelease || !r.prerelease)
        .filter(|r| has_required_asset(r, required))
        .filter(|r| parse_tag_version(&r.tag_name).is_none())
        .map(|r| r.tag_name.as_str())
        .collect()
}

/// Select the latest release carrying the required asset from `v*` or
/// `host-utility-v*` tagged releases.
///
/// Latest is judged by the version parsed from the tag — the GitHub
/// /releases list order does not track recency.
fn select_latest_release(
    releases: &[GitHubRelease],
    include_prerelease: bool,
    required: RequiredAsset,
) -> Option<&GitHubRelease> {
    releases
        .iter()
        .filter(|r| include_prerelease || !r.prerelease)
        .filter(|r| has_required_asset(r, required))
        .filter_map(|r| parse_tag_version(&r.tag_name).map(|v| (v, r)))
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, r)| r)
}

/// Build `VersionInfo` from a selected release and its fetched checksums
fn build_version_info(release: &GitHubRelease, checksums: &HashMap<String, String>) -> VersionInfo {
    // Parse version from tag (strip prefix)
    let version = release
        .tag_name
        .trim_start_matches("host-utility-v")
        .trim_start_matches('v')
        .to_string();

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
                    sha256: checksums.get(&asset.name).cloned().unwrap_or_default(),
                    size_bytes: asset.size,
                    download_url: asset.browser_download_url.clone(),
                },
            );
        } else if asset.name == "russignol-aarch64" {
            binaries.insert(
                "aarch64".to_string(),
                BinaryInfo {
                    filename: asset.name.clone(),
                    sha256: checksums.get(&asset.name).cloned().unwrap_or_default(),
                    size_bytes: asset.size,
                    download_url: asset.browser_download_url.clone(),
                },
            );
        } else if asset.name == "russignol-pi-zero.img.xz" {
            images.insert(
                "pi-zero".to_string(),
                ImageInfo {
                    filename: asset.name.clone(),
                    sha256: checksums.get(&asset.name).cloned().unwrap_or_default(),
                    size_bytes: 0, // Uncompressed size not available
                    compressed_size_bytes: asset.size,
                    min_sd_size_gb: 8,
                    download_url: asset.browser_download_url.clone(),
                },
            );
        }
    }

    VersionInfo {
        version,
        release_date,
        binaries,
        images,
    }
}

/// Fetch latest version info from GitHub releases API
///
/// Selects the newest `v*` or `host-utility-v*` release that carries the
/// required asset.
pub fn fetch_latest_version(
    include_prerelease: bool,
    required: RequiredAsset,
) -> Result<VersionInfo> {
    let agent = create_http_agent(30);
    let json = http_get_json(&agent, GITHUB_RELEASES_URL)
        .with_context(|| format!("Failed to fetch releases from {GITHUB_RELEASES_URL}"))?;

    let releases: Vec<GitHubRelease> =
        serde_json::from_value(json).context("Failed to parse GitHub releases response")?;

    for tag in unparsed_candidate_tags(&releases, include_prerelease, required) {
        crate::utils::warning(&format!(
            "Ignoring release with an unparseable version tag '{tag}' when selecting the latest release"
        ));
    }

    let release = select_latest_release(&releases, include_prerelease, required)
        .context("No matching release found")?;

    // Fetch checksums from checksums.txt (if available)
    let checksums = fetch_checksums(&agent, &release.assets);

    Ok(build_version_info(release, &checksums))
}

/// Get download URL for a specific architecture
pub fn get_download_url(version_info: &VersionInfo, arch: &str) -> Result<String> {
    let binary_info = version_info
        .binaries
        .get(arch)
        .with_context(|| format!("No binary available for architecture: {arch}"))?;

    Ok(binary_info.download_url.clone())
}

/// Get image download URL for a specific target (e.g., "pi-zero")
pub fn get_image_download_url(version_info: &VersionInfo, target: &str) -> Result<String> {
    let image_info = version_info
        .images
        .get(target)
        .with_context(|| format!("No image available for target: {target}"))?;

    Ok(image_info.download_url.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    "size_bytes": 3288232,
                    "download_url": "https://github.com/RichAyotte/russignol/releases/download/v0.2.0/russignol-amd64"
                },
                "aarch64": {
                    "filename": "russignol-aarch64",
                    "sha256": "def456",
                    "size_bytes": 2825296,
                    "download_url": "https://github.com/RichAyotte/russignol/releases/download/v0.2.0/russignol-aarch64"
                }
            }
        }"#;

        let version_info: VersionInfo = serde_json::from_str(json).unwrap();
        assert_eq!(version_info.version, "0.2.0");
        assert_eq!(version_info.binaries.len(), 2);
        assert_eq!(version_info.binaries["amd64"].filename, "russignol-amd64");
    }

    #[test]
    fn test_parse_checksums_valid() {
        let content = "\
abc123def456789012345678901234567890123456789012345678901234  russignol-amd64
def456abc789012345678901234567890123456789012345678901234567  russignol-aarch64
f9dbc58069cf55bfdd0497e16cfba842d5fbe4c3230ebc8a515bef6edd37904f  russignol-pi-zero.img.xz
";
        let checksums = parse_checksums(content);

        assert_eq!(checksums.len(), 3);
        assert_eq!(
            checksums.get("russignol-amd64"),
            Some(&"abc123def456789012345678901234567890123456789012345678901234".to_string())
        );
        assert_eq!(
            checksums.get("russignol-aarch64"),
            Some(&"def456abc789012345678901234567890123456789012345678901234567".to_string())
        );
        assert_eq!(
            checksums.get("russignol-pi-zero.img.xz"),
            Some(&"f9dbc58069cf55bfdd0497e16cfba842d5fbe4c3230ebc8a515bef6edd37904f".to_string())
        );
    }

    #[test]
    fn test_parse_checksums_empty() {
        let checksums = parse_checksums("");
        assert!(checksums.is_empty());
    }

    #[test]
    fn test_parse_checksums_with_empty_lines() {
        let content = "\
abc123  file1

def456  file2

";
        let checksums = parse_checksums(content);
        assert_eq!(checksums.len(), 2);
        assert_eq!(checksums.get("file1"), Some(&"abc123".to_string()));
        assert_eq!(checksums.get("file2"), Some(&"def456".to_string()));
    }

    #[test]
    fn test_parse_checksums_malformed_lines_ignored() {
        let content = "\
abc123  file1
invalid-no-double-space
def456  file2
";
        let checksums = parse_checksums(content);
        assert_eq!(checksums.len(), 2);
        assert_eq!(checksums.get("file1"), Some(&"abc123".to_string()));
        assert_eq!(checksums.get("file2"), Some(&"def456".to_string()));
    }

    #[test]
    fn test_missing_checksum_returns_empty_string() {
        // When a file is not in checksums.txt, unwrap_or_default returns empty string
        let checksums = parse_checksums("abc123  other-file\n");

        // File not in checksums - should return empty string (not None)
        // This empty string signals "checksum not available" to download functions
        let missing = checksums
            .get("russignol-amd64")
            .cloned()
            .unwrap_or_default();
        assert!(missing.is_empty());

        // Verify empty string is filtered out (the pattern used in download code)
        let as_option: Option<String> = Some(missing);
        let checksum = as_option.as_deref().filter(|s| !s.is_empty());
        assert!(checksum.is_none(), "Empty checksum should filter to None");
    }

    /// Helper to build a `GitHubRelease` with the given asset names,
    /// each carrying its real GitHub download URL derived from the tag
    fn make_release_with_assets(tag: &str, prerelease: bool, assets: &[&str]) -> GitHubRelease {
        GitHubRelease {
            tag_name: tag.to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
            prerelease,
            assets: assets
                .iter()
                .map(|name| GitHubAsset {
                    name: (*name).to_string(),
                    size: 1000,
                    browser_download_url: format!(
                        "https://github.com/RichAyotte/russignol/releases/download/{tag}/{name}"
                    ),
                })
                .collect(),
        }
    }

    /// Helper to build a `GitHubRelease` with both host binaries
    fn make_release(tag: &str, prerelease: bool) -> GitHubRelease {
        make_release_with_assets(tag, prerelease, &["russignol-amd64", "russignol-aarch64"])
    }

    #[test]
    fn unparsed_candidate_tags_flags_unparseable_but_qualifying_releases() {
        let releases = [
            make_release("v0.25.0", false),
            make_release("garbage-tag", false),
        ];
        assert_eq!(
            unparsed_candidate_tags(&releases, false, RequiredAsset::Binaries),
            vec!["garbage-tag"]
        );
    }

    #[test]
    fn unparsed_candidate_tags_respects_prerelease_filtering() {
        // An unparseable prerelease tag is filtered out before parsing, so it is
        // only surfaced when prereleases are actually being considered.
        let releases = [make_release("weird-beta", true)];
        assert!(unparsed_candidate_tags(&releases, false, RequiredAsset::Binaries).is_empty());
        assert_eq!(
            unparsed_candidate_tags(&releases, true, RequiredAsset::Binaries),
            vec!["weird-beta"]
        );
    }

    #[test]
    fn test_prerelease_filtering_excludes_prerelease_by_default() {
        let releases = [
            make_release("v0.20.0-beta.1", true),
            make_release("v0.19.0", false),
        ];

        let found = select_latest_release(&releases, false, RequiredAsset::Binaries).unwrap();

        assert_eq!(found.tag_name, "v0.19.0");
    }

    #[test]
    fn test_prerelease_filtering_includes_prerelease_when_requested() {
        let releases = [
            make_release("v0.20.0-beta.1", true),
            make_release("v0.19.0", false),
        ];

        let found = select_latest_release(&releases, true, RequiredAsset::Binaries).unwrap();

        assert_eq!(found.tag_name, "v0.20.0-beta.1");
    }

    #[test]
    fn test_selects_newest_version_not_first_in_list() {
        // GitHub's /releases ordering does not track recency
        let releases = [
            make_release("v0.25.0", false),
            make_release("host-utility-v0.26.0-beta.1", true),
        ];

        let found = select_latest_release(&releases, true, RequiredAsset::Binaries).unwrap();

        assert_eq!(found.tag_name, "host-utility-v0.26.0-beta.1");
    }

    #[test]
    fn test_selects_newest_stable_regardless_of_list_order() {
        let releases = [
            make_release("v0.24.0", false),
            make_release("v0.25.0", false),
        ];

        let found = select_latest_release(&releases, false, RequiredAsset::Binaries).unwrap();

        assert_eq!(found.tag_name, "v0.25.0");
    }

    #[test]
    fn test_image_selection_skips_releases_without_image() {
        let releases = [
            make_release_with_assets(
                "host-utility-v0.26.0-beta.1",
                true,
                &["russignol-amd64", "russignol-aarch64"],
            ),
            make_release_with_assets(
                "v0.25.0",
                false,
                &[
                    "russignol-amd64",
                    "russignol-aarch64",
                    "russignol-pi-zero.img.xz",
                ],
            ),
        ];

        let found = select_latest_release(&releases, true, RequiredAsset::Image).unwrap();

        assert_eq!(found.tag_name, "v0.25.0");
    }

    #[test]
    fn test_download_url_comes_from_release_asset() {
        let release =
            make_release_with_assets("host-utility-v0.26.0-beta.1", true, &["russignol-amd64"]);

        let info = build_version_info(&release, &HashMap::new());
        let url = get_download_url(&info, "amd64").unwrap();

        assert_eq!(
            url,
            "https://github.com/RichAyotte/russignol/releases/download/host-utility-v0.26.0-beta.1/russignol-amd64"
        );
    }

    #[test]
    fn test_image_download_url_comes_from_release_asset() {
        let mut release = make_release_with_assets("v0.25.0", false, &["russignol-pi-zero.img.xz"]);
        release.assets[0].browser_download_url =
            "https://cdn.example.com/russignol-pi-zero.img.xz".to_string();

        let info = build_version_info(&release, &HashMap::new());
        let url = get_image_download_url(&info, "pi-zero").unwrap();

        assert_eq!(url, "https://cdn.example.com/russignol-pi-zero.img.xz");
    }
}
