//! Flashed-image provenance, read once at boot.
//!
//! The init scripts mount the boot partition (p1) read-only, read
//! `flash-manifest.json`, and hand it to the signer in the environment — the
//! unprivileged runtime signer cannot mount p1 itself. This module parses that
//! value once and combines it with the live hardened posture (derived from the
//! read-only rootfs, never stored) into display-ready rows for the Image
//! screen and the greeting footer.

use crate::constants::FLASH_MANIFEST_ENV;
use crate::rootfs_check;
use russignol_flash_manifest::{
    FlashManifest, SIGNED_UNAVAILABLE, SIGNED_UNSIGNED, SIGNED_VERIFIED,
};
use std::sync::OnceLock;

/// A display label paired with its resolved value.
pub struct Row {
    pub label: &'static str,
    pub value: String,
}

/// Flashed-image provenance for display: the parsed manifest (absent on cards
/// flashed by an older host) and the live hardened posture.
pub struct ImageInfo {
    manifest: Option<FlashManifest>,
    hardened: bool,
}

static IMAGE_INFO: OnceLock<ImageInfo> = OnceLock::new();

/// The image provenance, parsed from the environment on first call and cached
/// for the process lifetime — the manifest is fixed at flash time and the
/// rootfs mount posture does not change once booted.
pub fn image_info() -> &'static ImageInfo {
    IMAGE_INFO.get_or_init(|| ImageInfo {
        manifest: parse_manifest_env(),
        hardened: rootfs_check::is_hardened(),
    })
}

/// Log the image provenance at boot, so a card's origin lands on the
/// operational trail even when no operator opens the Image screen.
pub fn log_image_info() {
    let info = image_info();
    for row in info.posture_rows().iter().chain(&info.checksum_rows()) {
        log::info!("image {}: {}", row.label, row.value);
    }
}

fn parse_manifest_env() -> Option<FlashManifest> {
    parse_manifest(&std::env::var(FLASH_MANIFEST_ENV).ok()?)
}

/// Parse the manifest JSON the init handed over. An empty value (older cards,
/// or no manifest on p1) or unparseable JSON yields `None`.
fn parse_manifest(raw: &str) -> Option<FlashManifest> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    serde_json::from_str(trimmed).ok()
}

impl ImageInfo {
    pub fn posture_rows(&self) -> Vec<Row> {
        posture_rows(self.manifest.as_ref(), self.hardened, build_commit())
    }

    pub fn checksum_rows(&self) -> Vec<Row> {
        checksum_rows(self.manifest.as_ref())
    }
}

const UNKNOWN: &str = "Unknown";
const ABSENT: &str = "—";

/// The signer's source commit, embedded at build time; `None` when built
/// outside a git tree. It stands in as the version for a locally built image,
/// which carries no release version but always has a source commit.
fn build_commit() -> Option<&'static str> {
    match option_env!("RUSSIGNOL_GIT_HASH") {
        Some(hash) if !hash.is_empty() && hash != "unknown" => Some(hash),
        _ => None,
    }
}

/// The recorded release version with channel, e.g. `0.25.0 (beta)`, or the
/// version alone when no channel is recorded; falling back to the build commit
/// when the manifest records no version; `None` when neither is available.
fn version_known(manifest: Option<&FlashManifest>, build_commit: Option<&str>) -> Option<String> {
    if let Some(manifest) = manifest
        && let Some(version) = &manifest.image_version
    {
        return Some(match &manifest.channel {
            Some(channel) => format!("{version} ({channel})"),
            None => version.clone(),
        });
    }
    build_commit.map(str::to_string)
}

/// Version for display; `Unknown` when neither the manifest nor a build commit
/// supplies one.
fn version_display(manifest: Option<&FlashManifest>, build_commit: Option<&str>) -> String {
    version_known(manifest, build_commit).unwrap_or_else(|| UNKNOWN.to_string())
}

/// The maintainer-signature verdict the host recorded, as a display word;
/// `None` when the field is missing (older manifest) or unrecognized.
fn signed_known(signed: Option<&str>) -> Option<&'static str> {
    match signed {
        Some(value) if value == SIGNED_VERIFIED => Some("Verified"),
        Some(value) if value == SIGNED_UNSIGNED => Some("Unsigned"),
        Some(value) if value == SIGNED_UNAVAILABLE => Some("Unavailable"),
        _ => None,
    }
}

/// The signature verdict as a display word, `Unknown` when absent/unrecognized.
fn signed_display(signed: Option<&str>) -> &'static str {
    signed_known(signed).unwrap_or(UNKNOWN)
}

/// Flash date (the date portion of the RFC3339 timestamp); `—` when no
/// manifest is present.
fn flashed_display(manifest: Option<&FlashManifest>) -> String {
    match manifest {
        Some(manifest) => match manifest.flashed_at.split_once('T') {
            Some((date, _)) => date.to_string(),
            None => manifest.flashed_at.clone(),
        },
        None => ABSENT.to_string(),
    }
}

/// Posture rows for the Image screen and greeting footer: Version, Mode,
/// Signed, Flashed. `hardened` is the live read-only-rootfs posture.
pub fn posture_rows(
    manifest: Option<&FlashManifest>,
    hardened: bool,
    build_commit: Option<&str>,
) -> Vec<Row> {
    vec![
        Row {
            label: "Version",
            value: version_display(manifest, build_commit),
        },
        Row {
            label: "Mode",
            value: if hardened { "Hardened" } else { "Dev" }.to_string(),
        },
        Row {
            label: "Signed",
            value: signed_display(manifest.and_then(|m| m.signed.as_deref())).to_string(),
        },
        Row {
            label: "Flashed",
            value: flashed_display(manifest),
        },
    ]
}

/// Checksum rows for the Image screen: the recorded SHA-256s and identifiers,
/// as full values — the page truncates for the narrow display. `—` when absent.
pub fn checksum_rows(manifest: Option<&FlashManifest>) -> Vec<Row> {
    let absent = || ABSENT.to_string();
    vec![
        Row {
            label: "Image",
            value: manifest.map_or_else(absent, |m| m.image_sha256.clone()),
        },
        Row {
            label: "Rootfs",
            value: manifest
                .and_then(|m| m.rootfs_sha256.clone())
                .unwrap_or_else(absent),
        },
        Row {
            label: "Host",
            value: manifest.map_or_else(absent, |m| m.host_version.clone()),
        },
        Row {
            label: "Card ID",
            value: manifest.map_or_else(absent, |m| m.card_id.clone()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_manifest() -> FlashManifest {
        FlashManifest {
            card_id: "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8".to_string(),
            flashed_at: "2026-03-06T12:34:56Z".to_string(),
            host_version: "0.25.0".to_string(),
            image_sha256: "image-hash".to_string(),
            image_version: Some("0.25.0".to_string()),
            channel: Some("beta".to_string()),
            rootfs_sha256: Some("rootfs-hash".to_string()),
            signed: Some("verified".to_string()),
        }
    }

    fn value_of<'a>(rows: &'a [Row], label: &str) -> &'a str {
        rows.iter()
            .find(|row| row.label == label)
            .map(|row| row.value.as_str())
            .unwrap()
    }

    #[test]
    fn posture_rows_render_a_full_hardened_manifest() {
        let manifest = full_manifest();
        let rows = posture_rows(Some(&manifest), true, None);
        assert_eq!(value_of(&rows, "Version"), "0.25.0 (beta)");
        assert_eq!(value_of(&rows, "Mode"), "Hardened");
        assert_eq!(value_of(&rows, "Signed"), "Verified");
        assert_eq!(value_of(&rows, "Flashed"), "2026-03-06");
    }

    #[test]
    fn dev_posture_reports_dev_mode() {
        let manifest = full_manifest();
        let rows = posture_rows(Some(&manifest), false, None);
        assert_eq!(value_of(&rows, "Mode"), "Dev");
    }

    #[test]
    fn version_without_channel_omits_parentheses() {
        let mut manifest = full_manifest();
        manifest.channel = None;
        let rows = posture_rows(Some(&manifest), true, None);
        assert_eq!(value_of(&rows, "Version"), "0.25.0");
    }

    #[test]
    fn missing_signature_field_reads_unknown() {
        let mut manifest = full_manifest();
        manifest.signed = None;
        let rows = posture_rows(Some(&manifest), true, None);
        assert_eq!(value_of(&rows, "Signed"), "Unknown");
    }

    #[test]
    fn unsigned_and_unavailable_verdicts_map_to_words() {
        let mut manifest = full_manifest();
        manifest.signed = Some("unsigned".to_string());
        assert_eq!(
            value_of(&posture_rows(Some(&manifest), true, None), "Signed"),
            "Unsigned"
        );
        manifest.signed = Some("unavailable".to_string());
        assert_eq!(
            value_of(&posture_rows(Some(&manifest), true, None), "Signed"),
            "Unavailable"
        );
    }

    #[test]
    fn unrecognized_verdict_reads_unknown() {
        let mut manifest = full_manifest();
        manifest.signed = Some("bogus".to_string());
        assert_eq!(
            value_of(&posture_rows(Some(&manifest), true, None), "Signed"),
            "Unknown"
        );
    }

    #[test]
    fn absent_manifest_degrades_gracefully() {
        let rows = posture_rows(None, true, None);
        assert_eq!(value_of(&rows, "Version"), "Unknown");
        assert_eq!(value_of(&rows, "Signed"), "Unknown");
        assert_eq!(value_of(&rows, "Flashed"), "—");
        // Mode still reflects the live posture, not the missing manifest.
        assert_eq!(value_of(&rows, "Mode"), "Hardened");

        let checks = checksum_rows(None);
        assert_eq!(value_of(&checks, "Image"), "—");
        assert_eq!(value_of(&checks, "Rootfs"), "—");
        assert_eq!(value_of(&checks, "Host"), "—");
        assert_eq!(value_of(&checks, "Card ID"), "—");
    }

    #[test]
    fn checksum_rows_render_recorded_values() {
        let manifest = full_manifest();
        let rows = checksum_rows(Some(&manifest));
        assert_eq!(value_of(&rows, "Image"), "image-hash");
        assert_eq!(value_of(&rows, "Rootfs"), "rootfs-hash");
        assert_eq!(value_of(&rows, "Host"), "0.25.0");
        assert_eq!(
            value_of(&rows, "Card ID"),
            "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
        );
    }

    #[test]
    fn rootfs_hash_absent_is_a_dash() {
        let mut manifest = full_manifest();
        manifest.rootfs_sha256 = None;
        assert_eq!(value_of(&checksum_rows(Some(&manifest)), "Rootfs"), "—");
    }

    #[test]
    fn version_falls_back_to_build_commit() {
        let mut manifest = full_manifest();
        manifest.image_version = None;
        manifest.channel = None;
        let rows = posture_rows(Some(&manifest), false, Some("a1b2c3d"));
        assert_eq!(value_of(&rows, "Version"), "a1b2c3d");
    }

    #[test]
    fn manifest_version_takes_precedence_over_build_commit() {
        let manifest = full_manifest();
        let rows = posture_rows(Some(&manifest), true, Some("a1b2c3d"));
        assert_eq!(value_of(&rows, "Version"), "0.25.0 (beta)");
    }

    #[test]
    fn build_commit_is_the_version_when_no_manifest() {
        let rows = posture_rows(None, true, Some("a1b2c3d"));
        assert_eq!(value_of(&rows, "Version"), "a1b2c3d");
    }

    #[test]
    fn parse_manifest_reads_valid_json() {
        let json = r#"{
            "card_id": "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",
            "flashed_at": "2026-03-06T12:34:56Z",
            "host_version": "0.25.0",
            "image_sha256": "abc123",
            "signed": "verified"
        }"#;
        let parsed = parse_manifest(json).unwrap();
        assert_eq!(parsed.signed, Some("verified".to_string()));
    }

    #[test]
    fn parse_manifest_empty_or_whitespace_is_none() {
        assert!(parse_manifest("").is_none());
        assert!(parse_manifest("   \n  ").is_none());
    }

    #[test]
    fn parse_manifest_invalid_json_is_none() {
        assert!(parse_manifest("not json").is_none());
    }
}
