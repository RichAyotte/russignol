//! Flash manifest contract.
//!
//! The host utility writes a manifest to the boot partition when it flashes a
//! card, and the signer reads it back on the device. The struct lives in one
//! crate so the writer and the reader cannot disagree on the format.

use serde::{Deserialize, Serialize};

/// Flash manifest written to the boot partition (p1) as `flash-manifest.json`
#[derive(Serialize, Deserialize)]
pub struct FlashManifest {
    pub card_id: String,
    pub flashed_at: String,
    pub host_version: String,
    pub image_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// SHA-256 (hex) of the image's rootfs partition region, for the
    /// device-side integrity check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rootfs_sha256: Option<String>,
    /// Maintainer-signature verdict recorded by the host at flash time:
    /// `"verified"`, `"unsigned"`, or `"unavailable"`. Informational
    /// provenance only — p1 is attacker-mutable and the Pi has no secure boot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<String>,
}

/// Manifest filename on boot partition
pub const MANIFEST_FILENAME: &str = "flash-manifest.json";

/// Values for [`FlashManifest::signed`]. The host writes one of these and the
/// device reads it back, so both ends share the vocabulary here rather than
/// duplicating the literals across crates.
pub const SIGNED_VERIFIED: &str = "verified";
pub const SIGNED_UNSIGNED: &str = "unsigned";
pub const SIGNED_UNAVAILABLE: &str = "unavailable";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_all_fields() {
        let manifest = FlashManifest {
            card_id: "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8".to_string(),
            flashed_at: "2026-03-06T12:34:56Z".to_string(),
            host_version: "0.20.0-beta.1".to_string(),
            image_sha256: "abc123".to_string(),
            image_version: Some("0.20.0-beta.1".to_string()),
            channel: Some("beta".to_string()),
            rootfs_sha256: Some("def456".to_string()),
            signed: Some("verified".to_string()),
        };
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(json.contains("\"card_id\""));
        assert!(json.contains("\"image_version\""));
        assert!(json.contains("\"channel\""));
        assert!(json.contains("\"rootfs_sha256\""));
        assert!(json.contains("\"signed\""));
    }

    #[test]
    fn serialization_skips_none() {
        let manifest = FlashManifest {
            card_id: "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8".to_string(),
            flashed_at: "2026-03-06T12:34:56Z".to_string(),
            host_version: "0.20.0-beta.1".to_string(),
            image_sha256: "abc123".to_string(),
            image_version: None,
            channel: None,
            rootfs_sha256: None,
            signed: None,
        };
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(!json.contains("image_version"));
        assert!(!json.contains("channel"));
        assert!(!json.contains("rootfs_sha256"));
        assert!(!json.contains("signed"));
    }

    #[test]
    fn rootfs_hash_round_trips() {
        let manifest = FlashManifest {
            card_id: "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8".to_string(),
            flashed_at: "2026-03-06T12:34:56Z".to_string(),
            host_version: "0.25.0".to_string(),
            image_sha256: "abc123".to_string(),
            image_version: None,
            channel: None,
            rootfs_sha256: Some("def456".to_string()),
            signed: Some("verified".to_string()),
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: FlashManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rootfs_sha256, Some("def456".to_string()));
        assert_eq!(parsed.signed, Some("verified".to_string()));
    }

    #[test]
    fn deserializes_manifest_without_rootfs_hash() {
        // Manifests written before the field existed must keep parsing.
        let json = r#"{
            "card_id": "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",
            "flashed_at": "2026-03-06T12:34:56Z",
            "host_version": "0.20.0",
            "image_sha256": "abc123"
        }"#;
        let parsed: FlashManifest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.rootfs_sha256, None);
    }

    #[test]
    fn deserializes_manifest_without_signed() {
        // Cards flashed before the field existed must keep parsing.
        let json = r#"{
            "card_id": "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",
            "flashed_at": "2026-03-06T12:34:56Z",
            "host_version": "0.20.0",
            "image_sha256": "abc123"
        }"#;
        let parsed: FlashManifest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.signed, None);
    }
}
