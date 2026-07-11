//! Shared writers for the device-owned files a host may write onto a signer card.
//!
//! The device reads `chain_info.json`, so a host that writes it (restoring a
//! card, or repairing one with `check disk`) must produce a byte- and
//! mode-identical artifact. Watermark files are not written here: only the
//! PIN-unlocked device can authenticate a mark, so the host stages a boot config
//! and the device establishes the floor itself. Both callers route through these
//! helpers so the JSON shape and permissions live in one place and cannot drift.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result};

use crate::watermark::ChainInfo;

/// Owner (uid:gid) every device file must carry. `russignol` is uid/gid 1000 on
/// the device and does not exist on the host, so ownership is numeric.
pub const DEVICE_UID: u32 = 1000;
pub const DEVICE_GID: u32 = 1000;

/// Mode the device sets on `chain_info.json`: owner read-only. The device
/// (`rpi-signer/src/watermark_setup.rs`) chmods it to this after writing, so a
/// host writer must match or the disk check reports mode drift on its own output.
pub const CHAIN_INFO_MODE: u32 = 0o400;

/// Basename of the chain-info file on the keys partition.
pub const CHAIN_INFO_FILENAME: &str = "chain_info.json";

/// Write `chain_info.json` into a mounted keys partition and set its device mode.
///
/// The persisted shape is `{id, name, blocks_per_cycle}` — `level` is
/// deliberately not stored here (it lives in the watermark files).
pub fn write_chain_info(keys_mount: &Path, chain_info: &ChainInfo) -> Result<()> {
    let path = keys_mount.join(CHAIN_INFO_FILENAME);
    let json = serde_json::json!({
        "id": chain_info.id,
        "name": chain_info.name,
        "blocks_per_cycle": chain_info.blocks_per_cycle,
    });
    let contents =
        serde_json::to_string_pretty(&json).context("failed to serialize chain_info.json")?;
    // A prior chain_info.json is left at 0o400 (owner read-only), so a truncating
    // write is denied unless the owner first restores write permission. The
    // disk check rewrites a stale one unprivileged, so make an existing file writable
    // before overwriting; the mode is reset to 0o400 below.
    if path.exists() {
        let mut perms = fs::metadata(&path)
            .with_context(|| format!("failed to stat {}", path.display()))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)
            .with_context(|| format!("failed to make {} writable", path.display()))?;
    }
    fs::write(&path, contents).with_context(|| format!("failed to write {}", path.display()))?;
    set_chain_info_mode(&path)?;
    Ok(())
}

/// Set `chain_info.json` to its device mode (`0o400`, owner read-only). Shared
/// by the writer and the disk check's mode-drift repair so the mode has one home.
pub fn set_chain_info_mode(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .permissions();
    perms.set_mode(CHAIN_INFO_MODE);
    fs::set_permissions(path, perms)
        .with_context(|| format!("failed to set mode on {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_info_rewrites_over_an_existing_read_only_file() {
        // The device and restore path leave chain_info.json at 0o400 (owner
        // read-only). The disk check rewrites a stale one over that existing file
        // while running unprivileged, where a plain truncating write is denied.
        let dir = tempfile::tempdir().unwrap();
        let stale = ChainInfo {
            id: "NetXstale".to_string(),
            level: 1,
            name: "Stale".to_string(),
            blocks_per_cycle: 8,
        };
        write_chain_info(dir.path(), &stale).unwrap();

        let fresh = ChainInfo {
            id: "NetXfresh".to_string(),
            level: 2,
            name: "Fresh".to_string(),
            blocks_per_cycle: 16,
        };
        write_chain_info(dir.path(), &fresh).expect("rewrite over 0o400 file must succeed");

        let path = dir.path().join(CHAIN_INFO_FILENAME);
        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed["id"], "NetXfresh");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, CHAIN_INFO_MODE);
    }

    #[test]
    fn chain_info_persists_shape_without_level_and_is_owner_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let ci = ChainInfo {
            id: "NetXTest".to_string(),
            level: 999,
            name: "TestNet".to_string(),
            blocks_per_cycle: 128,
        };
        write_chain_info(dir.path(), &ci).unwrap();

        let path = dir.path().join(CHAIN_INFO_FILENAME);
        let contents = fs::read_to_string(&path).expect("chain_info.json not written");
        let parsed: serde_json::Value = serde_json::from_str(&contents).expect("valid JSON");
        assert_eq!(parsed["id"], "NetXTest");
        assert_eq!(parsed["name"], "TestNet");
        assert_eq!(parsed["blocks_per_cycle"], 128);
        // The level lives in the watermark files, never in chain_info.json.
        assert!(parsed.get("level").is_none());

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, CHAIN_INFO_MODE);
    }
}
