//! `russignol check disk` — diagnose a signer SD card (read-only).
//!
//! Reads a signer's SD card and reports every detectable issue: missing or
//! corrupt watermarks, missing or stale `chain_info.json`, ownership/mode drift,
//! leftover boot config, log health, and setup/keys/migration state. Repair is
//! layered on separately; this module gathers state and classifies it.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use russignol_signer_lib::KeyManager;
use russignol_signer_lib::server::{KEY_ROLES, LARGE_GAP_CYCLES};
use russignol_storage::watermark;

use crate::card_fs::{self, CHAIN_INFO_MODE, DEVICE_GID, DEVICE_UID};
use crate::utils::{self, get_partition_path, info, print_title_bar, success, warning};
use crate::watermark::ChainInfo;
use crate::{config, network};

/// Maximum `panic.log` size before the disk check offers to truncate it, matching
/// the 1 MiB cap the device init applies on boot.
const PANIC_LOG_MAX_BYTES: u64 = 1024 * 1024;

/// Whether the running kernel can mount f2fs, read from `/proc/filesystems`
/// contents. Each line is `<flags>\t<name>`; a bare `nodev` line marks a
/// pseudo-filesystem. f2fs is a block filesystem, so its line has no leading
/// `nodev`.
fn proc_filesystems_has_f2fs(contents: &str) -> bool {
    contents.lines().any(|line| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            // "nodev\t<name>": a pseudo-filesystem, not mountable from a block device.
            (Some("nodev"), _) => false,
            // A block filesystem line carries only its name.
            (Some(name), None) => name == "f2fs",
            _ => false,
        }
    })
}

// =============================================================================
// Gathered card state (populated by read-only IO at the edges)
// =============================================================================

/// Which physical partition a finding concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Partition {
    /// p1, vfat boot partition.
    Boot,
    /// p3, f2fs keys partition.
    Keys,
    /// p4, f2fs data partition.
    Data,
}

/// Parse state of the keys partition's `public_key_hashs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysState {
    /// `public_key_hashs` absent.
    Missing,
    /// present but unparseable or empty.
    Unparseable,
    /// parsed; carries the key aliases and hashes found.
    Parsed {
        aliases: Vec<String>,
        pkhs: Vec<String>,
    },
}

/// Parse state of `/keys/chain_info.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainInfoState {
    /// file absent.
    Missing,
    /// Present (stat succeeded) but no valid chain info could be read — either
    /// the bytes were unreadable (wrong ownership/permissions) or the content
    /// was invalid. `owner`/`mode` let the classifier tell the two apart.
    Unreadable {
        owner: Option<(u32, u32)>,
        mode: Option<u32>,
    },
    /// present and parseable.
    Present {
        id: String,
        mode: Option<u32>,
        owner: Option<(u32, u32)>,
    },
}

/// Decode status of a single watermark file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatermarkFileStatus {
    Missing,
    WrongSize,
    Corrupt,
    Valid { level: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatermarkFile {
    pub name: String,
    pub status: WatermarkFileStatus,
    pub owner: Option<(u32, u32)>,
}

/// The watermark set for one key, as found under `/data/watermarks/<pkh>/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWatermarks {
    pub pkh: String,
    pub dir_present: bool,
    pub dir_owner: Option<(u32, u32)>,
    pub files: Vec<WatermarkFile>,
}

/// An un-consumed `watermark-config.json` staged on the boot partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootConfigState {
    pub chain_id: String,
    pub level: u32,
}

/// Outcome of trying to inspect the f2fs partitions (p3/p4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inspection {
    /// Mounted read-only and read successfully.
    Inspected,
    /// The host kernel cannot mount f2fs.
    NotCapable,
    /// The host can mount f2fs but the mount or read failed.
    Failed,
}

/// Everything the classifier needs, gathered by read-only IO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardState {
    /// Whether the keys and data partitions could be read.
    pub inspection: Inspection,

    // p3 keys
    pub setup_complete: bool,
    pub migration_pending: bool,
    pub keys: KeysState,
    pub chain_info: ChainInfoState,

    // p4 data
    pub watermarks: Vec<KeyWatermarks>,
    pub logs_dir_present: bool,
    pub panic_log_size: Option<u64>,

    // p1 boot
    pub boot_config: Option<BootConfigState>,
}

// =============================================================================
// Classified issues (pure)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The device cannot sign or cannot read its own files.
    Critical,
    /// Degraded but functional.
    Warning,
    /// Informational or report-only.
    Info,
}

/// How an issue can be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remedy {
    /// Repairable in place with the card in a host reader.
    HostDirect,
    /// Repairable by staging a boot config the device applies on its next boot,
    /// the fallback when the host cannot mount f2fs to repair the keys and data
    /// partitions directly.
    FatStage,
    /// A node endpoint is required before this can be resolved or even judged.
    NeedsNode,
    /// The disk check does not change this; the user or device must act.
    Manual,
}

/// Whether the tool can apply a repair for an issue with this remedy. This is
/// the only fix/no-fix split the report surfaces; the `HostDirect` (in place)
/// vs `FatStage` (staged for next boot) mechanism difference is internal to the
/// executor and deliberately not shown to the user.
fn remedy_is_fixable(remedy: Remedy) -> bool {
    match remedy {
        Remedy::HostDirect | Remedy::FatStage => true,
        Remedy::NeedsNode | Remedy::Manual => false,
    }
}

/// A card with no fault and nothing to repair. Info-severity findings describe
/// expected, self-resolving state — a staged config the device consumes on its
/// next boot, a directory it recreates on boot — so they are not issues: there
/// is nothing to warn about and nothing to act on. A fixable finding of any
/// severity means a repair is pending, so it is not healthy.
fn is_healthy(issues: &[Issue]) -> bool {
    !issues.iter().any(|i| {
        matches!(i.severity, Severity::Critical | Severity::Warning) || remedy_is_fixable(i.remedy)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    SetupIncomplete,
    KeysMissing,
    KeysUnparseable,
    KeysRoleMissing,
    MigrationPending,
    F2fsNotInspected,
    FatStageAvailable,
    WatermarkSeedMissing,
    WatermarkDirMissing,
    WatermarkFileMissing,
    WatermarkCorrupt,
    WatermarkBelowHead,
    WatermarkNodeUnknown,
    ChainInfoMissing,
    ChainInfoUnreadable,
    ChainInfoStale,
    ChainInfoNodeUnknown,
    ChainInfoModeDrift,
    OwnershipDrift,
    LeftoverBootConfig,
    LogsDirMissing,
    PanicLogOversized,
}

/// A concrete, confirmable repair the disk check applies to a card in a host reader.
///
/// Produced alongside the issue that motivates it, so the executor consumes the
/// planned repair rather than re-deriving one from the card state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairAction {
    /// Restore `1000:1000` ownership on a key's watermark directory.
    ChownWatermarks { pkh: String },
    /// Rewrite `chain_info.json` from the node (content, mode, owner).
    WriteChainInfo,
    /// Set `chain_info.json` mode to `0o400`.
    ChmodChainInfo,
    /// Restore `1000:1000` ownership on `chain_info.json`.
    ChownChainInfo,
    /// Truncate an oversized `panic.log`.
    TruncatePanicLog,
    /// Delete a stale `watermark-config.json` from the boot partition.
    DeleteBootConfig,
    /// Stage a `watermark-config.json` on the boot partition; the device
    /// configures watermarks and `chain_info` from it on its next boot. The
    /// fallback used when the host cannot mount f2fs to repair in place.
    StageBootConfig(ChainInfo),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub kind: IssueKind,
    pub severity: Severity,
    pub partition: Partition,
    pub remedy: Remedy,
    /// The repair the disk check can apply for this issue: present for `HostDirect`
    /// (in place) and `FatStage` (staged boot config) remedies, `None` for
    /// `NeedsNode` and `Manual`.
    pub action: Option<RepairAction>,
    pub message: String,
}

/// The remedy for an issue whose repair sources a level or chain id from the
/// node. Reachable only after f2fs inspection, so the host can mount f2fs and a
/// present node means an in-place repair; without a node it must wait.
fn node_backed_remedy(node: Option<&ChainInfo>) -> Remedy {
    if node.is_some() {
        Remedy::HostDirect
    } else {
        Remedy::NeedsNode
    }
}

fn owner_ok(owner: Option<(u32, u32)>) -> bool {
    owner.is_none_or(|(u, g)| u == DEVICE_UID && g == DEVICE_GID)
}

/// Whether a key's floor is far enough behind the node head to flag. Any offline
/// card lags a live chain, so a floor merely below head is normal; it only
/// warrants a repair once the gap exceeds what the device itself tolerates
/// (`LARGE_GAP_CYCLES`), the point past which a catch-up sign is refused on
/// device anyway. `blocks_per_cycle` of 0 (a degenerate node) falls back to a
/// plain below-head comparison.
fn floor_significantly_behind(floor: u32, node: &ChainInfo) -> bool {
    let threshold = LARGE_GAP_CYCLES.saturating_mul(node.blocks_per_cycle);
    node.level.saturating_sub(floor) > threshold
}

/// Map gathered card state and an optional node snapshot to the full issue list.
///
/// Pure: no IO, no clock, no environment. Detection that needs the node head or
/// chain id downgrades to an informational "unknown" when `node` is `None`.
pub fn classify(state: &CardState, node: Option<&ChainInfo>) -> Vec<Issue> {
    let mut issues = Vec::new();

    // The boot partition (p1, vfat) is inspectable on any host.
    classify_boot_config(state, node, &mut issues);

    if state.inspection != Inspection::Inspected {
        let message = if state.inspection == Inspection::NotCapable {
            "the host kernel cannot mount f2fs, so the keys and data partitions \
             were not inspected; run 'check disk' on an f2fs-capable host to \
             diagnose them"
        } else {
            "the keys or data partition could not be mounted, so they were not \
             inspected; check that the card is readable and that mounting f2fs is \
             permitted"
        };
        issues.push(Issue {
            kind: IssueKind::F2fsNotInspected,
            severity: Severity::Warning,
            partition: Partition::Keys,
            remedy: Remedy::Manual,
            action: None,
            message: message.to_string(),
        });
        // The keys and data partitions can't be repaired in place on this host,
        // but with a node a boot config can be staged for the device to apply on
        // its next boot. A failed mount is a card fault to investigate, not a
        // case for a blind staged config, so this is offered only when the host
        // simply lacks f2fs support.
        if state.inspection == Inspection::NotCapable
            && let Some(n) = node
        {
            issues.push(Issue {
                kind: IssueKind::FatStageAvailable,
                severity: Severity::Info,
                partition: Partition::Boot,
                remedy: Remedy::FatStage,
                action: Some(RepairAction::StageBootConfig(n.clone())),
                message: format!(
                    "the host cannot mount f2fs to repair the keys and data partitions \
                     directly; a watermark-config.json can be staged so the device \
                     configures watermarks and chain_info at level {} on its next boot",
                    n.level
                ),
            });
        }
        return issues;
    }

    // The migration blob lives on p3 whether or not first-boot setup finished.
    if state.migration_pending {
        issues.push(Issue {
            kind: IssueKind::MigrationPending,
            severity: Severity::Info,
            partition: Partition::Keys,
            remedy: Remedy::Manual,
            action: None,
            message: "a pending v1->v2 PIN-blob migration is present; the device \
                      completes it on boot and the disk check leaves it untouched"
                .to_string(),
        });
    }

    if !state.setup_complete {
        issues.push(Issue {
            kind: IssueKind::SetupIncomplete,
            severity: Severity::Info,
            partition: Partition::Keys,
            remedy: Remedy::Manual,
            action: None,
            message: "first-boot setup has not completed (.setup_complete absent); \
                      the device generates its keys, watermarks, and chain_info on \
                      first boot"
                .to_string(),
        });
        // A card that has never completed first-boot setup and has no seed staged
        // cannot establish an authenticated watermark floor on its own; stage a boot
        // config so the device seeds one. A seed already present is classified by
        // `classify_boot_config`, so gate on its absence to avoid double-counting.
        if state.boot_config.is_none() {
            let remedy = if node.is_some() {
                Remedy::FatStage
            } else {
                Remedy::NeedsNode
            };
            issues.push(Issue {
                kind: IssueKind::WatermarkSeedMissing,
                severity: Severity::Warning,
                partition: Partition::Boot,
                remedy,
                action: node.map(|n| RepairAction::StageBootConfig(n.clone())),
                message: match node {
                    Some(n) => format!(
                        "the card has no staged watermark-config.json and first-boot \
                         setup has not completed; a config can be staged so the device \
                         seeds watermarks and chain_info at level {} on its next boot",
                        n.level
                    ),
                    None => "the card has no staged watermark-config.json and first-boot \
                             setup has not completed; provide a node endpoint to stage one \
                             so the device seeds its authenticated watermark floor"
                        .to_string(),
                },
            });
        }
        return issues;
    }

    classify_keys(state, &mut issues);
    classify_chain_info(state, node, &mut issues);
    classify_watermarks(state, node, &mut issues);
    classify_logs(state, &mut issues);

    issues
}

fn classify_boot_config(state: &CardState, node: Option<&ChainInfo>, issues: &mut Vec<Issue>) {
    let Some(bc) = &state.boot_config else {
        return;
    };
    let stale_delete = |message: String| Issue {
        kind: IssueKind::LeftoverBootConfig,
        severity: Severity::Warning,
        partition: Partition::Boot,
        remedy: Remedy::HostDirect,
        action: Some(RepairAction::DeleteBootConfig),
        message,
    };
    match node {
        Some(n) if n.id != bc.chain_id => issues.push(stale_delete(format!(
            "a staged watermark-config.json targets chain {} at level {}, which differs \
             from the node's chain {}; it is stale and can be deleted",
            bc.chain_id, bc.level, n.id,
        ))),
        Some(n) if boot_config_superseded(state, &n.id, bc) => issues.push(stale_delete(format!(
            "a staged watermark-config.json (chain {} at level {}) is at or below the \
             card's current watermark floor and chain_info is current; it is superseded \
             and can be deleted",
            bc.chain_id, bc.level,
        ))),
        _ => issues.push(Issue {
            kind: IssueKind::LeftoverBootConfig,
            severity: Severity::Info,
            partition: Partition::Boot,
            remedy: Remedy::Manual,
            action: None,
            message: format!(
                "a staged watermark-config.json is present (chain {} at level {}); the \
                 device consumes it on the next boot, so it is left in place",
                bc.chain_id, bc.level,
            ),
        }),
    }
}

/// Whether a staged boot config would do nothing if consumed: its chain is the
/// node's, `chain_info.json` is already present and current, and every key
/// already holds a valid floor at or above the config's level (so the device's
/// never-lower guard would raise nothing). Only then is deleting it safe — a
/// config that would still seed a missing floor or repair `chain_info` is kept.
fn boot_config_superseded(state: &CardState, node_id: &str, bc: &BootConfigState) -> bool {
    let chain_info_current =
        matches!(&state.chain_info, ChainInfoState::Present { id, .. } if id == node_id);
    let floors_covered = state.inspection == Inspection::Inspected
        && !state.watermarks.is_empty()
        && state.watermarks.iter().all(|key| {
            !key.files.is_empty()
                && key.files.iter().all(
                    |f| matches!(f.status, WatermarkFileStatus::Valid { level } if level >= bc.level),
                )
        });
    chain_info_current && floors_covered
}

fn classify_keys(state: &CardState, issues: &mut Vec<Issue>) {
    match &state.keys {
        KeysState::Missing => issues.push(Issue {
            kind: IssueKind::KeysMissing,
            severity: Severity::Critical,
            partition: Partition::Keys,
            remedy: Remedy::Manual,
            action: None,
            message: "public_key_hashs is missing; the card has no keys and cannot \
                      sign — restore keys or re-run setup"
                .to_string(),
        }),
        KeysState::Unparseable => issues.push(Issue {
            kind: IssueKind::KeysUnparseable,
            severity: Severity::Critical,
            partition: Partition::Keys,
            remedy: Remedy::Manual,
            action: None,
            message: "public_key_hashs is present but could not be parsed or is empty".to_string(),
        }),
        KeysState::Parsed { aliases, .. } => {
            for role in KEY_ROLES {
                if !aliases.iter().any(|a| a == role) {
                    issues.push(Issue {
                        kind: IssueKind::KeysRoleMissing,
                        severity: Severity::Warning,
                        partition: Partition::Keys,
                        remedy: Remedy::Manual,
                        action: None,
                        message: format!(
                            "expected key role '{role}' was not found among the card's \
                             key aliases"
                        ),
                    });
                }
            }
        }
    }
}

fn classify_chain_info(state: &CardState, node: Option<&ChainInfo>, issues: &mut Vec<Issue>) {
    // A rewrite is only possible, and only makes sense, when a node is present.
    let write_action = node.is_some().then_some(RepairAction::WriteChainInfo);
    match &state.chain_info {
        ChainInfoState::Missing => issues.push(Issue {
            kind: IssueKind::ChainInfoMissing,
            severity: Severity::Critical,
            partition: Partition::Keys,
            remedy: node_backed_remedy(node),
            action: write_action,
            message: "chain_info.json is missing; the device cannot resolve the chain \
                      it signs for until it is rewritten from a node"
                .to_string(),
        }),
        ChainInfoState::Unreadable { owner, mode: _ } if !owner_ok(*owner) => {
            // Wrong owner is why the bytes could not be read; that is the fault
            // to name, not invalid content — the device (uid 1000) simply lacks
            // read access. A host-direct chown makes it readable again.
            let (u, g) = owner.unwrap_or_default();
            issues.push(Issue {
                kind: IssueKind::OwnershipDrift,
                severity: Severity::Critical,
                partition: Partition::Keys,
                remedy: Remedy::HostDirect,
                action: Some(RepairAction::ChownChainInfo),
                message: format!(
                    "chain_info.json is owned {u}:{g}, but the device runs as \
                     {DEVICE_UID}:{DEVICE_GID} and cannot read it"
                ),
            });
        }
        ChainInfoState::Unreadable { .. } => issues.push(Issue {
            kind: IssueKind::ChainInfoUnreadable,
            severity: Severity::Critical,
            partition: Partition::Keys,
            remedy: node_backed_remedy(node),
            action: write_action,
            message: "chain_info.json is present but is not valid JSON or is missing \
                      required fields"
                .to_string(),
        }),
        ChainInfoState::Present { id, mode, owner } => {
            match node {
                Some(n) if &n.id != id => issues.push(Issue {
                    kind: IssueKind::ChainInfoStale,
                    severity: Severity::Warning,
                    partition: Partition::Keys,
                    remedy: Remedy::HostDirect,
                    action: Some(RepairAction::WriteChainInfo),
                    message: format!(
                        "chain_info.json records chain {id}, but the node reports {}; \
                         it is stale and should be rewritten",
                        n.id
                    ),
                }),
                Some(_) => {}
                None => issues.push(Issue {
                    kind: IssueKind::ChainInfoNodeUnknown,
                    severity: Severity::Info,
                    partition: Partition::Keys,
                    remedy: Remedy::NeedsNode,
                    action: None,
                    message: "chain_info.json freshness cannot be checked without a \
                              node endpoint"
                        .to_string(),
                }),
            }
            if !owner_ok(*owner) {
                let (u, g) = owner.unwrap_or_default();
                issues.push(Issue {
                    kind: IssueKind::OwnershipDrift,
                    severity: Severity::Critical,
                    partition: Partition::Keys,
                    remedy: Remedy::HostDirect,
                    action: Some(RepairAction::ChownChainInfo),
                    message: format!(
                        "chain_info.json is owned {u}:{g}, but the device runs as \
                         {DEVICE_UID}:{DEVICE_GID} and cannot read it"
                    ),
                });
            }
            if let Some(m) = mode
                && *m != CHAIN_INFO_MODE
            {
                issues.push(Issue {
                    kind: IssueKind::ChainInfoModeDrift,
                    severity: Severity::Warning,
                    partition: Partition::Keys,
                    remedy: Remedy::HostDirect,
                    action: Some(RepairAction::ChmodChainInfo),
                    message: format!(
                        "chain_info.json mode is {m:04o}, expected {CHAIN_INFO_MODE:04o}"
                    ),
                });
            }
        }
    }
}

/// Whether a staged boot config the device will consume seeds the per-key
/// watermark floors on its next boot, so a wholly absent watermark directory is
/// pending that seed rather than a fault the host must repair now.
///
/// A fresh key has no existing floor, so the device's post-unlock seed path
/// (`rpi-signer` `recover_watermark_config` → `HighWatermark::seed_floor`)
/// unconditionally creates the directory and writes the authenticated floor —
/// but only for the chain the config targets, so a config whose chain differs
/// from the node's (the stale case `classify_boot_config` flags for deletion)
/// does not cover it. With no node the staged config is taken at face value,
/// matching the never-booted path's `boot_config.is_none()` gate above.
fn staged_config_seeds_watermarks(state: &CardState, node: Option<&ChainInfo>) -> bool {
    match (&state.boot_config, node) {
        (Some(bc), Some(n)) => n.id == bc.chain_id,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn classify_watermarks(state: &CardState, node: Option<&ChainInfo>, issues: &mut Vec<Issue>) {
    let seeds_pending = staged_config_seeds_watermarks(state, node);
    let mut any_valid = false;
    for key in &state.watermarks {
        classify_key_watermarks(key, node, seeds_pending, issues, &mut any_valid);
    }
    // Valid floors exist but there is no head to compare them against.
    if any_valid && node.is_none() {
        issues.push(Issue {
            kind: IssueKind::WatermarkNodeUnknown,
            severity: Severity::Info,
            partition: Partition::Data,
            remedy: Remedy::NeedsNode,
            action: None,
            message: "watermark floors cannot be compared to the node head without a \
                      node endpoint"
                .to_string(),
        });
    }
}

fn classify_key_watermarks(
    key: &KeyWatermarks,
    node: Option<&ChainInfo>,
    seeds_pending: bool,
    issues: &mut Vec<Issue>,
    any_valid: &mut bool,
) {
    // The host cannot produce an authenticated mark, so a watermark-content
    // fault is repaired by staging a boot config the PIN-unlocked device applies
    // (never-lower) on its next boot. Without a node there is nothing to stage,
    // so the fault is reported for the device to recover at signing time.
    let remedy = if node.is_some() {
        Remedy::FatStage
    } else {
        Remedy::NeedsNode
    };
    let stage_action = node.map(|n| RepairAction::StageBootConfig(n.clone()));
    if !key.dir_present {
        // A covering staged config already is the remedy: the device creates the
        // directory and seeds the floor on its next boot, so offering to stage
        // another would be redundant and misread as a fault. classify_boot_config
        // surfaces the staged config the operator is waiting on.
        if !seeds_pending {
            issues.push(Issue {
                kind: IssueKind::WatermarkDirMissing,
                severity: Severity::Critical,
                partition: Partition::Data,
                remedy,
                action: stage_action,
                message: format!("the watermark directory for key {} is missing", key.pkh),
            });
        }
        return;
    }

    let mut ownership_bad = !owner_ok(key.dir_owner);
    let mut min_level: Option<u32> = None;
    for file in &key.files {
        if !owner_ok(file.owner) {
            ownership_bad = true;
        }
        match file.status {
            WatermarkFileStatus::Missing => issues.push(Issue {
                kind: IssueKind::WatermarkFileMissing,
                severity: Severity::Critical,
                partition: Partition::Data,
                remedy,
                action: stage_action.clone(),
                message: format!(
                    "watermark file {} for key {} is missing",
                    file.name, key.pkh
                ),
            }),
            WatermarkFileStatus::WrongSize | WatermarkFileStatus::Corrupt => issues.push(Issue {
                kind: IssueKind::WatermarkCorrupt,
                severity: Severity::Critical,
                partition: Partition::Data,
                remedy,
                action: stage_action.clone(),
                message: format!(
                    "watermark file {} for key {} failed to decode",
                    file.name, key.pkh
                ),
            }),
            WatermarkFileStatus::Valid { level } => {
                *any_valid = true;
                min_level = Some(min_level.map_or(level, |m| m.min(level)));
            }
        }
    }

    if let (Some(n), Some(level)) = (node, min_level)
        && floor_significantly_behind(level, n)
    {
        issues.push(Issue {
            kind: IssueKind::WatermarkBelowHead,
            severity: Severity::Warning,
            partition: Partition::Data,
            remedy,
            action: stage_action.clone(),
            message: format!(
                "the watermark floor for key {} is level {level}, more than \
                 {LARGE_GAP_CYCLES} cycles behind the node head {}",
                key.pkh, n.level
            ),
        });
    }

    if ownership_bad {
        issues.push(Issue {
            kind: IssueKind::OwnershipDrift,
            severity: Severity::Critical,
            partition: Partition::Data,
            remedy: Remedy::HostDirect,
            action: Some(RepairAction::ChownWatermarks {
                pkh: key.pkh.clone(),
            }),
            message: format!(
                "watermark files for key {} are not owned {DEVICE_UID}:{DEVICE_GID}; the \
                 device cannot update them",
                key.pkh
            ),
        });
    }
}

fn classify_logs(state: &CardState, issues: &mut Vec<Issue>) {
    if !state.logs_dir_present {
        issues.push(Issue {
            kind: IssueKind::LogsDirMissing,
            severity: Severity::Info,
            partition: Partition::Data,
            remedy: Remedy::Manual,
            action: None,
            message: "/data/logs is missing; the device recreates it on boot".to_string(),
        });
    }
    if let Some(size) = state.panic_log_size
        && size > PANIC_LOG_MAX_BYTES
    {
        issues.push(Issue {
            kind: IssueKind::PanicLogOversized,
            severity: Severity::Warning,
            partition: Partition::Data,
            remedy: Remedy::HostDirect,
            action: Some(RepairAction::TruncatePanicLog),
            message: format!(
                "panic.log is {size} bytes, over the {PANIC_LOG_MAX_BYTES}-byte cap; it \
                 can be truncated"
            ),
        });
    }
}

// =============================================================================
// Repair planning (pure)
// =============================================================================

/// The confirmable repairs implied by a classified issue list.
///
/// Consumes the `action` each issue carries — the executor never re-derives a
/// fix from the card state. Drops actions superseded by a broader one on the
/// same target (a full `chain_info` rewrite already restores its mode and owner;
/// a staged boot config supersedes deleting one) and dedups identical actions
/// (one key's several watermark faults share one staged config).
pub fn plan_repairs(issues: &[Issue]) -> Vec<RepairAction> {
    let actions: Vec<RepairAction> = issues.iter().filter_map(|i| i.action.clone()).collect();

    let rewrites_chain_info = actions.contains(&RepairAction::WriteChainInfo);
    let stages_boot_config = actions
        .iter()
        .any(|a| matches!(a, RepairAction::StageBootConfig(_)));

    let mut planned: Vec<RepairAction> = Vec::new();
    for action in actions {
        let superseded = match &action {
            RepairAction::ChmodChainInfo | RepairAction::ChownChainInfo => rewrites_chain_info,
            RepairAction::DeleteBootConfig => stages_boot_config,
            _ => false,
        };
        if !superseded && !planned.contains(&action) {
            planned.push(action);
        }
    }
    planned
}

// =============================================================================
// State gathering (read-only IO at the edges)
// =============================================================================

/// The keys partition (p3) fields, read behind a read-only mount.
struct KeysPartitionState {
    setup_complete: bool,
    migration_pending: bool,
    keys: KeysState,
    chain_info: ChainInfoState,
}

/// The data partition (p4) fields, read behind a read-only mount.
struct DataPartitionState {
    watermarks: Vec<KeyWatermarks>,
    logs_dir_present: bool,
    panic_log_size: Option<u64>,
}

/// Whether f2fs is registered in the running kernel right now, read from
/// `/proc/filesystems`. Meaningful only *after* a mount attempt: the mount
/// syscall autoloads the module on demand, so f2fs still absent once a mount has
/// failed means the kernel has no f2fs to offer, while its presence means the
/// module loaded and the failure lies with the partition, not the host.
fn f2fs_registered() -> bool {
    std::fs::read_to_string("/proc/filesystems")
        .is_ok_and(|contents| proc_filesystems_has_f2fs(&contents))
}

/// Classify a failed keys-partition mount into [`Inspection::NotCapable`] (the
/// kernel has no f2fs support) or [`Inspection::Failed`] (f2fs is available but
/// this card's partition could not be mounted). The mount attempt has already
/// forced the on-demand autoload, so `f2fs_registered` is an accurate signal by
/// the time this is consulted.
fn inspection_from_failed_mount(f2fs_registered: bool) -> Inspection {
    if f2fs_registered {
        Inspection::Failed
    } else {
        Inspection::NotCapable
    }
}

/// Placeholder state used when the f2fs partitions cannot be read; only
/// `inspection` and `boot_config` are meaningful, and the classifier reads
/// nothing else once `inspection` is not `Inspected`.
fn uninspected_state(inspection: Inspection, boot_config: Option<BootConfigState>) -> CardState {
    CardState {
        inspection,
        setup_complete: false,
        migration_pending: false,
        keys: KeysState::Missing,
        chain_info: ChainInfoState::Missing,
        watermarks: Vec::new(),
        logs_dir_present: false,
        panic_log_size: None,
        boot_config,
    }
}

fn gather_card_state(device: &Path) -> CardState {
    utils::ensure_mount_capability();
    let boot_config = gather_boot_config(device);

    // Attempt the mount instead of pre-checking /proc/filesystems: the mount
    // syscall autoloads f2fs on demand, so a pre-check would false-negative a
    // kernel whose f2fs module is merely unloaded. Only if the attempt fails do
    // we read the now-post-autoload registration to phrase the failure.
    let keys_part = match gather_keys_partition(device) {
        Ok(state) => state,
        Err(e) => {
            warning(&format!("{e:#}"));
            let inspection = inspection_from_failed_mount(f2fs_registered());
            return uninspected_state(inspection, boot_config);
        }
    };

    let pkhs = match &keys_part.keys {
        KeysState::Parsed { pkhs, .. } => pkhs.clone(),
        _ => Vec::new(),
    };

    // p3 mounted, so f2fs is available on this host; a p4 failure is a genuine
    // mount/read fault, never a capability gap.
    let data_part = match gather_data_partition(device, &pkhs) {
        Ok(state) => state,
        Err(e) => {
            warning(&format!("{e:#}"));
            return uninspected_state(Inspection::Failed, boot_config);
        }
    };

    CardState {
        inspection: Inspection::Inspected,
        setup_complete: keys_part.setup_complete,
        migration_pending: keys_part.migration_pending,
        keys: keys_part.keys,
        chain_info: keys_part.chain_info,
        watermarks: data_part.watermarks,
        logs_dir_present: data_part.logs_dir_present,
        panic_log_size: data_part.panic_log_size,
        boot_config,
    }
}

/// Read an un-consumed `watermark-config.json` off the boot partition. Absent or
/// unreadable both resolve to `None` (absent is the healthy case).
fn gather_boot_config(device: &Path) -> Option<BootConfigState> {
    crate::watermark::read_watermark_config(device)
        .ok()
        .map(|wc| BootConfigState {
            chain_id: wc.chain.id,
            level: wc.chain.level,
        })
}

fn gather_keys_partition(device: &Path) -> Result<KeysPartitionState> {
    let p3 = get_partition_path(device, 3);
    let mount =
        utils::mount_partition(&p3, "f2fs", true).context("failed to mount keys partition (p3)")?;
    let state = read_keys_partition(&mount);
    utils::warn_if_err(
        utils::unmount_partition(&mount, &p3),
        "failed to unmount keys partition after diagnosis",
    );
    Ok(state)
}

fn read_keys_partition(mount: &Path) -> KeysPartitionState {
    KeysPartitionState {
        setup_complete: mount.join(".setup_complete").exists(),
        migration_pending: mount.join("secret_keys.enc").exists(),
        keys: read_keys_state(mount),
        chain_info: read_chain_info_state(mount),
    }
}

fn read_keys_state(mount: &Path) -> KeysState {
    if !mount.join("public_key_hashs").exists() {
        return KeysState::Missing;
    }
    // Single parser for the OCaml `{name,value}` key files (invariant: keys are
    // never re-parsed elsewhere).
    let loaded = KeyManager::new(Some(mount.to_path_buf())).load_keys();
    if loaded.is_empty() {
        return KeysState::Unparseable;
    }
    let mut aliases = Vec::with_capacity(loaded.len());
    let mut pkhs = Vec::with_capacity(loaded.len());
    for (alias, key) in loaded {
        aliases.push(alias);
        pkhs.push(key.public_key_hash);
    }
    KeysState::Parsed { aliases, pkhs }
}

fn read_chain_info_state(mount: &Path) -> ChainInfoState {
    let path = mount.join("chain_info.json");
    let Ok(meta) = std::fs::metadata(&path) else {
        return ChainInfoState::Missing;
    };
    let owner = Some((meta.uid(), meta.gid()));
    let mode = Some(meta.mode() & 0o777);

    let parsed = std::fs::read_to_string(&path)
        .ok()
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok());
    let id = parsed
        .as_ref()
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    match id {
        Some(id) => ChainInfoState::Present {
            id: id.to_string(),
            mode,
            owner,
        },
        None => ChainInfoState::Unreadable { owner, mode },
    }
}

fn gather_data_partition(device: &Path, pkhs: &[String]) -> Result<DataPartitionState> {
    let p4 = get_partition_path(device, 4);
    let mount =
        utils::mount_partition(&p4, "f2fs", true).context("failed to mount data partition (p4)")?;
    let state = read_data_partition(&mount, pkhs);
    utils::warn_if_err(
        utils::unmount_partition(&mount, &p4),
        "failed to unmount data partition after diagnosis",
    );
    Ok(state)
}

fn read_data_partition(mount: &Path, pkhs: &[String]) -> DataPartitionState {
    let wm_dir = mount.join("watermarks");
    let watermarks = pkhs
        .iter()
        .map(|pkh| read_key_watermarks(&wm_dir, pkh))
        .collect();
    let logs = mount.join("logs");
    DataPartitionState {
        watermarks,
        logs_dir_present: logs.is_dir(),
        panic_log_size: std::fs::metadata(logs.join("panic.log"))
            .ok()
            .map(|m| m.len()),
    }
}

fn read_key_watermarks(wm_dir: &Path, pkh: &str) -> KeyWatermarks {
    let key_dir = wm_dir.join(pkh);
    let dir_meta = std::fs::metadata(&key_dir);
    let dir_present = dir_meta.as_ref().is_ok_and(std::fs::Metadata::is_dir);
    let dir_owner = dir_meta.ok().map(|m| (m.uid(), m.gid()));
    let files = if dir_present {
        watermark::FILENAMES
            .iter()
            .map(|name| read_watermark_file(&key_dir, name))
            .collect()
    } else {
        Vec::new()
    };
    KeyWatermarks {
        pkh: pkh.to_string(),
        dir_present,
        dir_owner,
        files,
    }
}

/// Classify a watermark file's bytes by its shared 40-byte prefix (level, round,
/// BLAKE3 checksum), which the authenticated 72-byte record and the legacy
/// 40-byte record carry identically. The host holds no MAC key, so it reports
/// the level and corruption only; authenticity is confirmed on the device.
fn decode_watermark_prefix(bytes: &[u8]) -> WatermarkFileStatus {
    if bytes.len() != watermark::FILE_SIZE && bytes.len() != watermark::AUTH_FILE_SIZE {
        return WatermarkFileStatus::WrongSize;
    }
    let prefix: [u8; watermark::FILE_SIZE] = bytes[..watermark::FILE_SIZE]
        .try_into()
        .expect("checked length covers the prefix");
    match watermark::decode(&prefix) {
        Some((level, _)) => WatermarkFileStatus::Valid { level },
        None => WatermarkFileStatus::Corrupt,
    }
}

fn read_watermark_file(key_dir: &Path, name: &str) -> WatermarkFile {
    let path = key_dir.join(name);
    let owner = std::fs::metadata(&path).ok().map(|m| (m.uid(), m.gid()));
    let status = match std::fs::read(&path) {
        Err(_) => WatermarkFileStatus::Missing,
        Ok(bytes) => decode_watermark_prefix(&bytes),
    };
    WatermarkFile {
        name: name.to_string(),
        status,
        owner,
    }
}

// =============================================================================
// Report
// =============================================================================

fn report(issues: &[Issue]) {
    println!();
    print_title_bar("🩺 Russignol Disk Check");

    if is_healthy(issues) {
        success("No issues found — the card is good.");
        return;
    }

    for severity in [Severity::Critical, Severity::Warning, Severity::Info] {
        let group: Vec<&Issue> = issues.iter().filter(|i| i.severity == severity).collect();
        if group.is_empty() {
            continue;
        }
        println!();
        println!("{}", severity_header(severity, group.len()));
        for issue in group {
            println!(
                "  {} {} {}  {}",
                severity_bullet(severity),
                format!("[{}]", partition_label(issue.partition)).dimmed(),
                remedy_tag(issue.remedy),
                issue.message,
            );
        }
    }

    println!();
    let critical = issues
        .iter()
        .filter(|i| i.severity == Severity::Critical)
        .count();
    let warnings = issues
        .iter()
        .filter(|i| i.severity == Severity::Warning)
        .count();
    let fixable = issues
        .iter()
        .filter(|i| remedy_is_fixable(i.remedy))
        .count();
    info(&format!(
        "{critical} critical, {warnings} warning(s); {fixable} fixable."
    ));
}

fn severity_header(severity: Severity, count: usize) -> colored::ColoredString {
    match severity {
        Severity::Critical => format!("Critical ({count})").red().bold(),
        Severity::Warning => format!("Warning ({count})").yellow().bold(),
        Severity::Info => format!("Info ({count})").cyan().bold(),
    }
}

fn severity_bullet(severity: Severity) -> colored::ColoredString {
    match severity {
        Severity::Critical => "✗".red(),
        Severity::Warning => "⚠".yellow(),
        Severity::Info => "•".cyan(),
    }
}

fn partition_label(partition: Partition) -> &'static str {
    match partition {
        Partition::Boot => "boot",
        Partition::Keys => "keys",
        Partition::Data => "data",
    }
}

fn remedy_tag(remedy: Remedy) -> colored::ColoredString {
    match remedy {
        Remedy::HostDirect | Remedy::FatStage => "fix".green(),
        Remedy::NeedsNode => "needs-node".yellow(),
        Remedy::Manual => "manual".dimmed(),
    }
}

// =============================================================================
// Repair execution (IO at the edges; exercised on-device, not in CI)
// =============================================================================

/// The partition a repair touches, so the executor mounts each one once.
fn action_partition(action: &RepairAction) -> Partition {
    match action {
        RepairAction::ChownWatermarks { .. } | RepairAction::TruncatePanicLog => Partition::Data,
        RepairAction::WriteChainInfo
        | RepairAction::ChmodChainInfo
        | RepairAction::ChownChainInfo => Partition::Keys,
        RepairAction::DeleteBootConfig | RepairAction::StageBootConfig(_) => Partition::Boot,
    }
}

/// One-line human description of a repair, for the confirmation prompt.
fn describe_action(action: &RepairAction) -> String {
    match action {
        RepairAction::ChownWatermarks { pkh } => {
            format!("restore {DEVICE_UID}:{DEVICE_GID} ownership of the watermarks for {pkh}")
        }
        RepairAction::WriteChainInfo => "rewrite chain_info.json from the node".to_string(),
        RepairAction::ChmodChainInfo => {
            format!("set chain_info.json mode to {CHAIN_INFO_MODE:04o}")
        }
        RepairAction::ChownChainInfo => {
            format!("restore {DEVICE_UID}:{DEVICE_GID} ownership of chain_info.json")
        }
        RepairAction::TruncatePanicLog => "truncate the oversized panic.log".to_string(),
        RepairAction::DeleteBootConfig => {
            "delete the stale watermark-config.json from the boot partition".to_string()
        }
        RepairAction::StageBootConfig(chain_info) => format!(
            "stage a watermark-config.json so the device configures watermarks and \
             chain_info at level {} on its next boot",
            chain_info.level
        ),
    }
}

/// Prompt for each planned repair unless `--yes` auto-confirms them all.
fn confirm_actions(actions: &[RepairAction], yes: bool) -> Result<Vec<RepairAction>> {
    if yes {
        return Ok(actions.to_vec());
    }
    let mut confirmed = Vec::new();
    for action in actions {
        let ok = inquire::Confirm::new(&format!("Apply repair: {}?", describe_action(action)))
            .with_default(false)
            .with_render_config(utils::create_orange_theme())
            .prompt()
            .context("failed to read repair confirmation")?;
        if ok {
            confirmed.push(action.clone());
        }
    }
    Ok(confirmed)
}

fn owned_by_device(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.uid() == DEVICE_UID && m.gid() == DEVICE_GID)
}

/// Whether a directory and all its immediate entries are device-owned. Watermark
/// key directories are flat, so one level is enough.
fn tree_owned_by_device(dir: &Path) -> bool {
    owned_by_device(dir)
        && std::fs::read_dir(dir).is_ok_and(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .all(|e| owned_by_device(&e.path()))
        })
}

/// Chown a path to `1000:1000` via sudo, skipping when it is already correct so
/// the common (host uid 1000) case needs no privilege prompt.
fn ensure_device_owned(path: &Path, recursive: bool) -> Result<()> {
    let already = if recursive {
        tree_owned_by_device(path)
    } else {
        owned_by_device(path)
    };
    if already {
        return Ok(());
    }
    let spec = format!("{DEVICE_UID}:{DEVICE_GID}");
    let path_str = path.to_string_lossy();
    let args: Vec<&str> = if recursive {
        vec!["-R", &spec, &path_str]
    } else {
        vec![&spec, &path_str]
    };
    let output = utils::sudo_command("chown", &args).context("failed to run chown")?;
    if !output.status.success() {
        bail!(
            "chown of {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Apply every confirmed repair, mounting each partition read-write once.
fn execute_repairs(
    device: &Path,
    node: Option<&ChainInfo>,
    actions: &[RepairAction],
) -> Result<()> {
    utils::ensure_mount_capability();

    // Staging writes the boot partition through a self-mounting helper, so it
    // runs outside the per-partition mount loop below.
    for action in actions {
        if let RepairAction::StageBootConfig(chain_info) = action {
            stage_boot_config(device, chain_info)?;
        }
    }

    for (partition, part_num, fs_type) in [
        (Partition::Keys, 3u8, "f2fs"),
        (Partition::Data, 4u8, "f2fs"),
        (Partition::Boot, 1u8, "vfat"),
    ] {
        let group: Vec<&RepairAction> = actions
            .iter()
            .filter(|a| !matches!(a, RepairAction::StageBootConfig(_)))
            .filter(|a| action_partition(a) == partition)
            .collect();
        if group.is_empty() {
            continue;
        }
        apply_on_partition(device, part_num, fs_type, |mount| {
            for action in &group {
                apply_action(mount, node, action)?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// Stage a `watermark-config.json` on the boot partition and verify the write.
/// The device consumes it on its next boot, configuring watermarks and
/// `chain_info` without lowering a valid floor.
fn stage_boot_config(device: &Path, chain_info: &ChainInfo) -> Result<()> {
    crate::watermark::write_watermark_config(device, chain_info)
        .context("failed to stage watermark-config.json on the boot partition")?;
    let written = crate::watermark::read_back_and_verify(device)
        .context("failed to verify the staged watermark-config.json")?;
    success(&format!(
        "Staged watermark-config.json (chain {}, level {}); the device applies it on its next boot",
        written.chain.id, written.chain.level
    ));
    Ok(())
}

/// Mount a partition read-write, run `apply`, then always sync and unmount.
fn apply_on_partition(
    device: &Path,
    part_num: u8,
    fs_type: &str,
    apply: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let part = get_partition_path(device, part_num);
    let mount = utils::mount_partition(&part, fs_type, false)
        .with_context(|| format!("failed to mount partition {part_num} read-write for repair"))?;
    let result = apply(&mount);
    utils::run_best_effort("sync", &[], "Failed to sync after repair");
    utils::warn_if_err(
        utils::unmount_partition(&mount, &part),
        "failed to unmount partition after repair",
    );
    result
}

fn apply_action(mount: &Path, node: Option<&ChainInfo>, action: &RepairAction) -> Result<()> {
    match action {
        RepairAction::ChownWatermarks { pkh } => {
            let key_dir = mount.join("watermarks").join(pkh);
            ensure_device_owned(&key_dir, true)?;
            success(&format!("Restored ownership of watermarks for {pkh}"));
        }
        RepairAction::WriteChainInfo => {
            let node = node.context("chain_info repair requires a node endpoint")?;
            card_fs::write_chain_info(mount, node)?;
            ensure_device_owned(&mount.join(card_fs::CHAIN_INFO_FILENAME), false)?;
            success("Rewrote chain_info.json from the node");
        }
        RepairAction::ChmodChainInfo => {
            card_fs::set_chain_info_mode(&mount.join(card_fs::CHAIN_INFO_FILENAME))?;
            success("Reset chain_info.json mode");
        }
        RepairAction::ChownChainInfo => {
            ensure_device_owned(&mount.join(card_fs::CHAIN_INFO_FILENAME), false)?;
            success("Restored ownership of chain_info.json");
        }
        RepairAction::TruncatePanicLog => {
            let log = mount.join("logs").join("panic.log");
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&log)
                .with_context(|| format!("failed to truncate {}", log.display()))?;
            success("Truncated panic.log");
        }
        RepairAction::DeleteBootConfig => {
            let cfg = mount.join(crate::watermark::CONFIG_FILENAME);
            std::fs::remove_file(&cfg)
                .with_context(|| format!("failed to delete {}", cfg.display()))?;
            success("Deleted the stale watermark-config.json");
        }
        // Staging self-mounts the boot partition, so `execute_repairs` applies it
        // outside the mount loop and it never reaches here.
        RepairAction::StageBootConfig(_) => {
            bail!("StageBootConfig must be applied at the device level, not on a mount")
        }
    }
    Ok(())
}

// =============================================================================
// Node selection (the card's own chain is authoritative)
// =============================================================================

/// The chain the card is for, taken from the card itself. `chain_info.json` is
/// the network the device commits to signing; the staged boot config's chain is
/// the fallback when the keys partition can't be read (no f2fs / no privilege),
/// which is exactly when a Mainnet card would otherwise be diagnosed against
/// whatever testnet the host's saved endpoint points at.
fn card_target_chain_id(state: &CardState) -> Option<&str> {
    match &state.chain_info {
        ChainInfoState::Present { id, .. } => Some(id.as_str()),
        _ => state.boot_config.as_ref().map(|bc| bc.chain_id.as_str()),
    }
}

/// What to do with the endpoint currently configured, given the chain the card
/// is for. A card doctor's node is only a reference for the card's own chain, so
/// a node on a different chain must never stand in for it.
#[derive(Debug, PartialEq, Eq)]
enum NodePlan {
    /// The endpoint is on the card's chain (or the card names none); use it.
    Accept,
    /// Switch to this endpoint (the Mainnet public RPC) and re-check.
    Switch(&'static str),
    /// Ask the operator to point at the card's network.
    Prompt,
    /// No node on the card's chain is available; node-based checks stay unknown.
    GiveUp,
}

/// Decide how to reconcile the configured endpoint with the card's chain.
///
/// `current` is the chain id the configured endpoint reported, or `None` when it
/// was unreachable. An explicit `--endpoint` is honored as the operator's
/// choice: it is used when it matches and dropped (not auto-replaced) when it
/// does not.
fn plan_node(
    current: Option<&str>,
    card_chain_id: Option<&str>,
    explicit_endpoint: bool,
    non_interactive: bool,
) -> NodePlan {
    // Nothing on the card to match against: whatever answered is all we can use.
    let Some(cid) = card_chain_id else {
        return NodePlan::Accept;
    };
    if current == Some(cid) {
        return NodePlan::Accept;
    }
    if explicit_endpoint {
        return NodePlan::GiveUp;
    }
    if cid == network::MAINNET_CHAIN_ID {
        return NodePlan::Switch(network::MAINNET_RPC_URL);
    }
    if non_interactive {
        return NodePlan::GiveUp;
    }
    NodePlan::Prompt
}

/// Keep a node only when it is on the card's chain; a mismatch after a switch or
/// an operator's pick is dropped so it cannot misjudge the card.
fn accept_if_on_chain(node: Option<ChainInfo>, card_chain_id: Option<&str>) -> Option<ChainInfo> {
    match (node, card_chain_id) {
        (Some(info), Some(cid)) if info.id != cid => {
            warning(&format!(
                "The node is on chain {} but the card is for {cid}; node-based checks report as unknown.",
                info.id
            ));
            None
        }
        (node, _) => node,
    }
}

/// Fetch the node snapshot from the configured endpoint, surfacing
/// unreachability the way the rest of the check does: a warning, then
/// node-based checks report as unknown.
fn fetch_node(config: &config::RussignolConfig) -> Option<ChainInfo> {
    match crate::watermark::prefetch_chain_info(config) {
        Ok(info) => Some(info),
        Err(e) => {
            warning(&format!(
                "Node unavailable ({e:#}); node-based checks report as unknown"
            ));
            None
        }
    }
}

/// Resolve the node the card is diagnosed against, preferring the card's own
/// chain over the host's saved endpoint. Returns `None` (node-based checks
/// report as unknown) when no node on the card's chain can be reached.
fn resolve_node_for_card(
    config: &mut config::RussignolConfig,
    explicit_endpoint: bool,
    card_chain_id: Option<&str>,
    non_interactive: bool,
) -> Option<ChainInfo> {
    let node = fetch_node(config);
    match plan_node(
        node.as_ref().map(|n| n.id.as_str()),
        card_chain_id,
        explicit_endpoint,
        non_interactive,
    ) {
        NodePlan::Accept => node,
        NodePlan::GiveUp => {
            warning(
                "No node on the card's chain is available; node-based checks report as unknown.\n  \
                 Pass --endpoint <url> for the card's network to enable them.",
            );
            None
        }
        NodePlan::Switch(url) => {
            info(
                "The saved node is on a different chain than the card; switching to the Mainnet public RPC.",
            );
            config.rpc_endpoint = url.to_string();
            accept_if_on_chain(fetch_node(config), card_chain_id)
        }
        NodePlan::Prompt => {
            warning(
                "The saved node is on a different chain than the card; choose the card's network.",
            );
            let _ = network::select_endpoint_interactively(config, false);
            accept_if_on_chain(fetch_node(config), card_chain_id)
        }
    }
}

// =============================================================================
// Command entry point
// =============================================================================

/// Diagnose a signer SD card and, unless `dry_run`, repair fixable issues on
/// confirmation (all at once when `yes`).
pub fn run_disk_check(
    device: Option<PathBuf>,
    endpoint: Option<&str>,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let mut config = config::RussignolConfig::load()?;
    config.with_overrides(endpoint, None);

    // The card names the chain it is for, so read it before choosing a node: the
    // node is only a valid reference for the card's own chain, and diagnosis is
    // offline, so the card state does not depend on the node.
    let device = crate::watermark::detect_and_verify_device(device)?;
    let state = gather_card_state(&device);
    let node = resolve_node_for_card(
        &mut config,
        endpoint.is_some(),
        card_target_chain_id(&state),
        yes || dry_run,
    );

    let issues = classify(&state, node.as_ref());
    report(&issues);

    // A healthy card already reported "the card is good"; the repair machinery
    // below (and its "no repairs available" note) is only meaningful when there
    // was a fault to act on.
    if is_healthy(&issues) {
        return Ok(());
    }

    let actions = plan_repairs(&issues);
    if actions.is_empty() {
        info("No repairs are available for this card.");
        return Ok(());
    }
    if dry_run {
        info("Re-run without --dry-run to apply.");
        return Ok(());
    }

    println!();
    let confirmed = confirm_actions(&actions, yes)?;
    if confirmed.is_empty() {
        info("No repairs applied — the card is unchanged.");
        return Ok(());
    }
    execute_repairs(&device, node.as_ref(), &confirmed)?;
    success(&format!("Applied {} repair(s).", confirmed.len()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- f2fs capability predicate ------------------------------------------

    #[test]
    fn f2fs_detected_when_listed() {
        let contents = "nodev\tsysfs\nnodev\ttmpfs\n\text4\n\tf2fs\n\tvfat\n";
        assert!(proc_filesystems_has_f2fs(contents));
    }

    #[test]
    fn f2fs_absent_when_not_listed() {
        let contents = "nodev\tsysfs\nnodev\ttmpfs\n\text4\n\tvfat\n";
        assert!(!proc_filesystems_has_f2fs(contents));
    }

    #[test]
    fn f2fs_ignores_nodev_substring_match() {
        // A pseudo-fs whose name merely contains "f2fs" must not count, and a
        // real f2fs line must be matched on the whole field, not a substring.
        let contents = "nodev\txf2fsy\n\text4\n";
        assert!(!proc_filesystems_has_f2fs(contents));
    }

    #[test]
    fn failed_mount_with_f2fs_registered_is_a_mount_failure() {
        // f2fs registered after the attempt means its module loaded, so the
        // mount failed on the partition itself — not host capability.
        assert_eq!(inspection_from_failed_mount(true), Inspection::Failed);
    }

    #[test]
    fn failed_mount_without_f2fs_is_not_capable() {
        // The mount attempt autoloads f2fs on demand; still unregistered
        // afterward means the kernel has no f2fs module to offer.
        assert_eq!(inspection_from_failed_mount(false), Inspection::NotCapable);
    }

    // -- remedy display -----------------------------------------------------

    #[test]
    fn only_repairable_remedies_count_as_fixable() {
        // Both host-direct and staged repairs read as a single "fix" to the
        // user; needs-node and manual are not something the tool can apply.
        assert!(remedy_is_fixable(Remedy::HostDirect));
        assert!(remedy_is_fixable(Remedy::FatStage));
        assert!(!remedy_is_fixable(Remedy::NeedsNode));
        assert!(!remedy_is_fixable(Remedy::Manual));
    }

    // -- classifier ---------------------------------------------------------

    const CONSENSUS_PKH: &str = "tz4consensus";
    const COMPANION_PKH: &str = "tz4companion";

    fn node() -> ChainInfo {
        ChainInfo {
            id: "NetXmainnet".to_string(),
            level: 1_000,
            name: "Mainnet".to_string(),
            blocks_per_cycle: 24576,
        }
    }

    fn healthy_key(pkh: &str, level: u32) -> KeyWatermarks {
        KeyWatermarks {
            pkh: pkh.to_string(),
            dir_present: true,
            dir_owner: Some((DEVICE_UID, DEVICE_GID)),
            files: watermark::FILENAMES
                .iter()
                .map(|name| WatermarkFile {
                    name: (*name).to_string(),
                    status: WatermarkFileStatus::Valid { level },
                    owner: Some((DEVICE_UID, DEVICE_GID)),
                })
                .collect(),
        }
    }

    fn healthy_state() -> CardState {
        CardState {
            inspection: Inspection::Inspected,
            setup_complete: true,
            migration_pending: false,
            keys: KeysState::Parsed {
                aliases: vec!["consensus".to_string(), "companion".to_string()],
                pkhs: vec![CONSENSUS_PKH.to_string(), COMPANION_PKH.to_string()],
            },
            chain_info: ChainInfoState::Present {
                id: "NetXmainnet".to_string(),
                mode: Some(CHAIN_INFO_MODE),
                owner: Some((DEVICE_UID, DEVICE_GID)),
            },
            watermarks: vec![
                healthy_key(CONSENSUS_PKH, 1_000),
                healthy_key(COMPANION_PKH, 1_000),
            ],
            logs_dir_present: true,
            panic_log_size: Some(1024),
            boot_config: None,
        }
    }

    fn kinds(issues: &[Issue]) -> Vec<IssueKind> {
        issues.iter().map(|i| i.kind).collect()
    }

    fn find(issues: &[Issue], kind: IssueKind) -> Option<&Issue> {
        issues.iter().find(|i| i.kind == kind)
    }

    #[test]
    fn healthy_card_with_node_is_clean() {
        let issues = classify(&healthy_state(), Some(&node()));
        assert!(issues.is_empty(), "expected no issues, got {issues:?}");
    }

    #[test]
    fn healthy_card_without_node_only_downgrades() {
        // With no node the floor-vs-head and chain-id checks cannot run; they
        // downgrade to "unknown" info, but nothing else fires.
        let issues = classify(&healthy_state(), None);
        let ks = kinds(&issues);
        assert!(ks.contains(&IssueKind::WatermarkNodeUnknown));
        assert!(ks.contains(&IssueKind::ChainInfoNodeUnknown));
        assert!(issues.iter().all(|i| i.severity == Severity::Info));
        assert!(issues.iter().all(|i| i.remedy == Remedy::NeedsNode));
    }

    #[test]
    fn missing_watermark_dir_is_critical_and_fat_stage_with_node() {
        let mut state = healthy_state();
        state.watermarks[0].dir_present = false;
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::WatermarkDirMissing).expect("dir-missing issue");
        assert_eq!(issue.severity, Severity::Critical);
        assert_eq!(issue.partition, Partition::Data);
        assert_eq!(issue.remedy, Remedy::FatStage);
        assert_eq!(issue.action, Some(RepairAction::StageBootConfig(node())));
    }

    #[test]
    fn missing_watermark_dir_without_node_needs_node() {
        let mut state = healthy_state();
        state.watermarks[0].dir_present = false;
        let issues = classify(&state, None);
        let issue = find(&issues, IssueKind::WatermarkDirMissing).expect("dir-missing issue");
        assert_eq!(issue.remedy, Remedy::NeedsNode);
    }

    #[test]
    fn missing_watermark_dir_is_pending_when_staged_config_covers_it() {
        // A freshly restored, not-yet-unlocked card: keys, chain_info, and
        // .setup_complete are written and a watermark-config.json is staged, but
        // the device only seeds the authenticated floors after the first PIN
        // unlock. The empty watermark tree is pending that seed, not a fault the
        // host must repair, so it must not read as critical.
        let n = node();
        let mut state = healthy_state();
        for key in &mut state.watermarks {
            key.dir_present = false;
            key.dir_owner = None;
            key.files.clear();
        }
        state.boot_config = Some(BootConfigState {
            chain_id: n.id.clone(),
            level: n.level,
        });
        let issues = classify(&state, Some(&n));
        assert!(
            find(&issues, IssueKind::WatermarkDirMissing).is_none(),
            "a covering staged config makes a missing watermark dir pending: {issues:?}"
        );
        assert!(
            !issues.iter().any(|i| i.severity == Severity::Critical),
            "a restored card awaiting its first unlock has no critical faults: {issues:?}"
        );
        // The staged config is still surfaced as the pending remedy.
        assert!(find(&issues, IssueKind::LeftoverBootConfig).is_some());
        // A config is already staged, so no repair is offered to stage another.
        assert!(
            plan_repairs(&issues).is_empty(),
            "the staged config is the remedy; no repair should be planned: {issues:?}"
        );
    }

    #[test]
    fn missing_watermark_dir_is_pending_under_staged_config_without_a_node() {
        // The same restored card diagnosed with no reachable node: the staged
        // config is taken at face value, so the empty tree stays pending.
        let mut state = healthy_state();
        for key in &mut state.watermarks {
            key.dir_present = false;
            key.dir_owner = None;
            key.files.clear();
        }
        state.boot_config = Some(BootConfigState {
            chain_id: "NetXmainnet".to_string(),
            level: 1_000,
        });
        let issues = classify(&state, None);
        assert!(find(&issues, IssueKind::WatermarkDirMissing).is_none());
        assert!(!issues.iter().any(|i| i.severity == Severity::Critical));
    }

    #[test]
    fn missing_watermark_dir_stays_critical_when_staged_config_is_stale() {
        // A staged config for a different chain will not seed this card's floors,
        // so a missing directory is still a genuine fault.
        let mut state = healthy_state();
        state.watermarks[0].dir_present = false;
        state.watermarks[0].files.clear();
        state.boot_config = Some(BootConfigState {
            chain_id: "NetXold".to_string(),
            level: 1,
        });
        let issues = classify(&state, Some(&node()));
        assert_eq!(
            find(&issues, IssueKind::WatermarkDirMissing)
                .expect("dir-missing issue")
                .severity,
            Severity::Critical
        );
    }

    #[test]
    fn missing_watermark_file_is_critical() {
        let mut state = healthy_state();
        state.watermarks[0].files[0].status = WatermarkFileStatus::Missing;
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::WatermarkFileMissing).expect("file-missing issue");
        assert_eq!(issue.severity, Severity::Critical);
    }

    #[test]
    fn corrupt_watermark_is_critical() {
        let mut state = healthy_state();
        state.watermarks[1].files[2].status = WatermarkFileStatus::Corrupt;
        let issues = classify(&state, Some(&node()));
        assert_eq!(
            find(&issues, IssueKind::WatermarkCorrupt)
                .expect("corrupt issue")
                .severity,
            Severity::Critical
        );
    }

    #[test]
    fn wrong_size_watermark_is_corrupt() {
        let mut state = healthy_state();
        state.watermarks[0].files[1].status = WatermarkFileStatus::WrongSize;
        let issues = classify(&state, Some(&node()));
        assert!(find(&issues, IssueKind::WatermarkCorrupt).is_some());
    }

    #[test]
    fn below_head_floor_is_warning() {
        let mut n = node();
        n.level = 1_000_000; // more than 4 cycles above the card's 1_000 floor
        let issues = classify(&healthy_state(), Some(&n));
        let issue = find(&issues, IssueKind::WatermarkBelowHead).expect("below-head issue");
        assert_eq!(issue.severity, Severity::Warning);
        assert_eq!(issue.remedy, Remedy::FatStage);
    }

    #[test]
    fn floor_within_tolerance_is_not_flagged() {
        // A floor merely behind the head is the normal state of any offline card
        // on a live chain; only a gap beyond the device's own tolerance is flagged.
        let mut n = node();
        n.level = 50_000; // above the 1_000 floor but within 4 cycles (4 * 24576)
        let issues = classify(&healthy_state(), Some(&n));
        assert!(find(&issues, IssueKind::WatermarkBelowHead).is_none());
    }

    #[test]
    fn floor_above_head_is_never_flagged() {
        let mut n = node();
        n.level = 500; // head below the card's 1_000 floor: must not lower it
        let issues = classify(&healthy_state(), Some(&n));
        assert!(find(&issues, IssueKind::WatermarkBelowHead).is_none());
    }

    #[test]
    fn chain_info_missing_is_critical() {
        let mut state = healthy_state();
        state.chain_info = ChainInfoState::Missing;
        let issues = classify(&state, Some(&node()));
        assert_eq!(
            find(&issues, IssueKind::ChainInfoMissing)
                .expect("chain-info-missing issue")
                .severity,
            Severity::Critical
        );
    }

    #[test]
    fn chain_info_unreadable_is_critical() {
        // Owned correctly but the content is invalid: a genuine content fault.
        let mut state = healthy_state();
        state.chain_info = ChainInfoState::Unreadable {
            owner: Some((DEVICE_UID, DEVICE_GID)),
            mode: Some(CHAIN_INFO_MODE),
        };
        let issues = classify(&state, Some(&node()));
        assert!(find(&issues, IssueKind::ChainInfoUnreadable).is_some());
        assert!(find(&issues, IssueKind::OwnershipDrift).is_none());
    }

    #[test]
    fn chain_info_unreadable_by_ownership_is_reported_as_ownership_drift() {
        // Root-owned so the unprivileged device (uid 1000) cannot read it; the
        // fault is ownership, not invalid content.
        let mut state = healthy_state();
        state.chain_info = ChainInfoState::Unreadable {
            owner: Some((0, 0)),
            mode: Some(CHAIN_INFO_MODE),
        };
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::OwnershipDrift).expect("ownership-drift issue");
        assert_eq!(issue.action, Some(RepairAction::ChownChainInfo));
        assert!(find(&issues, IssueKind::ChainInfoUnreadable).is_none());
    }

    #[test]
    fn chain_info_stale_is_warning() {
        let mut state = healthy_state();
        state.chain_info = ChainInfoState::Present {
            id: "NetXwrong".to_string(),
            mode: Some(CHAIN_INFO_MODE),
            owner: Some((DEVICE_UID, DEVICE_GID)),
        };
        let issues = classify(&state, Some(&node()));
        assert_eq!(
            find(&issues, IssueKind::ChainInfoStale)
                .expect("stale issue")
                .severity,
            Severity::Warning
        );
    }

    #[test]
    fn chain_info_mode_drift_flagged() {
        let mut state = healthy_state();
        state.chain_info = ChainInfoState::Present {
            id: "NetXmainnet".to_string(),
            mode: Some(0o644),
            owner: Some((DEVICE_UID, DEVICE_GID)),
        };
        let issues = classify(&state, Some(&node()));
        assert!(find(&issues, IssueKind::ChainInfoModeDrift).is_some());
    }

    #[test]
    fn chain_info_owner_drift_is_critical() {
        let mut state = healthy_state();
        state.chain_info = ChainInfoState::Present {
            id: "NetXmainnet".to_string(),
            mode: Some(CHAIN_INFO_MODE),
            owner: Some((0, 0)),
        };
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::OwnershipDrift).expect("ownership issue");
        assert_eq!(issue.severity, Severity::Critical);
        assert_eq!(issue.partition, Partition::Keys);
    }

    #[test]
    fn setup_incomplete_skips_content_checks() {
        let mut state = healthy_state();
        state.setup_complete = false;
        state.keys = KeysState::Missing;
        state.chain_info = ChainInfoState::Missing;
        state.watermarks.clear();
        let issues = classify(&state, Some(&node()));
        let ks = kinds(&issues);
        assert!(ks.contains(&IssueKind::SetupIncomplete));
        // Pre-setup absence of keys/watermarks/chain_info is expected, not a fault.
        assert!(!ks.contains(&IssueKind::KeysMissing));
        assert!(!ks.contains(&IssueKind::ChainInfoMissing));
        assert!(!ks.contains(&IssueKind::WatermarkDirMissing));
    }

    fn uninitialized_state() -> CardState {
        let mut state = healthy_state();
        state.setup_complete = false;
        state.keys = KeysState::Missing;
        state.chain_info = ChainInfoState::Missing;
        state.watermarks.clear();
        state.boot_config = None;
        state
    }

    #[test]
    fn uninitialized_card_without_seed_offers_stage_with_node() {
        // A manually flashed / never-booted card with no staged seed is offered
        // the boot config that seeds the device's authenticated watermark floor.
        let issues = classify(&uninitialized_state(), Some(&node()));
        let issue = find(&issues, IssueKind::WatermarkSeedMissing).expect("seed-missing issue");
        assert_eq!(issue.severity, Severity::Warning);
        assert_eq!(issue.partition, Partition::Boot);
        assert_eq!(issue.remedy, Remedy::FatStage);
        assert_eq!(issue.action, Some(RepairAction::StageBootConfig(node())));
    }

    #[test]
    fn uninitialized_card_without_seed_needs_node() {
        // Without a node there is nothing to stage; the missing seed is reported
        // so the operator knows to supply an endpoint.
        let issues = classify(&uninitialized_state(), None);
        let issue = find(&issues, IssueKind::WatermarkSeedMissing).expect("seed-missing issue");
        assert_eq!(issue.remedy, Remedy::NeedsNode);
        assert_eq!(issue.action, None);
    }

    #[test]
    fn uninitialized_card_with_seed_staged_is_not_flagged_missing() {
        // A seed already staged is handled by the boot-config classifier; the
        // seed-missing finding must not double-count it.
        let mut state = uninitialized_state();
        state.boot_config = Some(BootConfigState {
            chain_id: "NetXmainnet".to_string(),
            level: 1_000,
        });
        let issues = classify(&state, Some(&node()));
        assert!(find(&issues, IssueKind::WatermarkSeedMissing).is_none());
    }

    #[test]
    fn keys_missing_is_critical() {
        let mut state = healthy_state();
        state.keys = KeysState::Missing;
        let issues = classify(&state, Some(&node()));
        assert_eq!(
            find(&issues, IssueKind::KeysMissing)
                .expect("keys-missing issue")
                .severity,
            Severity::Critical
        );
    }

    #[test]
    fn keys_unparseable_is_critical() {
        let mut state = healthy_state();
        state.keys = KeysState::Unparseable;
        let issues = classify(&state, Some(&node()));
        assert!(find(&issues, IssueKind::KeysUnparseable).is_some());
    }

    #[test]
    fn missing_key_role_reported() {
        let mut state = healthy_state();
        state.keys = KeysState::Parsed {
            aliases: vec!["consensus".to_string()],
            pkhs: vec![CONSENSUS_PKH.to_string()],
        };
        // Only the consensus key's watermarks remain, so drop the companion set.
        state.watermarks.truncate(1);
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::KeysRoleMissing).expect("role-missing issue");
        assert!(issue.message.contains("companion"));
    }

    #[test]
    fn migration_pending_reported() {
        let mut state = healthy_state();
        state.migration_pending = true;
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::MigrationPending).expect("migration issue");
        assert_eq!(issue.severity, Severity::Info);
        assert_eq!(issue.remedy, Remedy::Manual);
    }

    #[test]
    fn f2fs_not_inspected_skips_partition_content() {
        let mut state = healthy_state();
        state.inspection = Inspection::NotCapable;
        state.boot_config = Some(BootConfigState {
            chain_id: "NetXmainnet".to_string(),
            level: 1_000,
        });
        let issues = classify(&state, Some(&node()));
        let ks = kinds(&issues);
        assert!(ks.contains(&IssueKind::F2fsNotInspected));
        // No p3/p4 content should be judged.
        assert!(!ks.contains(&IssueKind::ChainInfoMissing));
        assert!(!ks.contains(&IssueKind::WatermarkBelowHead));
        // The boot partition is still inspectable.
        assert!(ks.contains(&IssueKind::LeftoverBootConfig));
    }

    #[test]
    fn f2fs_mount_failure_is_distinct_from_incapable() {
        let mut state = healthy_state();
        state.inspection = Inspection::Failed;
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::F2fsNotInspected).expect("not-inspected issue");
        // The mount-failure wording differs from the kernel-incapable wording so
        // the operator knows which to act on.
        assert!(issue.message.contains("could not be mounted"));
        assert!(!issue.message.contains("kernel"));
    }

    #[test]
    fn leftover_boot_config_stale_when_chain_differs() {
        let mut state = healthy_state();
        state.boot_config = Some(BootConfigState {
            chain_id: "NetXold".to_string(),
            level: 900,
        });
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::LeftoverBootConfig).expect("boot-config issue");
        assert_eq!(issue.severity, Severity::Warning);
        assert_eq!(issue.partition, Partition::Boot);
        assert_eq!(issue.remedy, Remedy::HostDirect);
    }

    #[test]
    fn leftover_boot_config_pending_is_info_only() {
        // A config above the card's floor still has work to do on the next boot
        // (it raises the floor), so it is left in place.
        let mut state = healthy_state();
        state.boot_config = Some(BootConfigState {
            chain_id: "NetXmainnet".to_string(),
            level: 1_001, // above the card's 1_000 floor
        });
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::LeftoverBootConfig).expect("boot-config issue");
        assert_eq!(issue.severity, Severity::Info);
        assert_eq!(issue.remedy, Remedy::Manual);
        assert!(issue.action.is_none());
    }

    #[test]
    fn leftover_boot_config_superseded_is_deletable() {
        // Chain current, chain_info healthy, and every floor already at or above
        // the config level: consuming it would do nothing, so offer to delete it.
        let mut state = healthy_state();
        state.boot_config = Some(BootConfigState {
            chain_id: "NetXmainnet".to_string(),
            level: 1_000, // at the card's 1_000 floor
        });
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::LeftoverBootConfig).expect("boot-config issue");
        assert_eq!(issue.severity, Severity::Warning);
        assert_eq!(issue.remedy, Remedy::HostDirect);
        assert_eq!(issue.action, Some(RepairAction::DeleteBootConfig));
    }

    #[test]
    fn leftover_boot_config_kept_when_chain_info_needs_repair() {
        // Floors cover the config level, but chain_info is missing — the config
        // would still repair chain_info on boot, so it must not be deleted.
        let mut state = healthy_state();
        state.chain_info = ChainInfoState::Missing;
        state.boot_config = Some(BootConfigState {
            chain_id: "NetXmainnet".to_string(),
            level: 1_000,
        });
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::LeftoverBootConfig).expect("boot-config issue");
        assert_eq!(issue.severity, Severity::Info);
        assert!(issue.action.is_none());
    }

    #[test]
    fn oversized_panic_log_flagged() {
        let mut state = healthy_state();
        state.panic_log_size = Some(PANIC_LOG_MAX_BYTES + 1);
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::PanicLogOversized).expect("panic-log issue");
        assert_eq!(issue.remedy, Remedy::HostDirect);
    }

    #[test]
    fn ownership_drift_on_watermark_is_critical() {
        let mut state = healthy_state();
        state.watermarks[0].files[0].owner = Some((0, 0));
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::OwnershipDrift).expect("ownership issue");
        assert_eq!(issue.severity, Severity::Critical);
        assert_eq!(issue.partition, Partition::Data);
    }

    #[test]
    fn decode_prefix_accepts_authenticated_72_byte_record() {
        let buf = watermark::encode_authenticated(&[0u8; 32], b"", 4242, 0);
        assert_eq!(
            decode_watermark_prefix(&buf),
            WatermarkFileStatus::Valid { level: 4242 }
        );
    }

    #[test]
    fn decode_prefix_accepts_legacy_40_byte_record() {
        let buf = watermark::encode(4242, 0);
        assert_eq!(
            decode_watermark_prefix(&buf),
            WatermarkFileStatus::Valid { level: 4242 }
        );
    }

    #[test]
    fn decode_prefix_rejects_an_unexpected_size() {
        assert_eq!(
            decode_watermark_prefix(&[0u8; 8]),
            WatermarkFileStatus::WrongSize
        );
    }

    #[test]
    fn decode_prefix_flags_a_bad_checksum() {
        let mut buf = watermark::encode_authenticated(&[0u8; 32], b"", 4242, 0);
        buf[39] ^= 0xFF; // corrupt the BLAKE3 prefix checksum
        assert_eq!(decode_watermark_prefix(&buf), WatermarkFileStatus::Corrupt);
    }

    // -- repair planning ----------------------------------------------------

    #[test]
    fn corrupt_watermark_stages_a_boot_config() {
        // The host cannot author an authenticated mark, so a content fault is
        // repaired by staging a boot config; the device applies the never-lower
        // floor itself on its next boot.
        let mut state = healthy_state();
        state.watermarks[0].files[0].status = WatermarkFileStatus::Corrupt;
        let plan = plan_repairs(&classify(&state, Some(&node())));
        assert!(plan.contains(&RepairAction::StageBootConfig(node())));
    }

    #[test]
    fn below_head_floor_stages_a_boot_config() {
        let mut n = node();
        n.level = 500_000; // both keys' 1_000 floors are well beyond 4 cycles behind
        let plan = plan_repairs(&classify(&healthy_state(), Some(&n)));
        assert!(plan.contains(&RepairAction::StageBootConfig(n)));
    }

    #[test]
    fn watermark_fault_without_a_node_is_report_only() {
        // No node to source a floor from: the fault is reported with no action;
        // the device re-establishes the floor at signing time.
        let mut state = healthy_state();
        state.watermarks[0].files[0].status = WatermarkFileStatus::Corrupt;
        let issues = classify(&state, None);
        let issue = find(&issues, IssueKind::WatermarkCorrupt).expect("corrupt issue");
        assert_eq!(issue.remedy, Remedy::NeedsNode);
        assert!(issue.action.is_none());
    }

    #[test]
    fn plan_dedups_boot_config_stage_across_faults() {
        // Several watermark faults across keys collapse to a single staged config.
        let mut state = healthy_state();
        state.watermarks[0].files[0].status = WatermarkFileStatus::Missing;
        state.watermarks[0].files[1].status = WatermarkFileStatus::Corrupt;
        state.watermarks[1].files[0].status = WatermarkFileStatus::Corrupt;
        let plan = plan_repairs(&classify(&state, Some(&node())));
        let stages = plan
            .iter()
            .filter(|a| matches!(a, RepairAction::StageBootConfig(_)))
            .count();
        assert_eq!(stages, 1, "expected one staged config, got {plan:?}");
    }

    #[test]
    fn plan_keeps_chown_alongside_a_staged_config() {
        // A content fault stages a boot config; an independent ownership drift on
        // the same key is still repaired in place. The two coexist.
        let mut state = healthy_state();
        state.watermarks[0].files[0].status = WatermarkFileStatus::Corrupt;
        state.watermarks[0].files[1].owner = Some((0, 0));
        let plan = plan_repairs(&classify(&state, Some(&node())));
        assert!(plan.contains(&RepairAction::StageBootConfig(node())));
        assert!(
            plan.iter().any(
                |a| matches!(a, RepairAction::ChownWatermarks { pkh } if pkh == CONSENSUS_PKH)
            ),
            "ownership drift is repaired independently of staging: {plan:?}"
        );
    }

    #[test]
    fn plan_keeps_chown_for_a_key_with_only_ownership_drift() {
        let mut state = healthy_state();
        state.watermarks[0].files[0].status = WatermarkFileStatus::Corrupt; // key0 stages a config
        state.watermarks[1].files[0].owner = Some((0, 0)); // key1 chown only
        let plan = plan_repairs(&classify(&state, Some(&node())));
        assert!(
            plan.iter().any(
                |a| matches!(a, RepairAction::ChownWatermarks { pkh } if pkh == COMPANION_PKH)
            )
        );
    }

    #[test]
    fn plan_write_chain_info_supersedes_mode_and_owner() {
        let mut state = healthy_state();
        state.chain_info = ChainInfoState::Present {
            id: "NetXwrong".to_string(),
            mode: Some(0o644),
            owner: Some((0, 0)),
        };
        let plan = plan_repairs(&classify(&state, Some(&node())));
        assert!(plan.contains(&RepairAction::WriteChainInfo));
        assert!(!plan.contains(&RepairAction::ChmodChainInfo));
        assert!(!plan.contains(&RepairAction::ChownChainInfo));
    }

    #[test]
    fn no_findings_is_healthy() {
        assert!(is_healthy(&[]));
    }

    #[test]
    fn restored_card_awaiting_first_unlock_is_healthy() {
        // The exact post-restore state: a staged config (Info), missing watermark
        // directories the device seeds after the first unlock, and /data/logs it
        // recreates on boot (Info). No fault, nothing to repair — the card is good.
        let n = node();
        let mut state = healthy_state();
        for key in &mut state.watermarks {
            key.dir_present = false;
            key.dir_owner = None;
            key.files.clear();
        }
        state.logs_dir_present = false;
        state.boot_config = Some(BootConfigState {
            chain_id: n.id.clone(),
            level: n.level,
        });
        let issues = classify(&state, Some(&n));
        assert!(
            is_healthy(&issues),
            "info-only findings are not issues: {issues:?}"
        );
    }

    #[test]
    fn a_warning_is_not_healthy() {
        let mut n = node();
        n.level = 1_000_000; // pushes the floor far behind head → below-head warning
        assert!(!is_healthy(&classify(&healthy_state(), Some(&n))));
    }

    #[test]
    fn a_critical_is_not_healthy() {
        let mut state = healthy_state();
        state.keys = KeysState::Missing;
        assert!(!is_healthy(&classify(&state, Some(&node()))));
    }

    #[test]
    fn a_fixable_info_finding_is_not_healthy() {
        // Guards the fixable arm independently of severity: an Info-severity
        // finding that still carries a repair must not read as healthy.
        let issue = Issue {
            kind: IssueKind::FatStageAvailable,
            severity: Severity::Info,
            partition: Partition::Boot,
            remedy: Remedy::FatStage,
            action: Some(RepairAction::StageBootConfig(node())),
            message: String::new(),
        };
        assert!(!is_healthy(std::slice::from_ref(&issue)));
    }

    // -- node selection -----------------------------------------------------

    const TESTNET_CHAIN_ID: &str = "NetXpX8WSZkAZZA";

    #[test]
    fn card_chain_prefers_chain_info_over_boot_config() {
        let mut state = healthy_state();
        state.chain_info = ChainInfoState::Present {
            id: "NetXcommitted".to_string(),
            mode: Some(CHAIN_INFO_MODE),
            owner: Some((DEVICE_UID, DEVICE_GID)),
        };
        state.boot_config = Some(BootConfigState {
            chain_id: "NetXstaged".to_string(),
            level: 1,
        });
        assert_eq!(card_target_chain_id(&state), Some("NetXcommitted"));
    }

    #[test]
    fn card_chain_falls_back_to_boot_config_when_keys_unreadable() {
        let mut state = uninspected_state(
            Inspection::Failed,
            Some(BootConfigState {
                chain_id: network::MAINNET_CHAIN_ID.to_string(),
                level: 1,
            }),
        );
        state.chain_info = ChainInfoState::Missing;
        assert_eq!(
            card_target_chain_id(&state),
            Some(network::MAINNET_CHAIN_ID)
        );
    }

    #[test]
    fn card_chain_is_none_when_the_card_names_none() {
        let state = uninspected_state(Inspection::Failed, None);
        assert_eq!(card_target_chain_id(&state), None);
    }

    #[test]
    fn plan_accepts_a_node_on_the_cards_chain() {
        assert_eq!(
            plan_node(Some(TESTNET_CHAIN_ID), Some(TESTNET_CHAIN_ID), false, false),
            NodePlan::Accept
        );
    }

    #[test]
    fn plan_accepts_any_node_when_the_card_names_no_chain() {
        assert_eq!(
            plan_node(Some(TESTNET_CHAIN_ID), None, false, false),
            NodePlan::Accept
        );
    }

    #[test]
    fn plan_switches_a_mainnet_card_off_a_wrong_node() {
        assert_eq!(
            plan_node(
                Some(TESTNET_CHAIN_ID),
                Some(network::MAINNET_CHAIN_ID),
                false,
                false
            ),
            NodePlan::Switch(network::MAINNET_RPC_URL)
        );
    }

    #[test]
    fn plan_switches_a_mainnet_card_when_the_node_is_unreachable() {
        assert_eq!(
            plan_node(None, Some(network::MAINNET_CHAIN_ID), false, false),
            NodePlan::Switch(network::MAINNET_RPC_URL)
        );
    }

    #[test]
    fn plan_prompts_for_a_testnet_card_on_a_wrong_node_interactively() {
        assert_eq!(
            plan_node(
                Some(network::MAINNET_CHAIN_ID),
                Some(TESTNET_CHAIN_ID),
                false,
                false
            ),
            NodePlan::Prompt
        );
    }

    #[test]
    fn plan_gives_up_for_a_testnet_card_non_interactively() {
        assert_eq!(
            plan_node(
                Some(network::MAINNET_CHAIN_ID),
                Some(TESTNET_CHAIN_ID),
                false,
                true
            ),
            NodePlan::GiveUp
        );
    }

    #[test]
    fn plan_drops_a_mismatched_explicit_endpoint_without_replacing_it() {
        // An explicit --endpoint is honored, so a Mainnet card pointed at a testnet
        // node is dropped (node-based checks go unknown) rather than auto-switched.
        assert_eq!(
            plan_node(
                Some(TESTNET_CHAIN_ID),
                Some(network::MAINNET_CHAIN_ID),
                true,
                false
            ),
            NodePlan::GiveUp
        );
    }

    #[test]
    fn accept_drops_a_node_on_a_different_chain() {
        let mut wrong = node();
        wrong.id = TESTNET_CHAIN_ID.to_string();
        assert!(accept_if_on_chain(Some(wrong), Some(network::MAINNET_CHAIN_ID)).is_none());
    }

    #[test]
    fn accept_keeps_a_node_on_the_cards_chain() {
        assert!(accept_if_on_chain(Some(node()), Some(&node().id)).is_some());
    }

    #[test]
    fn accept_keeps_a_node_when_the_card_names_no_chain() {
        assert!(accept_if_on_chain(Some(node()), None).is_some());
    }

    #[test]
    fn plan_is_empty_for_a_healthy_card() {
        let plan = plan_repairs(&classify(&healthy_state(), Some(&node())));
        assert!(
            plan.is_empty(),
            "healthy card needs no repair, got {plan:?}"
        );
    }

    #[test]
    fn plan_omits_node_backed_repairs_without_a_node() {
        let mut state = healthy_state();
        state.watermarks[0].dir_present = false;
        state.chain_info = ChainInfoState::Missing;
        let plan = plan_repairs(&classify(&state, None));
        assert!(
            plan.is_empty(),
            "node-backed repairs cannot be planned without a node, got {plan:?}"
        );
    }

    #[test]
    fn actionable_issue_carries_an_action_and_others_do_not() {
        let mut inspected = healthy_state();
        inspected.watermarks[0].dir_present = false;
        inspected.watermarks[1].files[0].owner = Some((0, 0));
        inspected.chain_info = ChainInfoState::Present {
            id: "NetXwrong".to_string(),
            mode: Some(0o644),
            owner: Some((0, 0)),
        };
        inspected.panic_log_size = Some(PANIC_LOG_MAX_BYTES + 1);
        inspected.boot_config = Some(BootConfigState {
            chain_id: "NetXold".to_string(),
            level: 1,
        });
        inspected.migration_pending = true;

        // The FAT-stage path is the other action-carrying remedy.
        let not_capable = uninspected_state(Inspection::NotCapable, None);

        let issues: Vec<Issue> = classify(&inspected, Some(&node()))
            .into_iter()
            .chain(classify(&not_capable, Some(&node())))
            .collect();

        for i in &issues {
            let actionable = matches!(i.remedy, Remedy::HostDirect | Remedy::FatStage);
            assert_eq!(
                actionable,
                i.action.is_some(),
                "remedy and action disagree: {i:?}"
            );
        }
    }

    // -- FAT-stage fallback -------------------------------------------------

    #[test]
    fn fat_stage_offered_when_f2fs_not_capable_with_node() {
        let state = uninspected_state(Inspection::NotCapable, None);
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::FatStageAvailable).expect("fat-stage issue");
        assert_eq!(issue.remedy, Remedy::FatStage);
        assert_eq!(
            issue.action,
            Some(RepairAction::StageBootConfig(node())),
            "the staged config carries the node snapshot verbatim"
        );
        assert!(plan_repairs(&issues).contains(&RepairAction::StageBootConfig(node())));
    }

    #[test]
    fn fat_stage_not_offered_without_a_node() {
        let state = uninspected_state(Inspection::NotCapable, None);
        let issues = classify(&state, None);
        assert!(find(&issues, IssueKind::FatStageAvailable).is_none());
        assert!(
            plan_repairs(&issues).is_empty(),
            "no node means nothing to stage"
        );
    }

    #[test]
    fn fat_stage_not_offered_when_f2fs_inspected() {
        let plan = plan_repairs(&classify(&healthy_state(), Some(&node())));
        assert!(
            !plan
                .iter()
                .any(|a| matches!(a, RepairAction::StageBootConfig(_))),
            "an f2fs-capable host repairs in place, not via staging: {plan:?}"
        );
    }

    #[test]
    fn fat_stage_not_offered_when_mount_failed() {
        // A capable host whose mount failed is a card or permission fault to
        // investigate, not a case for a blind staged config.
        let state = uninspected_state(Inspection::Failed, None);
        let issues = classify(&state, Some(&node()));
        assert!(find(&issues, IssueKind::FatStageAvailable).is_none());
    }

    #[test]
    fn plan_stage_supersedes_delete_of_a_stale_boot_config() {
        let state = uninspected_state(
            Inspection::NotCapable,
            Some(BootConfigState {
                chain_id: "NetXold".to_string(),
                level: 1,
            }),
        );
        let plan = plan_repairs(&classify(&state, Some(&node())));
        assert!(
            plan.iter()
                .any(|a| matches!(a, RepairAction::StageBootConfig(_)))
        );
        assert!(
            !plan.contains(&RepairAction::DeleteBootConfig),
            "staging overwrites the same file, so the delete is dropped: {plan:?}"
        );
    }
}
