//! `russignol disk doctor` — diagnose a signer SD card (read-only).
//!
//! Reads a signer's SD card and reports every detectable issue: missing or
//! corrupt watermarks, missing or stale `chain_info.json`, ownership/mode drift,
//! leftover boot config, log health, and setup/keys/migration state. Repair is
//! layered on separately; this module gathers state and classifies it.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use colored::Colorize;
use russignol_signer_lib::KeyManager;
use russignol_signer_lib::server::KEY_ROLES;
use russignol_storage::watermark;

use crate::card_fs::{self, CHAIN_INFO_MODE, DEVICE_GID, DEVICE_UID};
use crate::utils::{self, get_partition_path, info, print_title_bar, success, warning};
use crate::watermark::ChainInfo;
use crate::{config, network};

/// Maximum `panic.log` size before the doctor offers to truncate it, matching
/// the 1 MiB cap the device init applies on boot.
const PANIC_LOG_MAX_BYTES: u64 = 1024 * 1024;

/// Disk subcommands
#[derive(Subcommand, Debug)]
pub enum DiskCommands {
    /// Diagnose a signer SD card and repair fixable issues on confirmation
    Doctor {
        /// Target device (e.g. /dev/sdc or /dev/mmcblk0); auto-detected if omitted
        #[arg(long, short)]
        device: Option<PathBuf>,

        /// Tezos node RPC endpoint (default: <http://localhost:8732>)
        #[arg(long)]
        endpoint: Option<String>,

        /// Report issues without applying any repair
        #[arg(long)]
        dry_run: bool,

        /// Apply all fixable repairs without prompting
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

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
    /// present but invalid JSON or missing required fields.
    Unreadable,
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
    /// A node endpoint is required before this can be resolved or even judged.
    NeedsNode,
    /// The doctor does not change this; the user or device must act.
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    SetupIncomplete,
    KeysMissing,
    KeysUnparseable,
    KeysRoleMissing,
    MigrationPending,
    F2fsNotInspected,
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

/// A concrete, confirmable repair the doctor applies to a card in a host reader.
///
/// Produced alongside the issue that motivates it, so the executor consumes the
/// planned repair rather than re-deriving one from the card state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairAction {
    /// Rewrite the full watermark set for a key at `level`, then restore
    /// `1000:1000` ownership. `level` never lowers an existing valid floor.
    WriteWatermarks { pkh: String, level: u32 },
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub kind: IssueKind,
    pub severity: Severity,
    pub partition: Partition,
    pub remedy: Remedy,
    /// The in-place repair for this issue, present iff `remedy` is `HostDirect`.
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

/// The level to rewrite a key's watermark set at: the node head raised to any
/// existing valid floor the key still has, so a valid higher floor is never
/// lowered (slashing guard). Called only when a node is present.
fn repair_level_for_key(key: &KeyWatermarks, node_level: u32) -> u32 {
    key.files
        .iter()
        .filter_map(|f| match f.status {
            WatermarkFileStatus::Valid { level } => Some(level),
            _ => None,
        })
        .fold(node_level, u32::max)
}

fn owner_ok(owner: Option<(u32, u32)>) -> bool {
    owner.is_none_or(|(u, g)| u == DEVICE_UID && g == DEVICE_GID)
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
             were not inspected; run 'disk doctor' on an f2fs-capable host to \
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
                      completes it on boot and the doctor leaves it untouched"
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
    match node {
        Some(n) if n.id != bc.chain_id => issues.push(Issue {
            kind: IssueKind::LeftoverBootConfig,
            severity: Severity::Warning,
            partition: Partition::Boot,
            remedy: Remedy::HostDirect,
            action: Some(RepairAction::DeleteBootConfig),
            message: format!(
                "a staged watermark-config.json targets chain {} at level {}, which \
                 differs from the node's chain {}; it is stale and can be deleted",
                bc.chain_id, bc.level, n.id,
            ),
        }),
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
        ChainInfoState::Unreadable => issues.push(Issue {
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

fn classify_watermarks(state: &CardState, node: Option<&ChainInfo>, issues: &mut Vec<Issue>) {
    let mut any_valid = false;
    for key in &state.watermarks {
        classify_key_watermarks(key, node, issues, &mut any_valid);
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
    issues: &mut Vec<Issue>,
    any_valid: &mut bool,
) {
    let remedy = node_backed_remedy(node);
    // Every watermark-content fault for this key is repaired by the same
    // rewrite-the-set action, at a level that never lowers a valid floor.
    let write_action = node.map(|n| RepairAction::WriteWatermarks {
        pkh: key.pkh.clone(),
        level: repair_level_for_key(key, n.level),
    });
    if !key.dir_present {
        issues.push(Issue {
            kind: IssueKind::WatermarkDirMissing,
            severity: Severity::Critical,
            partition: Partition::Data,
            remedy,
            action: write_action,
            message: format!("the watermark directory for key {} is missing", key.pkh),
        });
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
                action: write_action.clone(),
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
                action: write_action.clone(),
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
        && level < n.level
    {
        issues.push(Issue {
            kind: IssueKind::WatermarkBelowHead,
            severity: Severity::Warning,
            partition: Partition::Data,
            remedy,
            action: write_action.clone(),
            message: format!(
                "the watermark floor for key {} is level {level}, below the node head {}",
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
/// same target (a full rewrite already restores ownership and mode) and dedups
/// identical actions (one key's several watermark faults share one rewrite).
pub fn plan_repairs(issues: &[Issue]) -> Vec<RepairAction> {
    let actions: Vec<RepairAction> = issues.iter().filter_map(|i| i.action.clone()).collect();

    let rewritten_keys: std::collections::HashSet<String> = actions
        .iter()
        .filter_map(|a| match a {
            RepairAction::WriteWatermarks { pkh, .. } => Some(pkh.clone()),
            _ => None,
        })
        .collect();
    let rewrites_chain_info = actions.contains(&RepairAction::WriteChainInfo);

    let mut planned: Vec<RepairAction> = Vec::new();
    for action in actions {
        let superseded = match &action {
            RepairAction::ChownWatermarks { pkh } => rewritten_keys.contains(pkh),
            RepairAction::ChmodChainInfo | RepairAction::ChownChainInfo => rewrites_chain_info,
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

fn host_f2fs_capable() -> bool {
    std::fs::read_to_string("/proc/filesystems")
        .is_ok_and(|contents| proc_filesystems_has_f2fs(&contents))
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

    if !host_f2fs_capable() {
        return uninspected_state(Inspection::NotCapable, boot_config);
    }

    let keys_part = match gather_keys_partition(device) {
        Ok(state) => state,
        Err(e) => {
            warning(&format!("{e:#}"));
            return uninspected_state(Inspection::Failed, boot_config);
        }
    };

    let pkhs = match &keys_part.keys {
        KeysState::Parsed { pkhs, .. } => pkhs.clone(),
        _ => Vec::new(),
    };

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
        None => ChainInfoState::Unreadable,
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

fn read_watermark_file(key_dir: &Path, name: &str) -> WatermarkFile {
    let path = key_dir.join(name);
    let owner = std::fs::metadata(&path).ok().map(|m| (m.uid(), m.gid()));
    let status = match std::fs::read(&path) {
        Err(_) => WatermarkFileStatus::Missing,
        Ok(bytes) => match <[u8; watermark::FILE_SIZE]>::try_from(bytes.as_slice()) {
            Err(_) => WatermarkFileStatus::WrongSize,
            Ok(buf) => match watermark::decode(&buf) {
                Some((level, _)) => WatermarkFileStatus::Valid { level },
                None => WatermarkFileStatus::Corrupt,
            },
        },
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
    print_title_bar("🩺 Russignol Disk Doctor");

    if issues.is_empty() {
        success("No issues detected — the card looks healthy.");
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
        .filter(|i| i.remedy == Remedy::HostDirect)
        .count();
    info(&format!(
        "{critical} critical, {warnings} warning(s); {fixable} fixable in place."
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
        Remedy::HostDirect => "fixable".green(),
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
        RepairAction::WriteWatermarks { .. }
        | RepairAction::ChownWatermarks { .. }
        | RepairAction::TruncatePanicLog => Partition::Data,
        RepairAction::WriteChainInfo
        | RepairAction::ChmodChainInfo
        | RepairAction::ChownChainInfo => Partition::Keys,
        RepairAction::DeleteBootConfig => Partition::Boot,
    }
}

/// One-line human description of a repair, for the confirmation prompt.
fn describe_action(action: &RepairAction) -> String {
    match action {
        RepairAction::WriteWatermarks { pkh, level } => {
            format!("rewrite the watermark set for {pkh} at level {level}")
        }
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

    for (partition, part_num, fs_type) in [
        (Partition::Keys, 3u8, "f2fs"),
        (Partition::Data, 4u8, "f2fs"),
        (Partition::Boot, 1u8, "vfat"),
    ] {
        let group: Vec<&RepairAction> = actions
            .iter()
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
        RepairAction::WriteWatermarks { pkh, level } => {
            let key_dir = mount.join("watermarks").join(pkh);
            card_fs::write_watermark_file_set(&key_dir, *level)?;
            ensure_device_owned(&key_dir, true)?;
            success(&format!("Rewrote watermarks for {pkh} at level {level}"));
        }
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
    }
    Ok(())
}

// =============================================================================
// Command entry point
// =============================================================================

/// Main entry point for disk commands
pub fn run_disk_command(command: DiskCommands) -> Result<()> {
    match command {
        DiskCommands::Doctor {
            device,
            endpoint,
            dry_run,
            yes,
        } => run_doctor(device, endpoint.as_deref(), dry_run, yes),
    }
}

fn run_doctor(
    device: Option<PathBuf>,
    endpoint: Option<&str>,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Diagnosis runs offline; the node snapshot is best-effort. Node-dependent
    // checks downgrade to "unknown" when it is absent.
    let mut config = config::RussignolConfig::load()?;
    config.with_overrides(endpoint, None);
    if endpoint.is_none() {
        let _ = network::resolve_endpoint_interactively(&mut config, yes || dry_run);
    }
    let node = match crate::watermark::prefetch_chain_info(&config) {
        Ok(chain_info) => Some(chain_info),
        Err(e) => {
            warning(&format!(
                "Node unavailable ({e:#}); floor-vs-head and chain-id checks report as unknown"
            ));
            None
        }
    };

    let device = crate::watermark::detect_and_verify_device(device)?;
    let state = gather_card_state(&device);
    let issues = classify(&state, node.as_ref());
    report(&issues);

    let actions = plan_repairs(&issues);
    if actions.is_empty() {
        info("No in-place repairs are available for this card.");
        return Ok(());
    }
    if dry_run {
        info(&format!(
            "{} repair(s) available; re-run without --dry-run to apply.",
            actions.len()
        ));
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
    fn missing_watermark_dir_is_critical_and_host_direct_with_node() {
        let mut state = healthy_state();
        state.watermarks[0].dir_present = false;
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::WatermarkDirMissing).expect("dir-missing issue");
        assert_eq!(issue.severity, Severity::Critical);
        assert_eq!(issue.partition, Partition::Data);
        assert_eq!(issue.remedy, Remedy::HostDirect);
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
        n.level = 2_000; // head above the card's 1_000 floor
        let issues = classify(&healthy_state(), Some(&n));
        let issue = find(&issues, IssueKind::WatermarkBelowHead).expect("below-head issue");
        assert_eq!(issue.severity, Severity::Warning);
        assert_eq!(issue.remedy, Remedy::HostDirect);
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
        let mut state = healthy_state();
        state.chain_info = ChainInfoState::Unreadable;
        let issues = classify(&state, Some(&node()));
        assert!(find(&issues, IssueKind::ChainInfoUnreadable).is_some());
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
    fn leftover_boot_config_fresh_is_info_only() {
        let mut state = healthy_state();
        state.boot_config = Some(BootConfigState {
            chain_id: "NetXmainnet".to_string(),
            level: 1_000,
        });
        let issues = classify(&state, Some(&node()));
        let issue = find(&issues, IssueKind::LeftoverBootConfig).expect("boot-config issue");
        assert_eq!(issue.severity, Severity::Info);
        assert_eq!(issue.remedy, Remedy::Manual);
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

    // -- repair planning ----------------------------------------------------

    fn wm_file(status: WatermarkFileStatus) -> WatermarkFile {
        WatermarkFile {
            name: "block_watermark".to_string(),
            status,
            owner: Some((DEVICE_UID, DEVICE_GID)),
        }
    }

    #[test]
    fn repair_level_never_lowers_a_valid_floor() {
        let key = KeyWatermarks {
            pkh: CONSENSUS_PKH.to_string(),
            dir_present: true,
            dir_owner: Some((DEVICE_UID, DEVICE_GID)),
            files: vec![
                wm_file(WatermarkFileStatus::Valid { level: 2_000 }),
                wm_file(WatermarkFileStatus::Corrupt),
            ],
        };
        // Node head below the surviving valid floor: keep the floor.
        assert_eq!(repair_level_for_key(&key, 1_000), 2_000);
        // Node head above the floor: raise to the head.
        assert_eq!(repair_level_for_key(&key, 3_000), 3_000);
    }

    #[test]
    fn repair_level_uses_node_head_when_no_valid_floor_survives() {
        let key = KeyWatermarks {
            pkh: CONSENSUS_PKH.to_string(),
            dir_present: true,
            dir_owner: Some((DEVICE_UID, DEVICE_GID)),
            files: vec![wm_file(WatermarkFileStatus::Missing)],
        };
        assert_eq!(repair_level_for_key(&key, 1_234), 1_234);
    }

    #[test]
    fn corrupt_sibling_rewrites_at_the_surviving_higher_floor() {
        // Slashing guard end to end: one file corrupt, its siblings valid at
        // 2_000, node head 1_000 — the rewrite must use 2_000, never the head.
        let mut state = healthy_state();
        for f in &mut state.watermarks[0].files {
            f.status = WatermarkFileStatus::Valid { level: 2_000 };
        }
        state.watermarks[0].files[0].status = WatermarkFileStatus::Corrupt;
        let mut n = node();
        n.level = 1_000;
        let plan = plan_repairs(&classify(&state, Some(&n)));
        assert!(plan.contains(&RepairAction::WriteWatermarks {
            pkh: CONSENSUS_PKH.to_string(),
            level: 2_000,
        }));
    }

    #[test]
    fn below_head_rewrite_targets_the_node_head() {
        let mut n = node();
        n.level = 5_000; // both keys' 1_000 floors are below the head
        let plan = plan_repairs(&classify(&healthy_state(), Some(&n)));
        assert!(plan.contains(&RepairAction::WriteWatermarks {
            pkh: CONSENSUS_PKH.to_string(),
            level: 5_000,
        }));
    }

    #[test]
    fn plan_dedups_watermark_rewrite_for_one_key() {
        let mut state = healthy_state();
        state.watermarks[0].files[0].status = WatermarkFileStatus::Missing;
        state.watermarks[0].files[1].status = WatermarkFileStatus::Corrupt;
        let plan = plan_repairs(&classify(&state, Some(&node())));
        let writes = plan
            .iter()
            .filter(
                |a| matches!(a, RepairAction::WriteWatermarks { pkh, .. } if pkh == CONSENSUS_PKH),
            )
            .count();
        assert_eq!(writes, 1, "expected one rewrite for the key, got {plan:?}");
    }

    #[test]
    fn plan_write_supersedes_chown_for_the_same_key() {
        let mut state = healthy_state();
        state.watermarks[0].files[0].status = WatermarkFileStatus::Corrupt;
        state.watermarks[0].files[1].owner = Some((0, 0));
        let plan = plan_repairs(&classify(&state, Some(&node())));
        assert!(plan.iter().any(
            |a| matches!(a, RepairAction::WriteWatermarks { pkh, .. } if pkh == CONSENSUS_PKH)
        ));
        assert!(
            !plan.iter().any(
                |a| matches!(a, RepairAction::ChownWatermarks { pkh } if pkh == CONSENSUS_PKH)
            ),
            "the rewrite already restores ownership: {plan:?}"
        );
    }

    #[test]
    fn plan_keeps_chown_for_a_key_without_a_rewrite() {
        let mut state = healthy_state();
        state.watermarks[0].files[0].status = WatermarkFileStatus::Corrupt; // key0 rewrite
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
    fn host_direct_issue_carries_an_action_and_others_do_not() {
        let mut state = healthy_state();
        state.watermarks[0].dir_present = false;
        state.watermarks[1].files[0].owner = Some((0, 0));
        state.chain_info = ChainInfoState::Present {
            id: "NetXwrong".to_string(),
            mode: Some(0o644),
            owner: Some((0, 0)),
        };
        state.panic_log_size = Some(PANIC_LOG_MAX_BYTES + 1);
        state.boot_config = Some(BootConfigState {
            chain_id: "NetXold".to_string(),
            level: 1,
        });
        state.migration_pending = true;
        for i in &classify(&state, Some(&node())) {
            assert_eq!(
                i.remedy == Remedy::HostDirect,
                i.action.is_some(),
                "remedy and action disagree: {i:?}"
            );
        }
    }
}
