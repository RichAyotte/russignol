//! Restore keys and watermarks from an existing SD card to a new one
//!
//! Security constraint: Key data is held in memory only, never written to disk
//! on the host. The `SourceBackup` struct derives `ZeroizeOnDrop` for defense-in-depth
//! erasure of already-encrypted data.

use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::{Zeroize, ZeroizeOnDrop};

use russignol_storage::{self, F2FS_FORMAT_FEATURES, MIN_ALIGNMENT, SECTOR_SIZE};

use crate::image;
use crate::progress;
use crate::utils::{self, get_partition_path};

/// Re-export for callers and tests.
pub type RestorePartitionLayout = russignol_storage::PartitionLayout;

/// Key data read from a source card, held in memory only.
///
/// Derives `ZeroizeOnDrop` so fields are overwritten when the struct is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SourceBackup {
    pub secret_keys_enc: Vec<u8>,
    pub public_keys: Vec<u8>,
    pub public_key_hashs: Vec<u8>,
    pub chain_info: Vec<u8>,
    pub block_watermark: Option<Vec<u8>>,
    pub attestation_watermark: Option<Vec<u8>>,
    pub preattestation_watermark: Option<Vec<u8>>,
}

/// Calculate restore partition layout from sfdisk JSON output.
///
/// This is the testable core: takes parsed JSON plus the disk size (from sysfs)
/// and returns the layout without running any external commands.
/// `disk_size_sectors` comes from `/sys/block/<name>/size` since MBR partition
/// tables (used on Raspberry Pi SD cards) don't include `lastlba` in sfdisk JSON.
pub fn calculate_layout_from_json(
    json: &serde_json::Value,
    disk_size_sectors: u64,
) -> Result<RestorePartitionLayout> {
    let table = json
        .get("partitiontable")
        .context("Missing 'partitiontable' in sfdisk JSON")?;

    let partitions = table
        .get("partitions")
        .and_then(|v| v.as_array())
        .context("Missing 'partitions' array")?;

    // Find partition 2 (rootfs)
    if partitions.len() < 2 {
        bail!("Expected at least 2 partitions, found {}", partitions.len());
    }

    let p2 = &partitions[1];
    let p2_start = p2
        .get("start")
        .and_then(serde_json::Value::as_u64)
        .context("Missing partition 2 start")?;
    let p2_size = p2
        .get("size")
        .and_then(serde_json::Value::as_u64)
        .context("Missing partition 2 size")?;

    let p2_end_bytes = (p2_start + p2_size) * SECTOR_SIZE;
    let disk_size_bytes = disk_size_sectors * SECTOR_SIZE;

    russignol_storage::calculate_partition_layout(p2_end_bytes, MIN_ALIGNMENT, disk_size_bytes)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Read disk size in 512-byte sectors from sysfs
fn read_disk_size_sectors(device: &Path) -> Result<u64> {
    let device_name = device
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid device path")?;

    let size_path = format!("/sys/block/{device_name}/size");
    let size_str = fs::read_to_string(&size_path)
        .with_context(|| format!("Failed to read disk size from {size_path}"))?;

    size_str
        .trim()
        .parse::<u64>()
        .context("Failed to parse disk size")
}

/// Calculate restore partition layout by running sfdisk on the device
pub fn calculate_restore_partition_layout(device: &Path) -> Result<RestorePartitionLayout> {
    let sfdisk = utils::resolve_tool("sfdisk").context("sfdisk not found")?;
    let output = Command::new(sfdisk)
        .args(["--json"])
        .arg(device)
        .output()
        .context("Failed to run sfdisk")?;

    if !output.status.success() {
        bail!("sfdisk failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse sfdisk JSON")?;

    let disk_size_sectors = read_disk_size_sectors(device)?;
    calculate_layout_from_json(&json, disk_size_sectors)
}

/// Check that restore-keys-specific tools are available
#[cfg(target_os = "linux")]
pub fn check_restore_tools() -> Result<()> {
    let mut missing = Vec::new();

    for tool in ["sfdisk", "mkfs.f2fs"] {
        if utils::resolve_tool(tool).is_none() {
            missing.push(tool);
        }
    }

    if !missing.is_empty() {
        let tools_str = missing.join(", ");
        bail!(
            "Required tools not found: {tools_str}.\n  \
             Install with:\n    \
             sudo apt install f2fs-tools util-linux  (Debian/Ubuntu)\n    \
             sudo dnf install f2fs-tools util-linux  (Fedora)"
        );
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn check_restore_tools() -> Result<()> {
    bail!("Key restoration is only supported on Linux");
}

/// Resolve the `--restore-keys` argument to an actual device path.
///
/// When the user passes `--restore-keys` without a value, clap fills in
/// `"auto"` via `default_missing_value`. This function detects that sentinel
/// and auto-selects the source device from removable USB devices.
pub fn resolve_restore_source(arg: &Path) -> Result<PathBuf> {
    if arg.as_os_str() != "auto" {
        // Explicit device path — validate it exists
        if !arg.exists() {
            bail!("Source device not found: {}", arg.display());
        }
        return Ok(arg.to_path_buf());
    }

    // Auto-detect: check if a card is already inserted
    let mut devices = image::detect_removable_devices().unwrap_or_default();

    // No card yet — prompt the user to insert one
    if devices.is_empty() {
        prompt_enter("Insert the SOURCE SD card and press Enter...")?;

        // Poll for a device to appear (30-second timeout)
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let spinner = progress::create_spinner("Waiting for device...");
        loop {
            devices = image::detect_removable_devices().unwrap_or_default();
            if !devices.is_empty() {
                break;
            }
            if std::time::Instant::now() > deadline {
                spinner.finish_and_clear();
                bail!(
                    "No removable USB devices detected.\n\
                     Please check that the SD card is inserted and try again,\n\
                     or specify the device directly: --restore-keys /dev/sdX"
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        spinner.finish_and_clear();
    }

    if devices.len() == 1 {
        let device = &devices[0];
        utils::success(&format!("Found source device: {device}"));
        return Ok(device.path.clone());
    }

    // Multiple devices — prompt the user to pick the source
    let options: Vec<String> = devices
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    let selection = inquire::Select::new("Select source device to restore keys from:", options)
        .with_render_config(utils::create_orange_theme())
        .prompt()
        .context("Failed to get device selection")?;

    let selected = devices
        .into_iter()
        .find(|d| d.to_string() == selection)
        .context("Selected device not found")?;

    Ok(selected.path)
}

/// Read key and watermark data from a source card into memory
pub fn read_source_card(source_device: &Path) -> Result<SourceBackup> {
    let p3_path = get_partition_path(source_device, 3);
    let p4_path = get_partition_path(source_device, 4);

    if !p3_path.exists() || !p4_path.exists() {
        bail!(
            "Source card does not appear to be a configured russignol device\n  \
             (partitions {} and/or {} not found)",
            p3_path.display(),
            p4_path.display()
        );
    }

    // Mount keys partition (p3) read-only
    let p3_mount = utils::mount_partition(&p3_path, "f2fs", true)
        .context("Failed to mount source keys partition")?;

    let p3_result = (|| {
        let secret_keys_enc = fs::read(p3_mount.join("secret_keys.enc"))
            .context("No keys found on source card -- has this device completed setup?")?;
        let public_keys =
            fs::read(p3_mount.join("public_keys")).context("Missing public_keys on source card")?;
        let public_key_hashs = fs::read(p3_mount.join("public_key_hashs"))
            .context("Missing public_key_hashs on source card")?;
        let chain_info = fs::read(p3_mount.join("chain_info.json"))
            .context("Missing chain_info.json on source card")?;
        Ok((secret_keys_enc, public_keys, public_key_hashs, chain_info))
    })();

    // Always unmount p3, even on read error
    let (secret_keys_enc, public_keys, public_key_hashs, chain_info) = match p3_result {
        Ok(data) => {
            utils::unmount_partition(&p3_mount, &p3_path)?;
            data
        }
        Err(e) => {
            let _ = utils::unmount_partition(&p3_mount, &p3_path);
            return Err(e);
        }
    };

    // Mount data partition (p4) read-only
    let p4_mount = utils::mount_partition(&p4_path, "f2fs", true)
        .context("Failed to mount source data partition")?;

    let watermarks_dir = p4_mount.join("watermarks");
    let block_watermark = fs::read(watermarks_dir.join("block_high_watermark")).ok();
    let attestation_watermark = fs::read(watermarks_dir.join("attestation_high_watermark")).ok();
    let preattestation_watermark =
        fs::read(watermarks_dir.join("preattestation_high_watermark")).ok();

    // p4 reads use .ok() so they can't fail, but unmount consistently
    utils::unmount_partition(&p4_mount, &p4_path)?;

    Ok(SourceBackup {
        secret_keys_enc,
        public_keys,
        public_key_hashs,
        chain_info,
        block_watermark,
        attestation_watermark,
        preattestation_watermark,
    })
}

/// Create and format p3/p4 partitions on the target device
pub fn create_and_format_partitions(device: &Path) -> Result<()> {
    let sfdisk = utils::resolve_tool("sfdisk").context("sfdisk not found")?;
    let mkfs_f2fs = utils::resolve_tool("mkfs.f2fs").context("mkfs.f2fs not found")?;

    let layout = calculate_restore_partition_layout(device)?;

    let script = russignol_storage::generate_sfdisk_script(&layout);

    utils::info("Creating key/data partitions...");
    log::info!("sfdisk append script:\n{script}");

    let mut child = Command::new(&sfdisk)
        .args(["--append", "--no-reread"])
        .arg(device)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn sfdisk")?;

    child
        .stdin
        .as_mut()
        .context("Failed to open sfdisk stdin")?
        .write_all(script.as_bytes())
        .context("Failed to write sfdisk script")?;

    let output = child.wait_with_output().context("sfdisk failed")?;

    if !output.status.success() {
        bail!(
            "sfdisk --append failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Re-read partition table
    image::reread_partition_table(device);

    // Poll for partition device nodes (15-second timeout)
    let p3_path = get_partition_path(device, 3);
    let p4_path = get_partition_path(device, 4);

    utils::info("Waiting for partition devices...");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if p3_path.exists() && p4_path.exists() {
            break;
        }
        if std::time::Instant::now() > deadline {
            bail!(
                "Partition devices did not appear within 15 seconds: {} {}",
                p3_path.display(),
                p4_path.display()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Format partitions
    utils::info("Formatting keys partition (F2FS)...");
    let output = Command::new(&mkfs_f2fs)
        .args(["-l", "russignol-keys", "-O", F2FS_FORMAT_FEATURES, "-f"])
        .arg(&p3_path)
        .output()
        .context("Failed to run mkfs.f2fs for keys partition")?;

    if !output.status.success() {
        bail!(
            "mkfs.f2fs failed for keys partition: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    utils::info("Formatting data partition (F2FS)...");
    let output = Command::new(&mkfs_f2fs)
        .args(["-l", "russignol-data", "-O", F2FS_FORMAT_FEATURES, "-f"])
        .arg(&p4_path)
        .output()
        .context("Failed to run mkfs.f2fs for data partition")?;

    if !output.status.success() {
        bail!(
            "mkfs.f2fs failed for data partition: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// Write backup data to target device partitions
pub fn write_backup_to_target(device: &Path, backup: &SourceBackup) -> Result<()> {
    let p3_path = get_partition_path(device, 3);
    let p4_path = get_partition_path(device, 4);

    // Mount keys partition (p3) read-write
    utils::info("Writing keys to target...");
    let p3_mount = utils::mount_partition(&p3_path, "f2fs", false)
        .context("Failed to mount target keys partition")?;

    let p3_result = (|| {
        fs::write(p3_mount.join("secret_keys.enc"), &backup.secret_keys_enc)
            .context("Failed to write secret_keys.enc")?;
        fs::write(p3_mount.join("public_keys"), &backup.public_keys)
            .context("Failed to write public_keys")?;
        fs::write(p3_mount.join("public_key_hashs"), &backup.public_key_hashs)
            .context("Failed to write public_key_hashs")?;
        fs::write(p3_mount.join("chain_info.json"), &backup.chain_info)
            .context("Failed to write chain_info.json")?;
        // Write setup marker so signer skips first-boot setup
        fs::write(p3_mount.join(".setup_complete"), "1")
            .context("Failed to write .setup_complete marker")?;
        Ok(())
    })();

    // Always sync and unmount p3, even on write error
    let _ = Command::new("sync").output();
    if let Err(e) = p3_result {
        let _ = utils::unmount_partition(&p3_mount, &p3_path);
        return Err(e);
    }
    utils::unmount_partition(&p3_mount, &p3_path)?;

    // Mount data partition (p4) read-write
    utils::info("Writing watermarks to target...");
    let p4_mount = utils::mount_partition(&p4_path, "f2fs", false)
        .context("Failed to mount target data partition")?;

    let p4_result = (|| {
        let watermarks_dir = p4_mount.join("watermarks");
        fs::create_dir_all(&watermarks_dir).context("Failed to create watermarks directory")?;

        if let Some(ref data) = backup.block_watermark {
            fs::write(watermarks_dir.join("block_high_watermark"), data)
                .context("Failed to write block_high_watermark")?;
        }
        if let Some(ref data) = backup.attestation_watermark {
            fs::write(watermarks_dir.join("attestation_high_watermark"), data)
                .context("Failed to write attestation_high_watermark")?;
        }
        if let Some(ref data) = backup.preattestation_watermark {
            fs::write(watermarks_dir.join("preattestation_high_watermark"), data)
                .context("Failed to write preattestation_high_watermark")?;
        }
        Ok(())
    })();

    // Always sync and unmount p4, even on write error
    let _ = Command::new("sync").output();
    if let Err(e) = p4_result {
        let _ = utils::unmount_partition(&p4_mount, &p4_path);
        return Err(e);
    }
    utils::unmount_partition(&p4_mount, &p4_path)?;

    Ok(())
}

/// A named key entry from the wallet's `public_key_hashs` file
struct NamedKey {
    alias: String,
    address: String,
}

/// Extract named tz4 key entries from the `public_key_hashs` JSON data
fn extract_named_keys(public_key_hashs: &[u8]) -> Vec<NamedKey> {
    let Ok(entries) = serde_json::from_slice::<Vec<serde_json::Value>>(public_key_hashs) else {
        return Vec::new();
    };

    entries
        .iter()
        .filter_map(|e| {
            let name = e.get("name").and_then(|v| v.as_str())?;
            let value = e.get("value").and_then(|v| v.as_str())?;
            if value.starts_with("tz4") {
                Some(NamedKey {
                    alias: name.to_string(),
                    address: value.to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Extract tz4 addresses from the `public_key_hashs` JSON data
#[cfg(test)]
fn extract_tz4_addresses(public_key_hashs: &[u8]) -> Vec<String> {
    extract_named_keys(public_key_hashs)
        .into_iter()
        .map(|k| k.address)
        .collect()
}

/// Parse chain name and id from `chain_info.json` bytes
fn parse_chain_info(chain_info: &[u8]) -> Option<(String, String)> {
    let json: serde_json::Value = serde_json::from_slice(chain_info).ok()?;
    let name = json.get("name").and_then(|v| v.as_str())?.to_string();
    let id = json.get("id").and_then(|v| v.as_str())?.to_string();
    Some((name, id))
}

/// Extract the highest watermark level from a watermark file's bytes.
///
/// Watermark format: `{ chain_id: { pkh: { level, round, ... } } }`
fn extract_watermark_level(watermark: &[u8]) -> Option<u32> {
    let json: serde_json::Value = serde_json::from_slice(watermark).ok()?;
    let obj = json.as_object()?;

    let mut max_level: Option<u32> = None;
    for chain in obj.values() {
        let chain_obj = chain.as_object()?;
        for pkh_data in chain_obj.values() {
            if let Some(level) = pkh_data.get("level").and_then(serde_json::Value::as_u64) {
                let level = u32::try_from(level).unwrap_or(u32::MAX);
                max_level = Some(max_level.map_or(level, |cur| cur.max(level)));
            }
        }
    }
    max_level
}

/// Map a key alias to a user-friendly label
fn friendly_key_label(alias: &str) -> &str {
    use crate::constants;
    match alias {
        s if s == constants::CONSENSUS_KEY_ALIAS => "Consensus key",
        s if s == constants::COMPANION_KEY_ALIAS => "Companion key",
        s if s == constants::CONSENSUS_KEY_PENDING_ALIAS => "Pending consensus key",
        s if s == constants::COMPANION_KEY_PENDING_ALIAS => "Pending companion key",
        _ => "Key",
    }
}

/// Print restore success message matching the normal flash output
pub fn print_restore_success() {
    utils::success("Flash complete!");
    println!();
    println!("  You can now insert the SD card into your Raspberry Pi Zero 2W.");
}

/// Verify the inserted card is not the source card (user forgot to swap).
///
/// Checks whether the device's keys partition (p3) contains the same
/// `public_key_hashs` as the source backup. If it does, the user likely
/// forgot to swap cards and would overwrite their source.
fn verify_not_source_card(device: &Path, backup: &SourceBackup) -> Result<()> {
    let p3_path = get_partition_path(device, 3);
    if !p3_path.exists() {
        // No p3 partition — fresh or non-russignol card, safe to proceed
        return Ok(());
    }

    // Try to mount and read public_key_hashs; if anything fails the card
    // is clearly different from the source (corrupted, different FS, etc.)
    let Ok(mount) = utils::mount_partition(&p3_path, "f2fs", true) else {
        return Ok(());
    };

    let target_pkh = fs::read(mount.join("public_key_hashs")).ok();
    let _ = utils::unmount_partition(&mount, &p3_path);

    if let Some(target_pkh) = target_pkh
        && target_pkh == backup.public_key_hashs
    {
        bail!(
            "This card contains the same keys as the source card!\n  \
             You may have forgotten to swap cards.\n  \
             Please remove this card, insert the TARGET card, and try again."
        );
    }

    Ok(())
}

/// Show a destructive operation warning with key/chain details and require
/// the user to type the device name to confirm.
///
/// Returns `true` if the user confirms, `false` if cancelled.
/// Automatically confirms when `yes` is `true`.
pub fn confirm_restore_operation(
    target: &image::BlockDevice,
    backup: &SourceBackup,
    yes: bool,
) -> Result<bool> {
    let warning_msg = "ALL DATA ON THIS DEVICE WILL BE PERMANENTLY ERASED!";

    // Build info lines for the box
    let mut lines = vec![
        format!("Target: {}", target.path.display()),
        format!("Model:  {}", target.model),
        format!("Size:   {}", target.size),
    ];

    let keys = extract_named_keys(&backup.public_key_hashs);
    for key in &keys {
        let label = friendly_key_label(&key.alias);
        lines.push(format!("{label}: {}", key.address));
    }

    if let Some((name, id)) = parse_chain_info(&backup.chain_info) {
        lines.push(format!("Chain: {name} ({id})"));
    }

    if let Some(ref wm) = backup.block_watermark
        && let Some(level) = extract_watermark_level(wm)
    {
        lines.push(format!(
            "Head Level: {}",
            utils::format_with_separators(level)
        ));
    }

    println!();
    println!(
        "  {}",
        "╔══════════════════════════════════════════════════════════╗".red()
    );
    println!(
        "  {}  {:^54}  {}",
        "║".red(),
        "⚠  WARNING: DESTRUCTIVE OPERATION".red().bold(),
        "║".red()
    );
    println!(
        "  {}",
        "╠══════════════════════════════════════════════════════════╣".red()
    );
    for line in &lines {
        println!("  {}  {:<54}  {}", "║".red(), line, "║".red());
    }
    println!(
        "  {}",
        "╠══════════════════════════════════════════════════════════╣".red()
    );
    println!("  {}  {:^54}  {}", "║".red(), warning_msg.red(), "║".red());
    println!(
        "  {}",
        "╚══════════════════════════════════════════════════════════╝".red()
    );

    if yes {
        utils::warning("Auto-confirming due to --yes flag");
        return Ok(true);
    }

    let prompt = format!("Type '{}' to confirm (or 'q' to cancel):", target.name);
    loop {
        let response = inquire::Text::new(&prompt)
            .with_render_config(utils::create_orange_theme())
            .prompt()
            .context("Failed to get confirmation")?;

        let response_lower = response.trim().to_lowercase();

        if response_lower == target.name.to_lowercase() {
            return Ok(true);
        }

        if response_lower == "q" || response_lower == "quit" || response_lower == "cancel" {
            return Ok(false);
        }

        println!(
            "  {} Expected '{}', got '{}'. Try again.",
            "✗".red(),
            target.name,
            response.trim()
        );
    }
}

/// Determine if single-reader mode is needed.
///
/// Returns true if the source and target are (or would be) the same device,
/// meaning the user needs to swap cards in the same reader.
pub fn is_single_reader_mode(
    restore_from: &Path,
    device: Option<&Path>,
    detected_devices: &[image::BlockDevice],
) -> bool {
    if let Some(dev) = device {
        // Explicit --device matches --restore-keys
        dev == restore_from
    } else {
        // No --device: single reader if there's no second device available.
        // This covers: no devices detected (card not inserted yet), or only
        // the restore_from device detected.
        let other_devices = detected_devices
            .iter()
            .filter(|d| d.path != restore_from)
            .count();
        other_devices == 0
    }
}

/// Wait for a device to reappear after card swap
pub fn wait_for_device_reappear(device: &Path) -> Result<()> {
    let spinner = progress::create_spinner("Waiting for device...");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if device.exists() {
            // Give udev a moment to settle
            std::thread::sleep(std::time::Duration::from_secs(1));
            spinner.finish_and_clear();
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            spinner.finish_and_clear();
            bail!(
                "Device {} did not reappear within 30 seconds. \
                 Please insert the target SD card and try again.",
                device.display()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Ensure partition device nodes are visible for the source card.
///
/// After card insertion, the kernel may not have created device nodes for
/// all partitions yet. This triggers a partition table re-read and polls
/// briefly for p3 and p4 to appear.
pub fn ensure_source_partitions_visible(device: &Path) -> Result<()> {
    let p3_path = get_partition_path(device, 3);
    let p4_path = get_partition_path(device, 4);

    if p3_path.exists() && p4_path.exists() {
        return Ok(());
    }

    // Re-read partition table to make kernel aware of all partitions
    image::reread_partition_table(device);

    // Poll for partition nodes (5-second timeout)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if p3_path.exists() && p4_path.exists() {
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            // Partitions genuinely don't exist on this card
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// Prompt user to press Enter (for card swap prompts)
fn prompt_enter(message: &str) -> Result<()> {
    print!("  {message}");
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin()
        .read_line(&mut buf)
        .context("Failed to read input")?;
    Ok(())
}

/// Run the restore workflow for single-reader mode (card swap)
pub fn run_single_reader_restore(
    restore_from: &Path,
    image: &Path,
    yes: bool,
    uncompressed_size: Option<u64>,
) -> Result<()> {
    // Step 1: Read source card (prompt only if not already inserted)
    if !restore_from.exists() {
        prompt_enter("Insert SOURCE card and press Enter...")?;
        wait_for_device_reappear(restore_from)?;
    }

    ensure_source_partitions_visible(restore_from)?;
    let spinner = progress::create_spinner("Reading source card...");
    let backup = read_source_card(restore_from)?;
    spinner.finish_and_clear();

    // Step 2: Swap to target card
    prompt_enter("Remove SOURCE card, insert TARGET card, and press Enter...")?;
    wait_for_device_reappear(restore_from)?;

    // Verify the user actually swapped cards
    verify_not_source_card(restore_from, &backup)?;

    // Check not mounted
    image::check_device_not_mounted(restore_from)?;

    // Look up device info for the warning box
    let target = image::lookup_block_device(restore_from)
        .unwrap_or_else(|_| image::BlockDevice::from_path(restore_from));

    // Confirm before flashing
    if !confirm_restore_operation(&target, &backup, yes)? {
        utils::info("Restore cancelled");
        println!();
        return Ok(());
    }

    // Step 3: Flash, partition, and write keys
    image::flash_image_to_device(image, restore_from, uncompressed_size)?;
    image::reread_partition_table(restore_from);

    create_and_format_partitions(restore_from)?;
    write_backup_to_target(restore_from, &backup)?;

    print_restore_success();
    Ok(())
}

/// Run the restore workflow for dual-reader mode (both cards accessible)
pub fn run_dual_reader_restore(
    target: &image::BlockDevice,
    image: &Path,
    yes: bool,
    uncompressed_size: Option<u64>,
    backup: &SourceBackup,
) -> Result<()> {
    // Confirm before flashing
    if !confirm_restore_operation(target, backup, yes)? {
        utils::info("Restore cancelled");
        println!();
        return Ok(());
    }

    // Step 1: Flash target card
    image::flash_image_to_device(image, &target.path, uncompressed_size)?;
    image::reread_partition_table(&target.path);

    // Step 2: Create partitions and write backup
    create_and_format_partitions(&target.path)?;
    write_backup_to_target(&target.path, backup)?;

    print_restore_success();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_backup_zeroize() {
        let mut backup = SourceBackup {
            secret_keys_enc: vec![1, 2, 3, 4],
            public_keys: vec![5, 6, 7],
            public_key_hashs: vec![8, 9],
            chain_info: vec![10, 11, 12],
            block_watermark: Some(vec![13, 14]),
            attestation_watermark: Some(vec![15, 16]),
            preattestation_watermark: Some(vec![17, 18]),
        };

        backup.zeroize();

        assert!(backup.secret_keys_enc.is_empty());
        assert!(backup.public_keys.is_empty());
        assert!(backup.public_key_hashs.is_empty());
        assert!(backup.chain_info.is_empty());
        assert!(backup.block_watermark.is_none());
        assert!(backup.attestation_watermark.is_none());
        assert!(backup.preattestation_watermark.is_none());
    }

    #[test]
    fn test_partition_layout_from_sfdisk_json() {
        // Simulate a 32GB SD card with boot (p1) and rootfs (p2)
        let disk_size_sectors: u64 = 62_521_344; // ~32GB
        let json = serde_json::json!({
            "partitiontable": {
                "partitions": [
                    { "start": 8192u64, "size": 524288u64, "type": "c" },     // p1: boot (256MB)
                    { "start": 532480u64, "size": 4194304u64, "type": "83" }  // p2: rootfs (2GB)
                ]
            }
        });

        let layout = calculate_layout_from_json(&json, disk_size_sectors).unwrap();

        // p2 ends at sector 532480 + 4194304 = 4726784
        // p2 end bytes = 4726784 * 512 = 2420113408
        // align_up(2420113408, 16MB) = align_up(2420113408, 16777216)
        //   = ceil(2420113408 / 16777216) * 16777216 = 145 * 16777216 = 2432696320
        // keys_start_sector = 2432696320 / 512 = 4751360
        let expected_keys_start =
            russignol_storage::align_up((532480 + 4194304) * SECTOR_SIZE, MIN_ALIGNMENT)
                / SECTOR_SIZE;
        assert_eq!(layout.keys_start_sector, expected_keys_start);

        // keys_size = 64MB / 512 = 131072 sectors
        assert_eq!(
            layout.keys_size_sectors,
            russignol_storage::F2FS_PARTITION_SIZE / SECTOR_SIZE
        );

        // data_start = keys_start + keys_size
        assert_eq!(
            layout.data_start_sector,
            layout.keys_start_sector + layout.keys_size_sectors
        );
        assert_eq!(
            layout.data_size_sectors,
            russignol_storage::F2FS_PARTITION_SIZE / SECTOR_SIZE
        );
    }

    #[test]
    fn test_partition_layout_insufficient_space() {
        // Tiny disk: 100MB
        let disk_size_sectors = 100 * 1024 * 1024 / SECTOR_SIZE; // 204800
        let json = serde_json::json!({
            "partitiontable": {
                "partitions": [
                    { "start": 8192u64, "size": 16384u64, "type": "c" },
                    { "start": 24576u64, "size": 131072u64, "type": "83" }
                ]
            }
        });

        let result = calculate_layout_from_json(&json, disk_size_sectors);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Insufficient disk space")
        );
    }

    #[test]
    fn test_extract_tz4_addresses() {
        let json = serde_json::to_vec(&serde_json::json!([
            { "name": "key1", "value": "tz4HVR6aty9KwsQFHh81C1G7gBdhxT8kuHtm" },
            { "name": "key2", "value": "tz4KqQ9TbeYLg3Vtf6Pf5E9UJrhRepbgZ6WW" },
            { "name": "key3", "value": "tz1aSkwEot3L2kmUvcoxzjMomb9LTQjTBGDKS" }
        ]))
        .unwrap();

        let addresses = extract_tz4_addresses(&json);
        assert_eq!(addresses.len(), 2);
        assert!(addresses[0].starts_with("tz4"));
        assert!(addresses[1].starts_with("tz4"));
    }

    #[test]
    fn test_extract_tz4_addresses_empty() {
        let addresses = extract_tz4_addresses(b"invalid json");
        assert!(addresses.is_empty());
    }

    #[test]
    fn test_single_reader_detection_same_device() {
        let restore_from = Path::new("/dev/sdb");
        let device = Some(Path::new("/dev/sdb"));
        assert!(is_single_reader_mode(restore_from, device, &[]));
    }

    #[test]
    fn test_single_reader_detection_different_device() {
        let restore_from = Path::new("/dev/sdb");
        let device = Some(Path::new("/dev/sdc"));
        assert!(!is_single_reader_mode(restore_from, device, &[]));
    }

    #[test]
    fn test_single_reader_detection_auto_only_one() {
        let restore_from = Path::new("/dev/sdb");
        let devices = vec![image::BlockDevice {
            name: "sdb".to_string(),
            path: PathBuf::from("/dev/sdb"),
            transport: "usb".to_string(),
            size: "32G".to_string(),
            model: "Card Reader".to_string(),
        }];
        assert!(is_single_reader_mode(restore_from, None, &devices));
    }

    #[test]
    fn test_single_reader_detection_no_devices_detected() {
        // No media inserted yet -- still single reader
        let restore_from = Path::new("/dev/sdb");
        assert!(is_single_reader_mode(restore_from, None, &[]));
    }

    #[test]
    fn test_single_reader_detection_auto_multiple() {
        let restore_from = Path::new("/dev/sdb");
        let devices = vec![
            image::BlockDevice {
                name: "sdb".to_string(),
                path: PathBuf::from("/dev/sdb"),
                transport: "usb".to_string(),
                size: "32G".to_string(),
                model: "Reader 1".to_string(),
            },
            image::BlockDevice {
                name: "sdc".to_string(),
                path: PathBuf::from("/dev/sdc"),
                transport: "usb".to_string(),
                size: "32G".to_string(),
                model: "Reader 2".to_string(),
            },
        ];
        assert!(!is_single_reader_mode(restore_from, None, &devices));
    }
}
