use anyhow::{Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::constants::{ORANGE, ORANGE_RGB};

/// Calculate terminal display width, treating emojis as 2 cells wide
///
/// Terminals typically render emojis as 2 cells wide regardless of Unicode
/// Standard Annex #11 width properties, so we use a terminal-specific calculation.
fn terminal_width(s: &str) -> usize {
    use unicode_width::UnicodeWidthChar;
    s.chars()
        .map(|c| {
            if c.is_ascii() {
                1
            } else {
                // Non-ASCII: use unicode width but minimum 2 for visible chars (emojis)
                let w = UnicodeWidthChar::width(c).unwrap_or(0);
                if w > 0 { 2 } else { 0 }
            }
        })
        .sum()
}

/// Print a styled title bar with orange separator matching the title width
pub fn print_title_bar(title: &str) {
    println!("{}", title.bold().bright_white());
    let width = terminal_width(title);
    let separator: String = "─".repeat(width);
    println!("{}", separator.truecolor(ORANGE.0, ORANGE.1, ORANGE.2));
}

/// Print a subdued subtitle bar with gray separator matching the title width
pub fn print_subtitle_bar(title: &str) {
    println!("{}", title.white());
    let width = terminal_width(title);
    let separator: String = "─".repeat(width);
    println!("{}", separator.dimmed());
}

/// Display a success message
pub fn success(message: &str) {
    if message.is_empty() {
        println!("  {}", "✓".green());
    } else {
        println!("  {} {}", "✓".green(), message);
    }
}

/// Display a warning message
pub fn warning(message: &str) {
    println!("  {} {}", "⚠".bold().yellow(), message);
}

/// Display an info message
pub fn info(message: &str) {
    println!("  • {message}");
}

/// Surface a discarded fallible result as a warning instead of dropping it.
///
/// For best-effort cleanup where the failure is not fatal but must not vanish.
/// Returns whether a warning was emitted so callers can react and tests can
/// observe the branch taken.
pub fn warn_if_err<T, E: std::fmt::Display>(res: Result<T, E>, context: &str) -> bool {
    match res {
        Ok(_) => false,
        Err(e) => {
            warning(&format!("{context}: {e}"));
            true
        }
    }
}

/// Run a command as best-effort: warn (but never propagate) on a spawn failure
/// or a non-zero exit, surfacing stderr so the failure is visible.
///
/// For side-effecting commands (sync, partition re-read, service reload) whose
/// failure should be reported but should not abort the caller.
pub fn run_best_effort(program: &str, args: &[&str], context: &str) {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let trimmed = stderr.trim();
            if trimmed.is_empty() {
                warning(&format!(
                    "{context}: {program} exited with {}",
                    output.status
                ));
            } else {
                warning(&format!("{context}: {trimmed}"));
            }
        }
        Err(e) => warning(&format!("{context}: failed to run {program}: {e}")),
    }
}

/// Create orange-themed render config for inquire prompts
///
/// Uses 2-space indent prefix to align with `utils::info/success` output style.
pub fn create_orange_theme() -> inquire::ui::RenderConfig<'static> {
    inquire::ui::RenderConfig {
        prompt_prefix: inquire::ui::Styled::new("  ?").with_fg(ORANGE_RGB),
        answered_prompt_prefix: inquire::ui::Styled::new("  ✓").with_fg(ORANGE_RGB),
        answer: inquire::ui::StyleSheet::new().with_fg(ORANGE_RGB),
        ..Default::default()
    }
}

/// Run a command and return the output
pub fn run_command(program: &str, args: &[&str]) -> Result<std::process::Output> {
    log::debug!("Running command: {} {}", program, args.join(" "));

    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute: {} {}", program, args.join(" ")))?;

    log::debug!("Command exit status: {}", output.status);
    if !output.stdout.is_empty() {
        log::debug!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        log::debug!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(output)
}

/// Run an octez-client command with automatic endpoint and base-dir configuration
///
/// This wrapper automatically adds the --endpoint and --base-dir flags to all octez-client
/// commands, ensuring consistent RPC endpoint and client directory usage across the application.
pub fn run_octez_client_command(
    args: &[&str],
    config: &crate::config::RussignolConfig,
) -> Result<std::process::Output> {
    let client_dir = config
        .octez_client_dir
        .to_str()
        .context("Invalid client directory path")?;
    let mut full_args = vec![
        "--wait",
        "1",
        "--endpoint",
        config.rpc_endpoint.as_str(),
        "--base-dir",
        client_dir,
    ];
    full_args.extend_from_slice(args);
    run_command("octez-client", &full_args)
}

/// Check if a systemd service is currently active
pub fn is_service_active(service: &str) -> bool {
    if !command_exists("systemctl") {
        return false;
    }
    run_command("systemctl", &["is-active", service])
        .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).trim() == "active")
}

/// Check if a command exists in PATH
pub fn command_exists(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Check if a file exists
pub fn file_exists(path: &Path) -> bool {
    path.exists() && path.is_file()
}

/// Check if a directory exists
pub fn dir_exists(path: &Path) -> bool {
    path.exists() && path.is_dir()
}

/// Read a file to string
pub fn read_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))
}

/// Ensure sudo credentials are cached so subsequent sudo calls don't prompt
///
/// Runs `sudo -v` with inherited stdio so the user can see the password prompt
/// and type their password. This must be called _outside_ any spinner context.
pub fn ensure_sudo() -> Result<()> {
    let status = Command::new("sudo")
        .arg("-v")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("Failed to run sudo -v")?;

    if !status.success() {
        anyhow::bail!("sudo authentication failed");
    }

    Ok(())
}

/// Run a command with sudo
pub fn sudo_command(program: &str, args: &[&str]) -> Result<std::process::Output> {
    let cmd_line = format!("  $ sudo {} {}", program, args.join(" "));
    println!("{}", cmd_line.dimmed());
    let mut sudo_args = vec![program];
    sudo_args.extend(args);
    run_command("sudo", &sudo_args)
}

/// Run a command with sudo and check success
pub fn sudo_command_success(program: &str, args: &[&str]) -> Result<String> {
    let output = sudo_command(program, args)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Sudo command failed: {} {}\nError: {}",
            program,
            args.join(" "),
            stderr
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run a command with sudo (quiet — no printed command line)
pub fn sudo_command_quiet(program: &str, args: &[&str]) -> Result<std::process::Output> {
    let mut sudo_args = vec![program];
    sudo_args.extend(args);
    run_command("sudo", &sudo_args)
}

/// Run a command with sudo and check success (quiet — no printed command line)
pub fn sudo_command_success_quiet(program: &str, args: &[&str]) -> Result<String> {
    let output = sudo_command_quiet(program, args)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Sudo command failed: {} {}\nError: {}",
            program,
            args.join(" "),
            stderr
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run an RPC call via octez-client and parse the JSON response
///
/// This helper consolidates the common pattern of calling RPC endpoints,
/// checking for errors, and parsing JSON responses. It eliminates ~150 lines
/// of duplicate code across the codebase.
pub fn rpc_get_json(
    path: &str,
    config: &crate::config::RussignolConfig,
) -> Result<serde_json::Value> {
    let output = run_octez_client_command(&["rpc", "get", path], config)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("RPC call to {path} failed: {stderr}");
    }

    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("Failed to parse JSON from RPC endpoint: {path}"))
}

/// Prompt the user for a yes/no confirmation
///
/// Returns true if the user confirms (y/yes), false otherwise.
/// If `auto_confirm` is true, automatically returns true without prompting.
pub fn prompt_yes_no(message: &str, auto_confirm: bool) -> Result<bool> {
    use std::io::Write;

    if auto_confirm {
        return Ok(true);
    }

    print!("{message} [y/N]: ");
    std::io::stdout().flush()?;

    let mut response = String::new();
    std::io::stdin()
        .read_line(&mut response)
        .context("Failed to read user input")?;

    let response = response.trim().to_lowercase();
    Ok(response == "y" || response == "yes")
}

// =============================================================================
// HTTP Utilities
// =============================================================================

/// Create a ureq HTTP agent with the specified timeout
///
/// This consolidates the repeated agent configuration pattern across
/// version.rs, upgrade.rs, image.rs, and watermark.rs.
pub fn create_http_agent(timeout_secs: u64) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_secs)))
        .build();
    config.into()
}

/// Perform an HTTP GET request and parse the response as JSON
///
/// Returns an error if the request fails or returns non-200 status.
pub fn http_get_json(agent: &ureq::Agent, url: &str) -> Result<serde_json::Value> {
    let mut response = agent
        .get(url)
        .call()
        .with_context(|| format!("HTTP request failed: {url}"))?;

    if response.status() != 200 {
        anyhow::bail!("HTTP {} from {}", response.status(), url);
    }

    let text = response
        .body_mut()
        .read_to_string()
        .with_context(|| format!("Failed to read response from {url}"))?;

    serde_json::from_str(&text).with_context(|| format!("Failed to parse JSON from {url}"))
}

// =============================================================================
// Device/Partition Utilities
// =============================================================================

/// Get the boot partition path for a block device
///
/// Handles naming conventions for different device types:
/// - `/dev/sdc` -> `/dev/sdc1`
/// - `/dev/mmcblk0` -> `/dev/mmcblk0p1`
/// - `/dev/nvme0n1` -> `/dev/nvme0n1p1`
#[cfg(target_os = "linux")]
pub fn get_partition_path(device: &Path, partition_num: u8) -> PathBuf {
    let device_str = device.to_string_lossy();

    let partition = if device_str.contains("mmcblk") || device_str.contains("nvme") {
        format!("{device_str}p{partition_num}")
    } else {
        format!("{device_str}{partition_num}")
    };

    PathBuf::from(partition)
}

#[cfg(target_os = "macos")]
pub fn get_partition_path(device: &Path, partition_num: u8) -> PathBuf {
    let device_str = device.to_string_lossy();
    PathBuf::from(format!("{}s{}", device_str, partition_num))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn get_partition_path(device: &Path, partition_num: u8) -> PathBuf {
    // Fallback - just append the partition number
    let device_str = device.to_string_lossy();
    PathBuf::from(format!("{}{}", device_str, partition_num))
}

// =============================================================================
// Tool Resolution
// =============================================================================

/// Resolve a tool to its full path, checking PATH then /sbin and /usr/sbin
#[cfg(target_os = "linux")]
pub fn resolve_tool(name: &str) -> Option<PathBuf> {
    // Check PATH first via 'which'
    if let Ok(output) = Command::new("which").arg(name).output()
        && output.status.success()
    {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }

    // Check /sbin and /usr/sbin (not always in user's PATH)
    for dir in ["/sbin", "/usr/sbin"] {
        let path = Path::new(dir).join(name);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

#[cfg(not(target_os = "linux"))]
pub fn resolve_tool(_name: &str) -> Option<PathBuf> {
    None
}

// =============================================================================
// Mount / Unmount Helpers
// =============================================================================

/// Create a temporary mount point directory using mktemp
fn create_temp_mount_point() -> Result<PathBuf> {
    let output = Command::new("mktemp")
        .args(["-d", "-t", "russignol-mount.XXXXXX"])
        .output()
        .context("Failed to run mktemp")?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to create temp directory: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(path))
}

/// Extract the mount point from `udisksctl mount` output, which reads like
/// `Mounted /dev/sdb1 at /run/media/user/BOOT.` — the path after ` at `, with
/// the trailing period stripped. `None` when the marker is absent or the target
/// is empty, both of which mean the output could not be understood.
#[cfg(target_os = "linux")]
fn parse_udisks_mount_point(stdout: &str) -> Option<&str> {
    let point = stdout.split(" at ").nth(1)?.trim().trim_end_matches('.');
    (!point.is_empty()).then_some(point)
}

/// Mount `partition` at a fresh temp dir via `mount`, escalating with `sudo -n`
/// when the unprivileged attempt fails. The traditional fallback used when
/// neither findmnt nor udisksctl already provides a mount point.
#[cfg(target_os = "linux")]
fn mount_partition_with_sudo(partition: &Path, fs_type: &str, read_only: bool) -> Result<PathBuf> {
    let mount_point = create_temp_mount_point()?;
    let mount_opts = if read_only { "ro" } else { "rw" };
    let partition_str = partition.to_string_lossy().to_string();
    let mount_point_str = mount_point.to_string_lossy().to_string();

    let output = run_with_sudo_fallback(
        "mount",
        &[
            "-t",
            fs_type,
            "-o",
            mount_opts,
            &partition_str,
            &mount_point_str,
        ],
    )
    .context("Failed to run mount")?;

    if !output.status.success() {
        warn_if_err(
            std::fs::remove_dir(&mount_point),
            "Failed to remove temporary mount point after a failed mount",
        );
        anyhow::bail!(
            "Failed to mount {} partition {}: {}\n  \
             Mounting needs elevated privileges. Re-run with sudo (or cache \
             it first with `sudo -v`), or enable udisksctl/polkit for \
             removable media.",
            fs_type,
            partition.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(mount_point)
}

/// Mount a partition, auto-detecting existing mounts and trying udisksctl first.
///
/// `fs_type` is the filesystem type passed to `mount -t` (e.g. `"vfat"`, `"f2fs"`).
/// When `read_only` is true the partition is mounted read-only.
pub fn mount_partition(partition: &Path, fs_type: &str, read_only: bool) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        // Check if partition is already mounted via findmnt
        let output = Command::new("findmnt")
            .args(["-n", "-o", "TARGET"])
            .arg(partition)
            .output();

        if let Ok(output) = output
            && output.status.success()
        {
            let mount_point = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !mount_point.is_empty() {
                info(&format!("Partition already mounted at {mount_point}"));
                return Ok(PathBuf::from(mount_point));
            }
        }

        // Try udisksctl first (works without sudo for removable media)
        let mut udisks_args = vec!["mount", "-b"];
        let partition_str = partition.to_string_lossy().to_string();
        udisks_args.push(&partition_str);
        if read_only {
            udisks_args.push("-o");
            udisks_args.push("ro");
        }

        let output = Command::new("udisksctl").args(&udisks_args).output();

        if let Ok(output) = output
            && output.status.success()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(mount_point) = parse_udisks_mount_point(&stdout) {
                return Ok(PathBuf::from(mount_point));
            }
            // udisksctl mounted the partition but its output did not name where.
            // Falling through would mount a second time at a temp dir and leak
            // this mount; undo it and surface the reason.
            run_best_effort(
                "udisksctl",
                &["unmount", "-b", &partition_str],
                "Failed to undo an unparseable udisksctl mount",
            );
            anyhow::bail!(
                "udisksctl reported a successful mount of {} but its output could \
                 not be parsed for the mount point: {}",
                partition.display(),
                stdout.trim()
            );
        }

        // Fall back to the traditional mount, which needs root.
        mount_partition_with_sudo(partition, fs_type, read_only)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = read_only;
        let mount_point = create_temp_mount_point()?;
        let mac_fs = if fs_type == "vfat" { "msdos" } else { fs_type };

        let output = Command::new("mount")
            .args(["-t", mac_fs])
            .arg(partition)
            .arg(&mount_point)
            .output()
            .context("Failed to run mount")?;

        if !output.status.success() {
            warn_if_err(
                std::fs::remove_dir(&mount_point),
                "Failed to remove temporary mount point after a failed mount",
            );
            anyhow::bail!(
                "Failed to mount partition: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(mount_point)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (partition, fs_type, read_only);
        anyhow::bail!("Mounting not supported on this platform")
    }
}

/// Unmount a partition, trying udisksctl first then falling back to umount.
pub fn unmount_partition(mount_point: &Path, partition: &Path) -> Result<()> {
    // Sync first
    run_best_effort("sync", &[], "Failed to sync before unmount");

    #[cfg(target_os = "linux")]
    {
        // Try udisksctl first (matches how we mounted)
        let output = Command::new("udisksctl")
            .args(["unmount", "-b"])
            .arg(partition)
            .output();

        if let Ok(output) = output
            && output.status.success()
        {
            return Ok(());
        }

        // Fall back to the traditional umount, which needs root.
        let mount_point_str = mount_point.to_string_lossy().to_string();
        let output = run_with_sudo_fallback("umount", &[&mount_point_str])
            .context("Failed to run umount")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to unmount {}: {}",
                mount_point.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        warn_if_err(
            std::fs::remove_dir(mount_point),
            "Failed to remove mount point after unmount",
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let _ = partition;
        let output = Command::new("umount")
            .arg(mount_point)
            .output()
            .context("Failed to run umount")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to unmount: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        warn_if_err(
            std::fs::remove_dir(mount_point),
            "Failed to remove mount point after unmount",
        );
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (mount_point, partition);
        anyhow::bail!("Unmounting not supported on this platform")
    }
}

/// Run `program args`, retrying under non-interactive `sudo -n` when the
/// unprivileged attempt fails.
///
/// `sudo -n` never prompts, so a cached credential escalates silently and an
/// uncached one fails cleanly rather than blocking a spinner on a password
/// prompt — unlike [`sudo_command`], which shells out to interactive sudo.
fn run_with_sudo_fallback(
    program: impl AsRef<std::ffi::OsStr>,
    args: &[&str],
) -> std::io::Result<std::process::Output> {
    let program = program.as_ref();
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => Ok(output),
        _ => Command::new("sudo")
            .arg("-n")
            .arg(program)
            .args(args)
            .output(),
    }
}

/// Partition-table UUID of a whole-disk device, used as a stable card identity
/// for the swap guard when no flash manifest is present.
///
/// `-c /dev/null` bypasses blkid's cache so the value reflects the media
/// currently inserted, not a stale entry from before a swap. An unprivileged
/// read is tried first, then a non-interactive `sudo` (`-n`, never prompting),
/// so a manifest-less card is still identifiable without stalling the flow on
/// a password prompt. Returns `None` when the device has no partition table or
/// `blkid` is unavailable.
pub fn source_disk_ptuuid(device: &Path) -> Option<String> {
    let blkid = resolve_tool("blkid")?;
    let device_str = device.to_string_lossy().to_string();
    let output = run_with_sudo_fallback(
        &blkid,
        &[
            "-c",
            "/dev/null",
            "-s",
            "PTUUID",
            "-o",
            "value",
            &device_str,
        ],
    )
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if id.is_empty() { None } else { Some(id) }
}

/// Warn up front when nothing can mount partitions, so a long flash does not
/// fail deep inside a spinner. Mounting needs root, a working udisksctl/polkit,
/// or (cached) sudo; the mount helpers escalate via `sudo -n` when creds are
/// cached. Only warns — it does not prompt.
#[cfg(target_os = "linux")]
pub fn ensure_mount_capability() {
    let is_root = nix::unistd::Uid::effective().is_root();
    if is_root || resolve_tool("udisksctl").is_some() || resolve_tool("sudo").is_some() {
        return;
    }
    warning(
        "Cannot mount partitions: not root, and neither udisksctl nor sudo is \
         available. Reading the source card and verifying the target will fail. \
         Install udisks2, or run as root.",
    );
}

#[cfg(not(target_os = "linux"))]
pub fn ensure_mount_capability() {}

// =============================================================================
// JSON Value Extraction Utilities
// =============================================================================

/// Extension trait for easier JSON value extraction
///
/// Provides convenient methods for extracting typed values from `serde_json::Value`,
/// reducing the verbose `.get().and_then().and_then()` chains throughout the codebase.
pub trait JsonValueExt {
    /// Get a string value by key
    fn get_str(&self, key: &str) -> Option<&str>;

    /// Get an i64 value by key (handles both numeric and string representations)
    fn get_i64(&self, key: &str) -> Option<i64>;

    /// Get a bool value by key
    fn get_bool(&self, key: &str) -> Option<bool>;

    /// Get a nested value and apply the same extraction methods
    fn get_nested(&self, key: &str) -> Option<&serde_json::Value>;
}

impl JsonValueExt for serde_json::Value {
    fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| {
            // Try as number first, then as string (Tezos RPC returns some numbers as strings)
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
    }

    fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(serde_json::Value::as_bool)
    }

    fn get_nested(&self, key: &str) -> Option<&serde_json::Value> {
        self.get(key)
    }
}

// =============================================================================
// Number Formatting Utilities
// =============================================================================

/// Format a number with thousands separators
///
/// Example: 1234567 -> "1,234,567"
pub fn format_with_separators(num: u32) -> String {
    let s = num.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warn_if_err_reports_only_on_error() {
        assert!(!warn_if_err(Ok::<_, String>(()), "ok path"));
        assert!(warn_if_err(Err::<(), _>("boom"), "err path"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_udisks_mount_point_extracts_path_or_reports_unparseable() {
        assert_eq!(
            parse_udisks_mount_point("Mounted /dev/sdb1 at /run/media/user/BOOT.\n"),
            Some("/run/media/user/BOOT")
        );
        // No " at " marker: the output cannot be understood.
        assert_eq!(
            parse_udisks_mount_point("Mounted /dev/sdb1 somewhere"),
            None
        );
        // Marker present but empty target: also unparseable.
        assert_eq!(parse_udisks_mount_point("Mounted /dev/sdb1 at ."), None);
    }

    #[test]
    fn test_format_with_separators() {
        assert_eq!(format_with_separators(0), "0");
        assert_eq!(format_with_separators(100), "100");
        assert_eq!(format_with_separators(1000), "1,000");
        assert_eq!(format_with_separators(1_234_567), "1,234,567");
    }

    /// Test that `get_i64` returns None when key is missing (no silent fallback)
    ///
    /// This behavior is relied upon by blockchain.rs for protocol constants.
    /// Missing constants like `blocks_per_cycle` should propagate as errors,
    /// not silently use fallback values.
    #[test]
    fn test_get_i64_returns_none_for_missing_key() {
        let json: serde_json::Value = serde_json::json!({
            "blocks_per_cycle": 14400,
            "minimal_block_delay": "6"
        });

        // Present key returns Some
        assert_eq!(json.get_i64("blocks_per_cycle"), Some(14400));

        // String-encoded number also works
        assert_eq!(json.get_i64("minimal_block_delay"), Some(6));

        // Missing key returns None (not a default)
        assert_eq!(json.get_i64("nonexistent_key"), None);

        // Callers should use .context()? to convert None to error, not unwrap_or()
    }
}
