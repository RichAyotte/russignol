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
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "active")
        .unwrap_or(false)
}

/// Check if a command exists in PATH
pub fn command_exists(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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

    /// Get an i64 value by key, returning a default if not found
    fn get_i64_or(&self, key: &str, default: i64) -> i64;

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

    fn get_i64_or(&self, key: &str, default: i64) -> i64 {
        self.get_i64(key).unwrap_or(default)
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
