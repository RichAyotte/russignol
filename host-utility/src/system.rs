// System configuration checks and validation
//
// This module provides unified system validation logic used by both
// setup and status commands, including dependency checks, node verification,
// and user group membership.

use crate::constants::REQUIRED_COMMANDS;
use crate::utils::{
    JsonValueExt, command_exists, dir_exists, file_exists, info, run_command,
    run_octez_client_command, success, warning,
};
use anyhow::{Context, Result};

/// Verify that all required system dependencies are installed
///
/// Checks for: octez-client, octez-node, ps, grep, ip, ping, udevadm, lsusb
pub fn verify_dependencies() -> Result<()> {
    let mut missing = Vec::new();

    for cmd in REQUIRED_COMMANDS {
        if !command_exists(cmd) {
            missing.push(*cmd);
        }
    }

    if !missing.is_empty() {
        anyhow::bail!(
            "Missing required dependencies: {}\nPlease install these tools before running this utility.",
            missing.join(", ")
        );
    }

    Ok(())
}

/// Verify that octez-node is running, accessible, and synced
///
/// Checks via systemd service, process table, RPC responsiveness, and sync status
pub fn verify_octez_node(config: &crate::config::RussignolConfig) -> Result<()> {
    // Primary: Check systemd service
    let is_active_via_systemd = if command_exists("systemctl") {
        let output = run_command("systemctl", &["is-active", "octez-node.service"]);
        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.trim() == "active"
        } else {
            false
        }
    } else {
        false
    };

    // Secondary: Check process table
    let is_running = if is_active_via_systemd {
        true
    } else {
        let output = run_command("pgrep", &["-f", "octez-node"]);
        if let Ok(output) = output {
            output.status.success() && !output.stdout.is_empty()
        } else {
            // Fallback to ps + grep
            let output = run_command("ps", &["aux"])?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout
                .lines()
                .any(|line| line.contains("octez-node") && !line.contains("grep"))
        }
    };

    if !is_running {
        anyhow::bail!("Cannot find a running octez-node process. Please ensure it is started.");
    }

    // Tertiary: Check RPC responsiveness
    crate::utils::rpc_get_json("/version", config).context("octez-node RPC is not responsive")?;

    // Check sync status
    let head_output = run_octez_client_command(
        &["rpc", "get", "/chains/main/blocks/head/header/shell"],
        config,
    )
    .context("Failed to get blockchain head")?;

    if !head_output.status.success() {
        anyhow::bail!(
            "Failed to query blockchain head: {}",
            String::from_utf8_lossy(&head_output.stderr)
        );
    }

    let head_json: serde_json::Value = serde_json::from_slice(&head_output.stdout)
        .context("Failed to parse blockchain head JSON")?;

    if let Some(timestamp_str) = head_json.get_str("timestamp") {
        let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
            .context("Failed to parse block timestamp")?;
        let now = chrono::Utc::now();
        let diff = now.signed_duration_since(timestamp);

        if diff > chrono::Duration::minutes(5) {
            let total_minutes = diff.num_minutes();
            let days = total_minutes / (24 * 60);
            let hours = (total_minutes % (24 * 60)) / 60;
            let minutes = total_minutes % 60;

            let time_str = if days > 0 {
                format!(
                    "{} day{}, {} hour{}, {} minute{}",
                    days,
                    if days == 1 { "" } else { "s" },
                    hours,
                    if hours == 1 { "" } else { "s" },
                    minutes,
                    if minutes == 1 { "" } else { "s" }
                )
            } else if hours > 0 {
                format!(
                    "{} hour{}, {} minute{}",
                    hours,
                    if hours == 1 { "" } else { "s" },
                    minutes,
                    if minutes == 1 { "" } else { "s" }
                )
            } else {
                format!("{} minute{}", minutes, if minutes == 1 { "" } else { "s" })
            };

            anyhow::bail!(
                "octez-node is running but not synced. Last block is {time_str} old. Please wait for sync to complete."
            );
        }
    }

    Ok(())
}

/// Get the current block height from the octez-node
///
/// Returns Ok(Some(height)) if successful, Ok(None) if unable to query
pub fn get_node_block_height(config: &crate::config::RussignolConfig) -> Result<Option<i64>> {
    // First verify node is running and synced
    verify_octez_node(config)?;

    // Get current block level
    let Ok(header) = crate::utils::rpc_get_json("/chains/main/blocks/head/header", config) else {
        return Ok(None);
    };
    let level = header.get_i64("level");

    Ok(level)
}

/// Wait for the node to be fully synced, showing a spinner while waiting
///
/// This polls `verify_octez_node` until it succeeds (node is running and synced),
/// displaying progress to the user. Useful before operations that require a synced node.
pub fn wait_for_node_sync(config: &crate::config::RussignolConfig) -> Result<()> {
    use crate::progress::create_spinner;
    use std::time::Duration;

    // Quick check first - if already synced, return immediately
    if verify_octez_node(config).is_ok() {
        return Ok(());
    }

    // Not synced, show spinner and wait
    let spinner = create_spinner("Waiting for node to sync...");

    loop {
        match verify_octez_node(config) {
            Ok(()) => {
                spinner.finish_and_clear();
                return Ok(());
            }
            Err(e) => {
                // Check if it's a sync issue (expected) vs other error (bail)
                let err_msg = e.to_string();
                if err_msg.contains("not synced") {
                    // Still syncing, continue waiting
                    std::thread::sleep(Duration::from_secs(5));
                } else if err_msg.contains("not responsive") || err_msg.contains("Cannot find") {
                    // Node not running - this is a real error
                    spinner.finish_and_clear();
                    return Err(e);
                } else {
                    // Unknown error, keep waiting but log it
                    log::debug!("Node sync check failed: {e}");
                    std::thread::sleep(Duration::from_secs(5));
                }
            }
        }
    }
}

/// Verify that the octez-client directory exists and is properly initialized
///
/// Checks configured octez-client directory and required files (`public_keys`, `secret_keys`, `public_key_hashs`)
pub fn verify_octez_client_directory(config: &crate::config::RussignolConfig) -> Result<()> {
    // Use configured octez-client directory
    let client_dir = &config.octez_client_dir;

    if !dir_exists(client_dir) {
        anyhow::bail!(
            "octez-client directory not found at {}. Please initialize octez-client first.",
            client_dir.display()
        );
    }

    // Check for required key files
    let required_files = vec!["public_keys", "secret_keys", "public_key_hashs"];

    for file in required_files {
        let file_path = client_dir.join(file);
        if !file_exists(&file_path) {
            anyhow::bail!(
                "Required file {} not found in octez-client directory. This indicates a malformed or non-existent client setup.",
                file_path.display()
            );
        }
    }

    Ok(())
}

/// Check if the current user is in the plugdev group
///
/// This is required for USB device access without root privileges
pub fn check_plugdev_membership() -> Result<(bool, String)> {
    let username = std::env::var("USER").context("USER environment variable not set")?;

    // Get user's groups
    let output = run_command("groups", &[&username])?;
    let groups = String::from_utf8_lossy(&output.stdout);

    let in_group = groups.contains("plugdev");
    Ok((in_group, username))
}

/// Check plugdev membership and display appropriate warning
///
/// Used by setup command (displays warning message)
pub fn check_plugdev_with_warning() -> Result<()> {
    let (in_group, username) = check_plugdev_membership()?;

    if in_group {
        success(&format!("User '{username}' is in the 'plugdev' group"));
    } else {
        warning(&format!(
            "User '{username}' is not in the 'plugdev' group. Device access may be limited."
        ));
        info(&format!(
            "To add user to plugdev group, run: sudo usermod -aG plugdev {username}"
        ));
        info("You will need to log out and log back in for the change to take effect.");
    }

    Ok(())
}
