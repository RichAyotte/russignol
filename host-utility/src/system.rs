// System configuration checks and validation
//
// This module provides unified system validation logic used by both
// setup and status commands, including dependency checks, node verification,
// and user group membership.

use crate::utils::{JsonValueExt, dir_exists, file_exists, info, run_command, success, warning};
use anyhow::{Context, Result};

/// Verify that octez-node is accessible and synced
///
/// Checks RPC responsiveness and sync status via timestamp comparison.
pub fn verify_octez_node(config: &crate::config::RussignolConfig) -> Result<()> {
    // Check RPC responsiveness
    crate::utils::rpc_get_json("/version", config).with_context(|| {
        format!(
            "octez-node RPC is not responsive{}",
            crate::network::NON_INTERACTIVE_HINT
        )
    })?;

    // Check sync status
    let head_json = crate::utils::rpc_get_json("/chains/main/blocks/head/header/shell", config)
        .context("Failed to get blockchain head")?;

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

    // The node just answered a health check, so a header read that fails now is
    // an anomaly worth surfacing, not a silent "height unknown".
    let header = crate::utils::rpc_get_json("/chains/main/blocks/head/header", config)
        .context("Failed to read node block header after a successful health check")?;

    Ok(header.get_i64("level"))
}

/// How `wait_for_node_sync` should react to a `verify_octez_node` error.
#[derive(Debug, PartialEq, Eq)]
enum NodeWait {
    /// Node is up but still catching up — keep waiting indefinitely.
    Syncing,
    /// Node is not reachable — a real error, stop waiting.
    Down,
    /// Unrecognized failure — wait, but only for a bounded number of rounds.
    Unknown,
}

fn classify_node_wait(err_msg: &str) -> NodeWait {
    if err_msg.contains("not synced") {
        NodeWait::Syncing
    } else if err_msg.contains("not responsive") || err_msg.contains("Cannot find") {
        NodeWait::Down
    } else {
        NodeWait::Unknown
    }
}

/// Wait for the node to be fully synced, showing a spinner while waiting
///
/// This polls `verify_octez_node` until it succeeds (node is running and synced),
/// displaying progress to the user. Useful before operations that require a synced node.
pub fn wait_for_node_sync(config: &crate::config::RussignolConfig) -> Result<()> {
    use crate::progress::create_spinner;
    use std::time::Duration;

    // An unrecognized error may be transient, but it must not loop forever
    // silently: give up after this many consecutive unknown failures.
    const MAX_UNKNOWN_RETRIES: u32 = 12;

    // Quick check first - if already synced, return immediately
    if verify_octez_node(config).is_ok() {
        return Ok(());
    }

    // Not synced, show spinner and wait
    let spinner = create_spinner("Waiting for node to sync...");

    let mut unknown_retries: u32 = 0;

    loop {
        match verify_octez_node(config) {
            Ok(()) => {
                spinner.finish_and_clear();
                return Ok(());
            }
            Err(e) => match classify_node_wait(&e.to_string()) {
                NodeWait::Syncing => {
                    unknown_retries = 0;
                    std::thread::sleep(Duration::from_secs(5));
                }
                NodeWait::Down => {
                    // Node not running - this is a real error
                    spinner.finish_and_clear();
                    return Err(e);
                }
                NodeWait::Unknown => {
                    unknown_retries += 1;
                    if unknown_retries >= MAX_UNKNOWN_RETRIES {
                        spinner.finish_and_clear();
                        return Err(e).context(format!(
                            "Node health check kept failing for an unrecognized reason \
                             after {MAX_UNKNOWN_RETRIES} attempts"
                        ));
                    }
                    log::debug!("Node sync check failed: {e}");
                    std::thread::sleep(Duration::from_secs(5));
                }
            },
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

/// Check if the current user is in the plugdev group per the group database
///
/// This is required for USB device access without root privileges
pub fn check_plugdev_membership() -> Result<(bool, String)> {
    let username = std::env::var("USER").context("USER environment variable not set")?;

    // Get user's groups. A non-zero exit yields empty stdout, which would read
    // as "not in plugdev" — surface the failure instead of a false negative.
    let output = run_command("groups", &[&username])?;
    if !output.status.success() {
        anyhow::bail!(
            "`groups {username}` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let groups = String::from_utf8_lossy(&output.stdout);

    let in_group = groups.split_whitespace().any(|g| g == "plugdev");
    Ok((in_group, username))
}

/// Whether plugdev is active in this process's session credentials.
///
/// `None` when the group cannot be resolved, so callers never claim
/// inactivity they could not verify.
fn plugdev_active_in_session() -> Option<bool> {
    use nix::unistd::{Group, getegid, getgroups};

    let gid = Group::from_name("plugdev").ok().flatten()?.gid;
    let mut gids = getgroups().ok()?;
    gids.push(getegid());
    Some(gids.contains(&gid))
}

/// The advice appropriate for the user's plugdev membership state.
///
/// `usermod` may only be suggested when the group database verifiably lacks
/// the membership; a member whose session is stale needs a re-login, not a
/// second usermod.
#[derive(Debug, PartialEq, Eq)]
enum PlugdevAdvice {
    Ok,
    ReloginNeeded,
    JoinGroup,
}

fn plugdev_advice(in_db: bool, in_session: Option<bool>) -> PlugdevAdvice {
    match (in_db, in_session) {
        (true, Some(false)) => PlugdevAdvice::ReloginNeeded,
        (true, _) => PlugdevAdvice::Ok,
        (false, _) => PlugdevAdvice::JoinGroup,
    }
}

/// Check plugdev membership and display appropriate warning
///
/// Used by setup command (displays warning message)
pub fn check_plugdev_with_warning() -> Result<()> {
    let (in_db, username) = check_plugdev_membership()?;

    match plugdev_advice(in_db, plugdev_active_in_session()) {
        PlugdevAdvice::Ok => {
            success(&format!("User '{username}' is in the 'plugdev' group"));
        }
        PlugdevAdvice::ReloginNeeded => {
            warning(&format!(
                "User '{username}' is in the 'plugdev' group, but this login session \
                 started before the membership was added."
            ));
            info("Log out completely (or reboot) and log back in to activate it.");
        }
        PlugdevAdvice::JoinGroup => {
            warning(&format!(
                "User '{username}' is not in the 'plugdev' group. Device access may be limited."
            ));
            info(&format!(
                "To add user to plugdev group, run: sudo usermod -aG plugdev {username}"
            ));
            info("You will need to log out and log back in for the change to take effect.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_node_wait_distinguishes_syncing_down_and_unknown() {
        assert_eq!(
            classify_node_wait(
                "octez-node is running but not synced. Last block is 9 minutes old."
            ),
            NodeWait::Syncing
        );
        assert_eq!(
            classify_node_wait("octez-node RPC is not responsive"),
            NodeWait::Down
        );
        assert_eq!(
            classify_node_wait("Cannot find the node data directory"),
            NodeWait::Down
        );
        assert_eq!(
            classify_node_wait("connection reset by peer"),
            NodeWait::Unknown
        );
    }

    #[test]
    fn active_member_needs_no_advice() {
        assert_eq!(plugdev_advice(true, Some(true)), PlugdevAdvice::Ok);
    }

    #[test]
    fn db_member_with_stale_session_needs_relogin_not_usermod() {
        assert_eq!(
            plugdev_advice(true, Some(false)),
            PlugdevAdvice::ReloginNeeded
        );
    }

    #[test]
    fn unverifiable_session_state_never_alarms_a_db_member() {
        assert_eq!(plugdev_advice(true, None), PlugdevAdvice::Ok);
    }

    #[test]
    fn only_verified_non_members_are_told_to_join() {
        assert_eq!(plugdev_advice(false, Some(false)), PlugdevAdvice::JoinGroup);
        assert_eq!(plugdev_advice(false, None), PlugdevAdvice::JoinGroup);
    }
}
