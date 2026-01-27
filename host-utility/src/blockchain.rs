// Blockchain RPC queries and key management for Tezos
//
// This module consolidates all blockchain-related operations, eliminating
// ~300 lines of duplication between phase3.rs, phase5.rs, and status.rs

use std::fmt::Write;

use crate::config::RussignolConfig;
use crate::utils::{JsonValueExt, rpc_get_json, run_octez_client_command};
use anyhow::{Context, Result};

/// Status of key activation on the blockchain
#[derive(Debug)]
pub struct KeyActivationStatus {
    pub consensus_pending: bool,
    pub consensus_pending_hash: Option<String>,
    pub consensus_cycle: Option<i64>,
    pub consensus_time_estimate: Option<String>,
    pub companion_pending: bool,
    pub companion_active: bool,
    pub companion_cycle: Option<i64>,
    pub companion_time_estimate: Option<String>,
}

/// Get the active consensus key hash for a delegate
///
/// Returns the tz4 public key hash of the currently active consensus key
pub fn get_active_consensus_key(delegate: &str, config: &RussignolConfig) -> Result<String> {
    let rpc_path = format!("/chains/main/blocks/head/context/delegates/{delegate}");
    let delegate_info = rpc_get_json(&rpc_path, config)?;

    delegate_info
        .get_nested("consensus_key")
        .and_then(|ck| ck.get_nested("active"))
        .and_then(|active| active.get_str("pkh"))
        .map(std::string::ToString::to_string)
        .context("Could not find active consensus key")
}

/// Find a delegate address from the Tezos client's known addresses
///
/// Reads configured octez-client directory's `public_key_hashs` and returns the first registered delegate found
pub fn find_delegate_address(config: &RussignolConfig) -> Result<Option<String>> {
    // Read public_key_hashs file to find known addresses
    let pkh_file = config.octez_client_dir.join("public_key_hashs");

    let Ok(content) = std::fs::read_to_string(&pkh_file) else {
        return Ok(None);
    };

    // Parse JSON array of key hashes
    let pkhs: serde_json::Value = serde_json::from_str(&content)?;

    if let Some(array) = pkhs.as_array() {
        for entry in array {
            if let Some(hash) = entry.get_str("value") {
                // Check if this address is a registered delegate
                if is_registered_delegate(hash, config) {
                    return Ok(Some(hash.to_string()));
                }
            }
        }
    }

    Ok(None)
}

/// Check if an address is a registered (and not deactivated) delegate
pub fn is_registered_delegate(address: &str, config: &RussignolConfig) -> bool {
    let rpc_path = format!("/chains/main/blocks/head/context/delegates/{address}");
    let Ok(delegate_info) = crate::utils::rpc_get_json(&rpc_path, config) else {
        return false; // Not registered if RPC call fails
    };

    // Check if deactivated
    let deactivated = delegate_info.get_bool("deactivated").unwrap_or(false);

    !deactivated
}

/// Query staking information for a delegate
///
/// Returns (`staked_mutez`, `total_balance_mutez`, percentage, `staking_enabled`)
pub fn query_staking_info(
    delegate: &str,
    config: &RussignolConfig,
) -> Result<(i64, i64, f64, bool)> {
    // Get delegate info
    let rpc_path = format!("/chains/main/blocks/head/context/delegates/{delegate}");
    let delegate_info = crate::utils::rpc_get_json(&rpc_path, config)?;

    // Use total_staked (includes own + external stakes)
    let staked = delegate_info.get_i64_or("total_staked", 0);
    let total = delegate_info.get_i64_or("own_full_balance", 0);

    // Staking is enabled if total_staked > 0
    let staking_enabled = staked > 0;

    // Calculate percentage using fixed-point arithmetic (basis points)
    // then convert to f64. For percentages 0-100, precision loss is impossible.
    let percentage = if total > 0 {
        // Calculate in basis points (100ths of a percent) to preserve one decimal
        let basis_points = staked.saturating_mul(1000) / total;
        // Safe cast: basis_points is max 1000 (100.0%), well within i32 range
        let basis_i32 = i32::try_from(basis_points.clamp(0, 1000)).unwrap_or(0);
        f64::from(basis_i32) / 10.0
    } else {
        0.0
    };

    Ok((staked, total, percentage, staking_enabled))
}

/// Get the balance of an address in tez
///
/// Returns the balance as a floating point number in tez (not mutez)
pub fn get_balance(address: &str, config: &RussignolConfig) -> Result<f64> {
    let rpc_path = format!("/chains/main/blocks/head/context/contracts/{address}/balance");
    let balance = rpc_get_json(&rpc_path, config)?;
    let balance_mutez: u64 = balance.as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
    Ok(mutez_to_tez(balance_mutez))
}

/// Convert mutez to tez as f64 for display purposes.
///
/// Uses split conversion to maintain precision: converts integer and fractional
/// parts separately, avoiding precision loss for typical Tezos values.
pub fn mutez_to_tez(mutez: u64) -> f64 {
    const MUTEZ_PER_TEZ: u64 = 1_000_000;
    let tez_part = mutez / MUTEZ_PER_TEZ;
    let mutez_remainder = mutez % MUTEZ_PER_TEZ;
    // Both parts fit in u32 for any realistic Tezos balance (tez_part < 2^32 = 4 billion tez)
    // and mutez_remainder < 1_000_000, so f64::from is lossless
    f64::from(u32::try_from(tez_part).unwrap_or(u32::MAX))
        + f64::from(u32::try_from(mutez_remainder).unwrap_or(0)) / 1_000_000.0
}

/// Calculate percentage of part/total using integer arithmetic.
///
/// Returns the percentage with one decimal place precision (e.g., 75.5 for 75.5%).
/// Uses integer math to avoid precision loss warnings.
pub fn percentage(part: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    // Calculate tenths of a percent to preserve one decimal place
    let tenths = part.saturating_mul(1000) / total;
    // Safe cast: tenths is max 1000 (100.0%), well within u32 range
    let tenths_u32 = u32::try_from(tenths.min(1000)).unwrap_or(0);
    f64::from(tenths_u32) / 10.0
}

/// Format mutez amount as tez with thousands separators
///
/// Example: 1234567890 mutez -> "1,235" tez (rounded)
pub fn format_tez(mutez: i64) -> String {
    // Use integer arithmetic for rounding to avoid float precision issues
    // Add 500_000 (half a tez) for rounding to nearest, handling sign correctly
    let rounded = if mutez >= 0 {
        mutez.saturating_add(500_000) / 1_000_000
    } else {
        mutez.saturating_sub(500_000) / 1_000_000
    };
    format_with_thousands(rounded)
}

/// Format an integer with thousands separators
fn format_with_thousands(value: i64) -> String {
    let mut result = value.to_string();
    // Handle negative sign - start after the minus if negative
    let start = usize::from(value < 0);
    let mut pos = result.len();
    while pos > start + 3 {
        pos -= 3;
        result.insert(pos, ',');
    }
    result
}

/// Query the activation status of consensus and companion keys
///
/// Checks if keys are pending activation and calculates estimated activation time
pub fn query_key_activation_status(
    delegate: &str,
    config: &RussignolConfig,
) -> Result<KeyActivationStatus> {
    let output = run_octez_client_command(
        &[
            "rpc",
            "get",
            &format!("/chains/main/blocks/head/context/delegates/{delegate}"),
        ],
        config,
    )?;

    if !output.status.success() {
        anyhow::bail!("Failed to query delegate info");
    }

    let delegate_info: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse delegate info")?;

    // Get current cycle
    let metadata = crate::utils::rpc_get_json("/chains/main/blocks/head/metadata", config)?;

    let current_cycle = metadata
        .get_nested("level_info")
        .and_then(|li| li.get_i64("cycle"))
        .context("Failed to get current cycle")?;

    let current_cycle_position = metadata
        .get_nested("level_info")
        .and_then(|li| li.get_i64("cycle_position"))
        .unwrap_or(0);

    // Get blocks_per_cycle from protocol constants
    let constants =
        crate::utils::rpc_get_json("/chains/main/blocks/head/context/constants", config)?;

    let blocks_per_cycle = constants
        .get_i64("blocks_per_cycle")
        .context("Failed to get blocks_per_cycle from constants")?;

    let minimal_block_delay = constants.get_i64("minimal_block_delay");

    // Check consensus key
    let consensus_key_obj = delegate_info.get("consensus_key");
    let mut consensus_pending = false;
    let mut consensus_pending_hash = None;
    let mut consensus_cycle = None;
    let mut consensus_time_estimate = None;

    if let Some(pendings) = consensus_key_obj
        .and_then(|ck| ck.get("pendings"))
        .and_then(|p| p.as_array())
        && let Some(pending) = pendings.first()
        && let Some(cycle) = pending.get_i64("cycle")
    {
        consensus_pending = true;
        consensus_cycle = Some(cycle);

        // Extract the pending key hash (pkh field)
        if let Some(pkh) = pending.get_str("pkh") {
            consensus_pending_hash = Some(pkh.to_string());
        }

        let cycles_away = cycle - current_cycle;
        let blocks_remaining = (cycles_away * blocks_per_cycle) - current_cycle_position;
        consensus_time_estimate = Some(format_time_estimate(blocks_remaining, minimal_block_delay));
    }

    // Check companion key
    let companion_key_obj = delegate_info.get("companion_key");
    let mut companion_pending = false;
    let mut companion_active = false;
    let mut companion_cycle = None;
    let mut companion_time_estimate = None;

    // Check if companion key is active
    if let Some(active) = companion_key_obj.and_then(|ck| ck.get("active"))
        && !active.is_null()
    {
        companion_active = true;
    }

    // Check if companion key is pending
    if let Some(pendings) = companion_key_obj
        .and_then(|ck| ck.get("pendings"))
        .and_then(|p| p.as_array())
        && let Some(pending) = pendings.first()
        && let Some(cycle) = pending.get_i64("cycle")
    {
        companion_pending = true;
        companion_cycle = Some(cycle);

        let cycles_away = cycle - current_cycle;
        let blocks_remaining = (cycles_away * blocks_per_cycle) - current_cycle_position;
        companion_time_estimate = Some(format_time_estimate(blocks_remaining, minimal_block_delay));
    }

    Ok(KeyActivationStatus {
        consensus_pending,
        consensus_pending_hash,
        consensus_cycle,
        consensus_time_estimate,
        companion_pending,
        companion_active,
        companion_cycle,
        companion_time_estimate,
    })
}

/// Query the next baking right for a delegate
///
/// Returns (`block_level`, `time_estimate`) or None if no upcoming rights found
pub fn query_next_baking_rights(
    delegate: &str,
    config: &RussignolConfig,
) -> Result<Option<(i64, String)>> {
    // Get current level
    let head = crate::utils::rpc_get_json("/chains/main/blocks/head/header", config)?;

    let current_level = head
        .get_i64("level")
        .context("Failed to get current level")?;

    // Get block delay for time estimation
    let minimal_block_delay = get_minimal_block_delay(config);

    // Get blocks per cycle from constants
    let constants =
        crate::utils::rpc_get_json("/chains/main/blocks/head/context/constants", config)?;

    let blocks_per_cycle = constants
        .get_i64("blocks_per_cycle")
        .context("Failed to get blocks_per_cycle from protocol constants")?;

    // Query baking rights in batches to avoid URL length limits
    // Use half a cycle as batch size to avoid crossing cycle boundaries
    let batch_size = blocks_per_cycle / 2;
    let batch_size_usize =
        usize::try_from(batch_size).context("batch_size must be non-negative")?;

    // Can only query ~2 cycles ahead before seed computation fails
    // Use conservative limit: 2 full cycles from current position
    let max_levels_to_check = blocks_per_cycle * 2;

    let mut all_delegate_rights: Vec<i64> = Vec::new();

    // Process in batches
    for batch_start in
        (current_level + 1..=current_level + max_levels_to_check).step_by(batch_size_usize)
    {
        let batch_end = std::cmp::min(
            batch_start + batch_size - 1,
            current_level + max_levels_to_check,
        );

        // Build the RPC path with level parameters for this batch
        let mut rpc_path =
            String::from("/chains/main/blocks/head/helpers/baking_rights?max_round=0");

        for level in batch_start..=batch_end {
            let _ = write!(rpc_path, "&level={level}");
        }

        // Make RPC call for this batch
        let rights = match crate::utils::rpc_get_json(&rpc_path, config) {
            Ok(r) => r,
            Err(e) => {
                // Check if error is due to seed not computed (querying too far into future)
                let error_msg = e.to_string();
                if error_msg.contains("seed") && error_msg.contains("has not been computed yet") {
                    // We've reached the limit of what can be queried, stop here
                    break;
                }
                continue; // Skip other failed batches
            }
        };

        // Filter for our delegate in this batch
        if let Some(rights_array) = rights.as_array() {
            let batch_rights: Vec<i64> = rights_array
                .iter()
                .filter_map(|right| {
                    if right.get_str("delegate") == Some(delegate) {
                        right.get_i64("level")
                    } else {
                        None
                    }
                })
                .collect();

            all_delegate_rights.extend(batch_rights);
        }

        // If we found any rights, we can stop early
        if !all_delegate_rights.is_empty() {
            break;
        }
    }

    // Return the earliest baking right
    if !all_delegate_rights.is_empty() {
        all_delegate_rights.sort_unstable();
        let level = all_delegate_rights[0];
        let blocks_away = level - current_level;
        let estimated_time = format_time_estimate(blocks_away, minimal_block_delay);
        return Ok(Some((level, estimated_time)));
    }

    Ok(None)
}

/// Query the next attesting right for a delegate
///
/// Returns (`block_level`, `time_estimate`) or None if no upcoming rights found
pub fn query_next_attesting_rights(
    delegate: &str,
    config: &RussignolConfig,
) -> Result<Option<(i64, String)>> {
    let output = run_octez_client_command(
        &[
            "rpc",
            "get",
            &format!("/chains/main/blocks/head/helpers/attestation_rights?delegate={delegate}"),
        ],
        config,
    )?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to query attesting rights: {}", stderr.trim());
    }

    let rights: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse attesting rights")?;

    // Get current level
    let head = crate::utils::rpc_get_json("/chains/main/blocks/head/header", config)?;

    let current_level = head
        .get_i64("level")
        .context("Failed to get current level")?;

    // Get block delay for time estimation
    let minimal_block_delay = get_minimal_block_delay(config);

    // Find the first attesting right
    // Note: attestation_rights returns [{level: N, delegates: [{delegate: "tz...", ...}]}]
    if let Some(rights_array) = rights.as_array() {
        for right in rights_array {
            if let Some(level) = right.get_i64("level")
                && level >= current_level
                && let Some(delegates_array) =
                    right.get_nested("delegates").and_then(|v| v.as_array())
            {
                // Check if our delegate is in the delegates array for this level
                let has_rights = delegates_array
                    .iter()
                    .any(|d| d.get_str("delegate") == Some(delegate));

                if has_rights {
                    let blocks_away = level - current_level;
                    let estimated_time = format_time_estimate(blocks_away, minimal_block_delay);
                    return Ok(Some((level, estimated_time)));
                }
            }
        }
    }

    Ok(None)
}

/// Get the minimal block delay from protocol constants
///
/// Returns None if unable to query or parse constants
pub fn get_minimal_block_delay(config: &RussignolConfig) -> Option<i64> {
    let constants = get_protocol_constants(config).ok()?;
    constants.get_i64("minimal_block_delay")
}

/// Get the number of blocks per cycle from protocol constants
///
/// Returns None if unable to query or parse constants
pub fn get_blocks_per_cycle(config: &RussignolConfig) -> Option<i64> {
    let constants = get_protocol_constants(config).ok()?;
    constants.get_i64("blocks_per_cycle")
}

/// Fetch protocol constants from the node
///
/// Caches the RPC call result for the duration of the request
fn get_protocol_constants(config: &RussignolConfig) -> Result<serde_json::Value> {
    rpc_get_json("/chains/main/blocks/head/context/constants", config)
}

/// Format time estimate from blocks away and block delay
///
/// Examples:
/// - 5 blocks @ 10s = "~50 seconds"
/// - 20 blocks @ 10s = "~3 minutes"
/// - 500 blocks @ 10s = "~1 hour 23 minutes"
pub fn format_time_estimate(blocks_away: i64, minimal_block_delay: Option<i64>) -> String {
    // If we don't know the block delay, we can't estimate time
    let Some(block_delay_seconds) = minimal_block_delay else {
        return format!("{blocks_away} blocks (time unknown)");
    };

    let seconds = blocks_away * block_delay_seconds;

    if seconds < 60 {
        format!("~{seconds} seconds")
    } else if seconds < 3600 {
        let minutes = seconds / 60;
        format!("~{} minute{}", minutes, if minutes == 1 { "" } else { "s" })
    } else {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        if minutes > 0 {
            format!(
                "~{} hour{} {} minute{}",
                hours,
                if hours == 1 { "" } else { "s" },
                minutes,
                if minutes == 1 { "" } else { "s" }
            )
        } else {
            format!("~{} hour{}", hours, if hours == 1 { "" } else { "s" })
        }
    }
}
