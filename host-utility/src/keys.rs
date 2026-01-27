// Key management operations for Russignol
//
// This module provides unified key management logic used by both
// setup and status commands, including key existence checks, hash retrieval,
// and remote signer connectivity verification.

use crate::constants::SIGNER_URI;
use crate::utils::run_octez_client_command;
use anyhow::Result;

/// Check if a key alias exists in octez-client
///
/// Returns true if the key exists, false otherwise
pub fn check_key_alias_exists(alias: &str, config: &crate::config::RussignolConfig) -> bool {
    let result = run_octez_client_command(&["show", "address", alias, "--show-secret"], config);

    result.is_ok() && result.unwrap().status.success()
}

/// Get the public key hash for a given alias
///
/// Returns the hash (e.g., "tz4...") or an error if not found
pub fn get_key_hash(alias: &str, config: &crate::config::RussignolConfig) -> Result<String> {
    let output = run_octez_client_command(&["show", "address", alias], config)?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse the hash from output like "Hash: tz4..."
    for line in stdout.lines() {
        if let Some(hash_part) = line.strip_prefix("Hash:") {
            return Ok(hash_part.trim().to_string());
        }
    }

    anyhow::bail!("Could not parse key hash from octez-client output")
}

/// Discover BLS keys from the remote signer
///
/// Returns a list of tz4 key hashes available on the signer
pub fn discover_remote_keys(config: &crate::config::RussignolConfig) -> Result<Vec<String>> {
    let output =
        run_octez_client_command(&["list", "known", "remote", "keys", SIGNER_URI], config)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to list remote keys: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    let keys: Vec<String> = stdout
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("tz4"))
        .map(std::string::ToString::to_string)
        .collect();

    Ok(keys)
}

/// Check if the remote signer is accessible and has at least 2 BLS keys
///
/// Returns true if signer is accessible with ≥2 keys, false otherwise
pub fn check_remote_signer(config: &crate::config::RussignolConfig) -> bool {
    match discover_remote_keys(config) {
        Ok(keys) => keys.len() >= 2,
        Err(_) => false,
    }
}

/// Wait for the remote signer to become accessible, showing a spinner while waiting
///
/// This polls `check_remote_signer` until it succeeds (signer accessible with ≥2 keys),
/// displaying progress to the user. If `auto_confirm` is true and the signer isn't
/// immediately available, returns an error. Otherwise prompts the user to retry.
pub fn wait_for_signer(auto_confirm: bool, config: &crate::config::RussignolConfig) -> Result<()> {
    use crate::progress::create_spinner;
    use crate::utils::{info, success, warning};
    use std::time::Duration;

    // Quick check first - if already accessible, return immediately
    if check_remote_signer(config) {
        return Ok(());
    }

    // Not accessible, show spinner and check
    let spinner = create_spinner("Checking signer at 169.254.1.1...");

    // Wait a moment and check again (network might just be slow)
    std::thread::sleep(Duration::from_secs(2));
    if check_remote_signer(config) {
        spinner.finish_and_clear();
        return Ok(());
    }

    spinner.finish_and_clear();

    // Signer not accessible - prompt user
    warning("Remote signer not accessible");
    println!();
    info("Please ensure the Russignol device is connected and the signer is running.");
    info("The signer should respond at tcp://169.254.1.1:7732");

    if auto_confirm {
        anyhow::bail!("Signer not accessible and --yes specified. Cannot proceed automatically.");
    }

    println!();
    let proceed = inquire::Confirm::new("Press Enter when ready to retry, or 'n' to abort")
        .with_default(true)
        .prompt()?;
    if !proceed {
        anyhow::bail!("User aborted");
    }

    // Retry with spinner
    let spinner = create_spinner("Rechecking signer...");

    std::thread::sleep(Duration::from_secs(2));
    let signer_ok = check_remote_signer(config);
    spinner.finish_and_clear();

    if !signer_ok {
        anyhow::bail!(
            "Signer still not accessible. Please check the device connection and try again."
        );
    }

    success("Signer is accessible");
    Ok(())
}

/// Import a key from the remote signer with optional force overwrite
///
/// Handles the common pattern of importing a key and optionally forcing
/// overwrite if the alias already exists.
pub fn import_key_from_signer(
    alias: &str,
    key_hash: &str,
    force: bool,
    config: &crate::config::RussignolConfig,
) -> Result<()> {
    let uri = format!("{SIGNER_URI}/{key_hash}");

    let args: Vec<&str> = if force {
        vec!["import", "secret", "key", alias, &uri, "--force"]
    } else {
        vec!["import", "secret", "key", alias, &uri]
    };

    let result = run_octez_client_command(&args, config)?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        // Check if it's an "already exists" error when not forcing
        if !force
            && (stderr.contains("already")
                || stderr.contains("use --force")
                || stderr.contains("Use --force"))
        {
            anyhow::bail!("alias_exists:{alias}");
        }
        anyhow::bail!("Failed to import key '{alias}': {stderr}");
    }

    Ok(())
}

/// Get the alias for a given address from octez-client
///
/// Returns the alias if found, or the address itself if no alias exists
pub fn get_alias_for_address(
    address: &str,
    config: &crate::config::RussignolConfig,
) -> anyhow::Result<String> {
    let output = run_octez_client_command(&["list", "known", "addresses"], config)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.contains(address)
            && let Some((alias_part, _)) = line.split_once(':')
        {
            return Ok(alias_part.trim().to_string());
        }
    }

    Ok(address.to_string())
}

/// Forget (remove) a key alias from octez-client
///
/// Returns the command output for callers that need to inspect results.
/// Use `let _ = forget_key_alias(...)` to ignore the result.
pub fn forget_key_alias(
    alias: &str,
    config: &crate::config::RussignolConfig,
) -> Result<std::process::Output> {
    run_octez_client_command(&["forget", "address", alias, "--force"], config)
}

/// Rename a key alias locally without contacting the remote signer
///
/// Edits the octez-client wallet files directly to rename an alias.
/// This is necessary during device swap when the connected signer may not
/// have the key being renamed.
///
/// Returns an error if the source alias is not found in the primary wallet file.
///
/// Wallet files modified:
/// - `public_key_hashs`: alias → pkh mapping (required)
/// - `public_keys`: alias → (`pk_uri`, pk option) mapping
/// - `secret_keys`: alias → `sk_uri` mapping
pub fn rename_alias_locally(
    old_alias: &str,
    new_alias: &str,
    config: &crate::config::RussignolConfig,
) -> Result<()> {
    let client_dir = &config.octez_client_dir;

    // Track whether we found the alias in the primary file
    let mut found_in_primary = false;

    // List of wallet files to update (public_key_hashs is primary/required)
    let wallet_files = ["public_key_hashs", "public_keys", "secret_keys"];

    for (idx, filename) in wallet_files.iter().enumerate() {
        let file_path = client_dir.join(filename);

        if !file_path.exists() {
            continue;
        }

        // Read the file
        let content = std::fs::read_to_string(&file_path)
            .map_err(|e| anyhow::anyhow!("Failed to read {filename}: {e}"))?;

        // Parse as JSON array
        let mut entries: Vec<serde_json::Value> = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse {filename}: {e}"))?;

        // FIRST: Remove any existing entry with new_alias (to handle --force-like behavior)
        // This must happen BEFORE rename to avoid accidentally removing our renamed entry
        entries.retain(|entry| entry.get("name").and_then(|n| n.as_str()) != Some(new_alias));

        // THEN: Find and rename the entry
        let mut found = false;
        for entry in &mut entries {
            if let Some(name) = entry.get("name").and_then(|n| n.as_str())
                && name == old_alias
            {
                entry["name"] = serde_json::Value::String(new_alias.to_string());
                found = true;
                break;
            }
        }

        if idx == 0 {
            // First file is public_key_hashs - the primary/required one
            found_in_primary = found;
        }

        if !found {
            // Alias not in this file, skip writing
            continue;
        }

        // Write back with pretty formatting to match octez-client style
        let output = serde_json::to_string_pretty(&entries)
            .map_err(|e| anyhow::anyhow!("Failed to serialize {filename}: {e}"))?;

        std::fs::write(&file_path, output)
            .map_err(|e| anyhow::anyhow!("Failed to write {filename}: {e}"))?;
    }

    // Error if alias was not found in the primary wallet file
    if !found_in_primary {
        anyhow::bail!("Alias '{old_alias}' not found in wallet. Cannot rename to '{new_alias}'.");
    }

    Ok(())
}
