// Key management operations for Russignol
//
// This module provides unified key management logic used by both
// setup and status commands, including key existence checks, hash retrieval,
// and remote signer connectivity verification.

use crate::utils::run_octez_client_command;
use anyhow::Result;
use russignol_signer_lib::KeyRole;

/// Classify a `show address` result into present, absent, or indeterminate.
///
/// `Some(true)` = the alias resolved, `Some(false)` = the client ran and said
/// no such alias, `None` = a non-zero exit for some other reason (the probe
/// could not decide). Kept pure so the three-way decision is unit-testable.
fn classify_alias_probe(status_success: bool, stderr: &str) -> Option<bool> {
    if status_success {
        Some(true)
    } else if stderr.contains(NO_SUCH_ALIAS) {
        Some(false)
    } else {
        None
    }
}

/// Check whether a key alias exists in octez-client.
///
/// `Ok(true)` = present, `Ok(false)` = the client ran and reported no such
/// alias, `Err` = the probe itself could not run or gave an indeterminate
/// failure. Keeping the probe failure distinct from a genuine absence lets
/// callers avoid reporting "not imported" for a wallet whose state is unknown.
pub fn check_key_alias_exists(
    alias: &str,
    config: &crate::config::RussignolConfig,
) -> Result<bool> {
    let output = run_octez_client_command(&["show", "address", alias, "--show-secret"], config)?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    classify_alias_probe(output.status.success(), &stderr).ok_or_else(|| {
        anyhow::anyhow!(
            "Could not determine whether alias '{alias}' exists: {}",
            stderr.trim()
        )
    })
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

/// Discover the remote signer's keys, in device-key order.
///
/// Returns addresses with `[DeviceKey::index()]` naming the key: `[0]` = the
/// BLS consensus key, `[1]` = the BLS companion key, `[2]` = the XMSS consensus
/// key where the card holds one. `[KeyRole::index()]` therefore names the BLS
/// key in that role.
///
/// **Position is the only channel for that mapping, and this side cannot check
/// it.** The signer's `KnownKeys` response is a bare pkh list carrying no
/// aliases, so the role of each hash is knowable only from its ordinal. The
/// chain is: the device's `KeyManager::list_keys()` emits `DeviceKey::ALL`
/// order, the wire codec preserves list order, and `octez-client list known
/// remote keys` is assumed to print in the order it received. That last link is
/// octez-client's behaviour, not ours — if it ever sorted or regrouped its
/// output, every caller would silently swap the roles. Any caller that could
/// verify a hash's role by another route should.
pub fn discover_remote_keys(config: &crate::config::RussignolConfig) -> Result<Vec<String>> {
    let signer_uri = config.signer_uri();
    let output =
        run_octez_client_command(&["list", "known", "remote", "keys", signer_uri], config)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to list remote keys: {stderr}");
    }

    Ok(remote_keys_in_listing(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// The addresses in a `list known remote keys` listing, one a line, of the
/// schemes the device signs under; every other line is client chatter.
fn remote_keys_in_listing(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| russignol_signer_lib::PublicKeyHash::from_b58check(line).is_ok())
        .map(std::string::ToString::to_string)
        .collect()
}

/// Check if the remote signer is accessible and holds a BLS key for every role
///
/// Returns true if the signer is reachable with at least [`KeyRole::COUNT`]
/// keys, false otherwise
pub fn check_remote_signer(config: &crate::config::RussignolConfig) -> bool {
    match discover_remote_keys(config) {
        Ok(keys) => keys.len() >= KeyRole::COUNT,
        Err(_) => false,
    }
}

/// Check whether the connected remote signer holds a specific key.
///
/// Round-trips to the device via [`discover_remote_keys`], so the `Err` case
/// (signer unreachable) is distinct from `Ok(false)` (signer reachable but
/// does not hold `expected_hash`). Callers that need to distinguish "wrong or
/// absent device" from "right device, wrong key" rely on that distinction.
pub fn signer_holds_key(
    expected_hash: &str,
    config: &crate::config::RussignolConfig,
) -> Result<bool> {
    let keys = discover_remote_keys(config)?;
    Ok(keys.iter().any(|k| k == expected_hash))
}

/// How long a signer that did not answer at once is asked for, and how often.
/// One value rather than two durations, so a caller cannot hand the window
/// over as the interval.
#[derive(Clone, Copy)]
struct Polling {
    window: std::time::Duration,
    every: std::time::Duration,
}

/// A device plugged in moments ago is still enumerating its USB gadget link,
/// which is what the window absorbs.
const SIGNER_POLLING: Polling = Polling {
    window: std::time::Duration::from_secs(2),
    every: std::time::Duration::from_millis(250),
};

/// Ask `probe` for the signer's keys every `polling.every` until it answers or
/// `polling.window` runs out, so a signer that comes up early is not waited on
/// for the whole window and one that never comes up is given the whole of it.
/// The first ask comes an interval in, since the caller has just asked and been
/// refused.
fn poll_for_keys(
    mut probe: impl FnMut() -> Option<Vec<String>>,
    polling: Polling,
) -> Option<Vec<String>> {
    let deadline = std::time::Instant::now() + polling.window;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return None;
        }
        std::thread::sleep(polling.every.min(left));
        if let Some(keys) = probe() {
            return Some(keys);
        }
    }
}

/// Wait for the remote signer to answer with a key per role, showing a spinner
/// while waiting.
///
/// Asks through [`discover_remote_keys`] for [`SIGNER_POLLING`]'s window. If
/// `auto_confirm` is true and the signer has not answered by then, returns an
/// error; otherwise prompts the user and asks for the same window again.
pub fn wait_for_signer(
    auto_confirm: bool,
    config: &crate::config::RussignolConfig,
) -> Result<Vec<String>> {
    use crate::progress::create_spinner;
    use crate::utils::{info, success, warning};

    let probe = || {
        discover_remote_keys(config)
            .ok()
            .filter(|keys| keys.len() >= KeyRole::COUNT)
    };

    if let Some(keys) = probe() {
        return Ok(keys);
    }

    let signer_uri = config.signer_uri();
    let spinner = create_spinner(&format!("Checking signer at {}...", config.signer_ip()));

    if let Some(keys) = poll_for_keys(probe, SIGNER_POLLING) {
        spinner.finish_and_clear();
        return Ok(keys);
    }

    spinner.finish_and_clear();

    // Signer not accessible - prompt user
    warning("Remote signer not accessible");
    println!();
    info("Please ensure the Russignol device is connected and the signer is running.");
    info(&format!("The signer should respond at {signer_uri}"));

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

    let keys = poll_for_keys(probe, SIGNER_POLLING);
    spinner.finish_and_clear();

    match keys {
        Some(keys) => {
            success("Signer is accessible");
            Ok(keys)
        }
        None => {
            anyhow::bail!(
                "Signer still not accessible. Please check the device connection and try again."
            );
        }
    }
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
    let signer_uri = config.signer_uri();
    let uri = format!("{signer_uri}/{key_hash}");

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

/// octez-client stderr fragment emitted when the alias is already absent.
const NO_SUCH_ALIAS: &str = "no public key hash alias named";

/// Decide whether a `forget address` invocation left the alias gone.
///
/// A non-zero exit whose stderr only says the alias was already absent is a
/// success for our purposes (the desired end state — no such alias — holds).
fn forget_alias_ok(status_success: bool, stderr: &str) -> bool {
    status_success || stderr.contains(NO_SUCH_ALIAS)
}

/// Forget (remove) a key alias from octez-client.
///
/// Errors when the command fails for any reason other than the alias already
/// being absent, so a swallowed failure can no longer masquerade as a clean
/// removal.
pub fn forget_key_alias(alias: &str, config: &crate::config::RussignolConfig) -> Result<()> {
    let output = run_octez_client_command(&["forget", "address", alias, "--force"], config)?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if forget_alias_ok(output.status.success(), &stderr) {
        Ok(())
    } else {
        anyhow::bail!("Failed to forget alias '{alias}': {}", stderr.trim())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_signer_lib::{PublicKeyHash, Scheme, base58check};

    /// Every address of a scheme the device signs under is kept in the order
    /// the client printed it, since position is what names the key; a line of
    /// anything else, another scheme's address included, is not a key.
    #[test]
    fn a_listing_yields_each_device_scheme_in_order() {
        let address = |scheme, byte| {
            PublicKeyHash::from_bytes(scheme, &[byte; 20])
                .expect("twenty bytes are an address")
                .to_b58check()
        };
        let consensus = address(Scheme::Bls, 1);
        let companion = address(Scheme::Bls, 2);
        let tz6 = address(Scheme::Xmss, 3);
        let tz1 = base58check::encode(&[6, 161, 159], &[4; 20]);
        let listing = format!(
            "Warning: the node is not synced\n{consensus}\n  {companion}\n{tz6}\n{tz1}\n\n"
        );

        assert_eq!(
            remote_keys_in_listing(&listing),
            [consensus, companion, tz6]
        );
    }

    /// A signer that answers on a later probe is returned then, not after the
    /// window; one that never answers is asked until the window runs out and
    /// then given up on.
    #[test]
    fn polling_returns_on_the_first_answer_and_gives_up_at_the_deadline() {
        use std::time::{Duration, Instant};

        let mut asked = 0;
        let keys = poll_for_keys(
            || {
                asked += 1;
                (asked == 3).then(|| vec!["tz4".to_string()])
            },
            Polling {
                window: Duration::from_secs(10),
                every: Duration::from_millis(1),
            },
        );
        assert_eq!(keys, Some(vec!["tz4".to_string()]));
        assert_eq!(asked, 3);

        let window = Duration::from_millis(20);
        let started = Instant::now();
        let mut asked = 0;
        let keys = poll_for_keys(
            || {
                asked += 1;
                None
            },
            Polling {
                window,
                every: Duration::from_millis(5),
            },
        );
        assert_eq!(keys, None);
        assert!(
            started.elapsed() >= window,
            "gave up after {:?}, inside the {window:?} window",
            started.elapsed()
        );
        assert!(asked >= 2, "asked {asked} time(s) inside the window");
    }

    #[test]
    fn forget_alias_ok_treats_success_and_absent_as_done() {
        // Clean success.
        assert!(forget_alias_ok(true, ""));
        // Non-zero exit but the alias was simply already gone.
        assert!(forget_alias_ok(
            false,
            "Error:\n  no public key hash alias named russignol-consensus-pending"
        ));
    }

    #[test]
    fn forget_alias_ok_rejects_a_genuine_failure() {
        // Non-zero exit with an unrelated error must not read as success.
        assert!(!forget_alias_ok(
            false,
            "Error: could not access wallet directory"
        ));
    }

    #[test]
    fn classify_alias_probe_distinguishes_absence_from_probe_failure() {
        // Present.
        assert_eq!(classify_alias_probe(true, ""), Some(true));
        // Ran, but the alias is simply not there.
        assert_eq!(
            classify_alias_probe(
                false,
                "Error:\n  no public key hash alias named russignol-consensus"
            ),
            Some(false)
        );
        // Non-zero exit for an unrelated reason: state is unknown, not absent.
        assert_eq!(
            classify_alias_probe(false, "Error: could not access wallet directory"),
            None
        );
    }
}
