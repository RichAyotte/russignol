use crate::backup;
use crate::blockchain;
use crate::config::RussignolConfig;
use crate::constants::{COMPANION_KEY_ALIAS, CONSENSUS_KEY_ALIAS, ORANGE_RGB};
use crate::keys;
use crate::utils::{JsonValueExt, read_file, run_octez_client_command};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

pub fn run(
    backup_dir: &Path,
    confirmation_config: &crate::confirmation::ConfirmationConfig,
    provided_baker_key: Option<&str>,
    russignol_config: &RussignolConfig,
) -> Result<String> {
    // Build mutation list for confirmation
    let mutations = crate::confirmation::PhaseMutations {
        phase_name: "Key Configuration".to_string(),
        actions: vec![
            crate::confirmation::MutationAction {
                description: "Select and verify baker key".to_string(),
                detailed_info: Some("May require baker re-registration if deactivated".to_string()),
            },
            crate::confirmation::MutationAction {
                description: "Configure staking parameters (if not set)".to_string(),
                detailed_info: Some("Required for baker to participate in consensus".to_string()),
            },
            crate::confirmation::MutationAction {
                description: "Import remote BLS keys from signer".to_string(),
                detailed_info: Some(format!(
                    "Import {CONSENSUS_KEY_ALIAS} and {COMPANION_KEY_ALIAS}"
                )),
            },
            crate::confirmation::MutationAction {
                description: "Set consensus key on-chain".to_string(),
                detailed_info: Some("Blockchain transaction to assign consensus key".to_string()),
            },
            crate::confirmation::MutationAction {
                description: "Set companion key on-chain".to_string(),
                detailed_info: Some("Blockchain transaction to assign companion key".to_string()),
            },
        ],
    };

    // Get confirmation
    match crate::confirmation::confirm_phase_mutations(&mutations, confirmation_config) {
        crate::confirmation::ConfirmationResult::Confirmed => {
            // Continue with phase
        }
        crate::confirmation::ConfirmationResult::Skipped => {
            // Return a dummy baker key since phase5 expects one
            return Ok("tz1skipped".to_string());
        }
        crate::confirmation::ConfirmationResult::Cancelled => {
            anyhow::bail!("Setup cancelled by user");
        }
    }

    // Get Baker Key (silent - progress shown in main)
    let baker_key = get_baker_key(
        confirmation_config.dry_run,
        confirmation_config.verbose,
        confirmation_config.auto_confirm,
        provided_baker_key,
        russignol_config,
    )?;

    // Ensure signer is accessible before attempting key operations
    if !confirmation_config.dry_run {
        keys::wait_for_signer(confirmation_config.auto_confirm, russignol_config)?;
    }

    // Discover, Import, and Verify Keys (silent - progress shown in main)
    discover_and_import_keys(
        backup_dir,
        confirmation_config.dry_run,
        confirmation_config.verbose,
        confirmation_config.auto_confirm,
        russignol_config,
    )?;

    // Assign and Verify Keys on Blockchain (silent - progress shown in main)
    assign_and_verify_keys(
        &baker_key,
        confirmation_config.dry_run,
        confirmation_config.verbose,
        confirmation_config.auto_confirm,
        russignol_config,
    )?;

    Ok(baker_key)
}

#[expect(
    clippy::cast_precision_loss,
    reason = "display-only balance/stake values"
)]
#[expect(
    clippy::too_many_lines,
    reason = "interactive baker key selection workflow"
)]
fn get_baker_key(
    dry_run: bool,
    verbose: bool,
    auto_confirm: bool,
    provided_baker_key: Option<&str>,
    config: &RussignolConfig,
) -> Result<String> {
    use inquire::{Select, ui::RenderConfig, ui::Styled};

    if dry_run {
        return Ok("tz1dummyKeyForDryRun".to_string());
    }

    // If auto_confirm is enabled and a baker key was provided, use it directly
    if auto_confirm {
        if let Some(key) = provided_baker_key {
            // Validate that the key exists
            let list_output = run_octez_client_command(&["list", "known", "addresses"], config)?;
            if list_output.status.success() {
                let stdout = String::from_utf8_lossy(&list_output.stdout);

                for line in stdout.lines() {
                    if let Some((alias_part, rest)) = line.split_once(':') {
                        let alias = alias_part.trim();
                        if let Some(addr) = rest.split_whitespace().next() {
                            // Check if provided key matches either alias or address
                            if alias == key || addr == key {
                                // Return the address (tz...), not the alias
                                return Ok(addr.to_string());
                            }
                        }
                    }
                }

                anyhow::bail!(
                    "Provided baker key '{key}' not found in octez-client known addresses"
                );
            }
        } else {
            anyhow::bail!("--yes flag requires --baker-key to be specified");
        }
    }

    // List known addresses and parse them
    let list_output = run_octez_client_command(&["list", "known", "addresses"], config)?;
    let mut choices: Vec<(String, String, String)> = Vec::new(); // (display, alias, address)

    if list_output.status.success() {
        let stdout = String::from_utf8_lossy(&list_output.stdout);

        // Parse the list to build selection options
        // Format: "alias: address (type)"
        for line in stdout.lines() {
            if let Some((alias_part, rest)) = line.split_once(':') {
                let alias = alias_part.trim();
                // Extract address (starts with tz)
                if let Some(addr) = rest.split_whitespace().next()
                    && addr.starts_with("tz")
                {
                    // Create display string: "alias (address)"
                    let display = format!("{alias} ({addr})");
                    choices.push((display, alias.to_string(), addr.to_string()));
                }
            }
        }
    }

    if choices.is_empty() {
        anyhow::bail!(
            "No known addresses found. Please import or create an address first using octez-client."
        );
    }

    // Use inquire to present interactive selection (only reached in non-auto-confirm mode)
    let display_choices: Vec<String> = choices
        .iter()
        .map(|(display, _, _)| display.clone())
        .collect();

    // Create custom theme with orange color
    let render_config = RenderConfig {
        prompt_prefix: Styled::new(">").with_fg(ORANGE_RGB),
        highlighted_option_prefix: Styled::new(">").with_fg(ORANGE_RGB),
        selected_option: Some(inquire::ui::StyleSheet::new().with_fg(ORANGE_RGB)),
        answer: inquire::ui::StyleSheet::new().with_fg(ORANGE_RGB),
        help_message: inquire::ui::StyleSheet::new().with_fg(ORANGE_RGB),
        ..Default::default()
    };

    let selection = Select::new("Select baker address/alias:", display_choices.clone())
        .with_help_message("↑↓ to navigate, Enter to select")
        .with_render_config(render_config)
        .prompt()
        .context("Failed to get user selection")?;

    // Find the corresponding alias and address
    let (input_key, baker_key) = choices
        .iter()
        .find(|(display, _, _)| display == &selection)
        .map(|(_, alias, addr)| (alias.clone(), addr.clone()))
        .context("Selected address not found")?;

    let is_registered = blockchain::is_registered_delegate(&baker_key, config);

    if is_registered {
        // Get delegate info for further checks
        let output = run_octez_client_command(
            &[
                "rpc",
                "get",
                &format!("/chains/main/blocks/head/context/delegates/{baker_key}"),
            ],
            config,
        )?;

        // Parse delegate info to check if deactivated
        let delegate_info: serde_json::Value =
            serde_json::from_slice(&output.stdout).context("Failed to parse delegate info")?;

        let is_deactivated = delegate_info.get_bool("deactivated").unwrap_or(false);

        log::info!("Baker {baker_key} deactivation status: {is_deactivated}");

        if is_deactivated {
            log::warn!("Baker {baker_key} is deactivated and needs re-registration");

            let should_reregister = crate::utils::prompt_yes_no(
                "Would you like to re-register the baker to reactivate it?",
                auto_confirm,
            )?;

            if should_reregister {
                log::info!("User chose to re-register deactivated baker {baker_key}");

                let register_output = run_octez_client_command(
                    &["register", "key", &input_key, "as", "delegate"],
                    config,
                )?;

                if !register_output.status.success() {
                    let stderr = String::from_utf8_lossy(&register_output.stderr);
                    anyhow::bail!("Failed to re-register delegate: {stderr}");
                }

                // Wait and verify
                std::thread::sleep(std::time::Duration::from_secs(5));

                for attempt in 1..=12 {
                    log::debug!("Verification attempt {attempt}/12");
                    let verify_output = run_octez_client_command(
                        &[
                            "rpc",
                            "get",
                            &format!("/chains/main/blocks/head/context/delegates/{baker_key}"),
                        ],
                        config,
                    );

                    if let Ok(verify_output) = verify_output
                        && verify_output.status.success()
                        && let Ok(info) =
                            serde_json::from_slice::<serde_json::Value>(&verify_output.stdout)
                    {
                        let still_deactivated = info.get_bool("deactivated").unwrap_or(true);

                        if !still_deactivated {
                            log::info!("Baker {baker_key} successfully reactivated");
                            break;
                        }
                    }

                    if attempt < 12 {
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }
                }
            } else {
                log::info!("User declined to re-register deactivated baker {baker_key}");
                anyhow::bail!(
                    "Baker {baker_key} is inactive and must be re-registered before continuing. You can re-register it manually with: octez-client register key {input_key} as delegate"
                );
            }
        }

        // Check if stake has been set
        if let Err(e) = check_and_set_stake(&baker_key, &input_key, verbose, auto_confirm, config) {
            log::debug!("Stake check failed: {e}");
        }

        Ok(baker_key)
    } else {
        // Not registered yet, check balance first

        // Get the minimum stake requirement from chain constants
        let constants_output = run_octez_client_command(
            &["rpc", "get", "/chains/main/blocks/head/context/constants"],
            config,
        )?;

        if !constants_output.status.success() {
            anyhow::bail!("Failed to query chain constants");
        }

        let constants: serde_json::Value = serde_json::from_slice(&constants_output.stdout)
            .context("Failed to parse chain constants")?;

        let min_stake_mutez: u64 = constants
            .get("minimal_stake")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .context("Failed to get minimal_stake from chain constants")?;

        let min_stake_tez = min_stake_mutez as f64 / 1_000_000.0;

        // Check balance to ensure it meets minimum requirement for baking
        let balance_output = run_octez_client_command(
            &[
                "rpc",
                "get",
                &format!("/chains/main/blocks/head/context/contracts/{baker_key}/balance"),
            ],
            config,
        )?;

        if !balance_output.status.success() {
            anyhow::bail!(
                "Could not check balance for {baker_key}. The account may not exist on-chain or may need to be revealed."
            );
        }

        let balance_str = String::from_utf8_lossy(&balance_output.stdout);
        let balance_mutez: u64 = balance_str
            .trim()
            .trim_matches('"')
            .parse()
            .context("Failed to parse balance")?;

        let balance_tez = balance_mutez as f64 / 1_000_000.0;

        if balance_tez < min_stake_tez {
            anyhow::bail!(
                "Insufficient balance for baking. The account has {balance_tez:.2} ꜩ but needs at least {min_stake_tez:.2} ꜩ to register as a delegate and participate in baking."
            );
        }

        // Ensure node is synced before prompting - otherwise registration will hang
        crate::system::wait_for_node_sync(config)?;

        let should_register =
            crate::utils::prompt_yes_no("Would you like to register it now?", auto_confirm)?;

        if should_register {
            let register_output = run_octez_client_command(
                &["register", "key", &input_key, "as", "delegate"],
                config,
            )?;

            if !register_output.status.success() {
                let stderr = String::from_utf8_lossy(&register_output.stderr);
                anyhow::bail!("Failed to register delegate: {stderr}");
            }

            crate::utils::success("Delegate registered successfully");

            // Check if stake has been set for the newly registered baker
            if let Err(e) =
                check_and_set_stake(&baker_key, &input_key, verbose, auto_confirm, config)
            {
                log::debug!("Stake check failed: {e}");
            }

            return Ok(baker_key);
        }
        anyhow::bail!(
            "Address {baker_key} must be registered as a delegate before continuing. You can register it manually with: octez-client register key {input_key} as delegate"
        );
    }
}

fn check_and_set_stake(
    baker_key: &str,
    baker_alias: &str,
    _verbose: bool,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    // Query the baker's staking parameters
    let delegate_output = run_octez_client_command(
        &[
            "rpc",
            "get",
            &format!("/chains/main/blocks/head/context/delegates/{baker_key}"),
        ],
        config,
    )?;

    if !delegate_output.status.success() {
        anyhow::bail!("Failed to query delegate staking info");
    }

    let delegate_info: serde_json::Value =
        serde_json::from_slice(&delegate_output.stdout).context("Failed to parse delegate info")?;

    // Get staked balance from delegate info (use total_staked which includes own + external)
    let staked_balance = delegate_info
        .get("total_staked")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    // Get full balance from delegate info (use own_full_balance)
    let full_balance = delegate_info
        .get("own_full_balance")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    log::debug!("Staked balance: {staked_balance} mutez, Full balance: {full_balance} mutez");

    let staked_balance_tez = crate::blockchain::mutez_to_tez(staked_balance);
    let full_balance_tez = crate::blockchain::mutez_to_tez(full_balance);

    log::info!(
        "Baker {baker_key}: staked_balance={staked_balance} mutez ({staked_balance_tez:.2} ꜩ), full_balance={full_balance} mutez ({full_balance_tez:.2} ꜩ)"
    );

    if staked_balance == 0 {
        log::warn!("Baker {baker_key} has not set their stake (total_staked=0)");

        let should_set_stake =
            crate::utils::prompt_yes_no("Would you like to set the stake now?", auto_confirm)?;

        if should_set_stake {
            let stake_amount = if auto_confirm {
                // Auto-confirm: stake all
                full_balance_tez.to_string()
            } else {
                print!("Enter stake amount in ꜩ (or 'all' to stake full balance): ");
                std::io::stdout().flush()?;

                let mut amount_input = String::new();
                std::io::stdin().read_line(&mut amount_input)?;
                let amount_input = amount_input.trim();

                if amount_input.to_lowercase() == "all" {
                    full_balance_tez.to_string()
                } else {
                    // Validate it's a valid number
                    match amount_input.parse::<f64>() {
                        Ok(amt) if amt > 0.0 && amt <= full_balance_tez => amt.to_string(),
                        Ok(amt) if amt > full_balance_tez => {
                            anyhow::bail!(
                                "Amount {amt:.2} ꜩ exceeds available balance {full_balance_tez:.2} ꜩ"
                            );
                        }
                        _ => {
                            anyhow::bail!("Invalid stake amount. Must be a positive number.");
                        }
                    }
                }
            };

            log::info!(
                "Setting stake for baker {baker_key}: amount={stake_amount} ꜩ, alias={baker_alias}"
            );

            let stake_output =
                run_octez_client_command(&["stake", &stake_amount, "for", baker_alias], config)?;

            if !stake_output.status.success() {
                let stderr = String::from_utf8_lossy(&stake_output.stderr);
                log::error!(
                    "Failed to set stake for baker {}: {}",
                    baker_key,
                    stderr.trim()
                );
                anyhow::bail!("Failed to set stake: {stderr}");
            }

            log::info!("Stake operation submitted successfully for baker {baker_key}");
        } else {
            log::info!("User declined to set stake for baker {baker_key}");
        }
    } else {
        let stake_percentage = crate::blockchain::percentage(staked_balance, full_balance);
        log::info!(
            "Baker {baker_key} already has stake set: {staked_balance_tez:.2} ꜩ ({stake_percentage:.1}% of total balance)"
        );
    }

    Ok(())
}

fn discover_and_import_keys(
    backup_dir: &Path,
    dry_run: bool,
    verbose: bool,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    let client_dir = &config.octez_client_dir;
    let secret_keys_file = client_dir.join("secret_keys");

    if dry_run {
        return Ok(());
    }

    // Discover keys from the remote signer
    let remote_keys = keys::discover_remote_keys(config)?;

    if remote_keys.len() < 2 {
        anyhow::bail!(
            "Expected at least 2 remote keys but found {}. Please ensure the signer is properly configured.",
            remote_keys.len()
        );
    }

    // Check if keys are already correctly imported
    let signer_ip = config.signer_ip();
    if let Ok((consensus_ok, companion_ok)) = check_keys_correctly_imported(
        &secret_keys_file,
        &remote_keys[0],
        &remote_keys[1],
        signer_ip,
    ) && consensus_ok
        && companion_ok
    {
        // Validation: Primary - CLI check (silent - progress shown in main)
        let list_output = run_octez_client_command(&["list", "known", "addresses"], config)
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .context("Failed to list known addresses")?;

        let has_consensus = list_output.contains("russignol-consensus")
            && (list_output.contains("tcp sk known") || list_output.contains("tcp:sk known"));
        let has_companion = list_output.contains("russignol-companion")
            && (list_output.contains("tcp sk known") || list_output.contains("tcp:sk known"));

        if !has_consensus || !has_companion {
            anyhow::bail!("Keys not found in octez-client after import (CLI validation failed)");
        }

        // Validation: Secondary - File system check (silent - progress shown in main)
        validate_keys_in_filesystem(client_dir, signer_ip)?;

        return Ok(());
    }

    // Import the first two keys as consensus and companion
    import_key_with_backup(
        CONSENSUS_KEY_ALIAS,
        &remote_keys[0],
        &secret_keys_file,
        backup_dir,
        auto_confirm,
        verbose,
        config,
    )?;

    import_key_with_backup(
        COMPANION_KEY_ALIAS,
        &remote_keys[1],
        &secret_keys_file,
        backup_dir,
        auto_confirm,
        verbose,
        config,
    )?;

    // Validation: Primary - CLI check (silent - progress shown in main)
    let list_output = run_octez_client_command(&["list", "known", "addresses"], config)
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .context("Failed to list known addresses")?;

    let has_consensus = list_output.contains(CONSENSUS_KEY_ALIAS)
        && (list_output.contains("tcp sk known") || list_output.contains("tcp:sk known"));
    let has_companion = list_output.contains(COMPANION_KEY_ALIAS)
        && (list_output.contains("tcp sk known") || list_output.contains("tcp:sk known"));

    if !has_consensus || !has_companion {
        anyhow::bail!("Keys not found in octez-client after import (CLI validation failed)");
    }

    // Validation: Secondary - File system check (silent - progress shown in main)
    validate_keys_in_filesystem(client_dir, config.signer_ip())?;

    Ok(())
}

fn check_keys_correctly_imported(
    secret_keys_file: &Path,
    expected_consensus_hash: &str,
    expected_companion_hash: &str,
    signer_ip: &str,
) -> Result<(bool, bool)> {
    if !secret_keys_file.exists() {
        return Ok((false, false));
    }

    let content = read_file(secret_keys_file)?;
    let keys: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse secret_keys file")?;

    let mut consensus_correct = false;
    let mut companion_correct = false;

    if let Some(keys_array) = keys.as_array() {
        for key in keys_array {
            if let Some(name) = key.get_str("name")
                && let Some(value) = key.get_str("value")
            {
                // Check consensus key
                if name == CONSENSUS_KEY_ALIAS
                    && value.contains(expected_consensus_hash)
                    && value.contains(signer_ip)
                {
                    consensus_correct = true;
                }

                // Check companion key
                if name == COMPANION_KEY_ALIAS
                    && value.contains(expected_companion_hash)
                    && value.contains(signer_ip)
                {
                    companion_correct = true;
                }
            }
        }
    }

    Ok((consensus_correct, companion_correct))
}

fn validate_keys_in_filesystem(client_dir: &Path, signer_ip: &str) -> Result<()> {
    let secret_keys_file = client_dir.join("secret_keys");

    // Check secret_keys
    let secret_content = read_file(&secret_keys_file)?;
    let secret_keys: serde_json::Value =
        serde_json::from_str(&secret_content).context("Failed to parse secret_keys file")?;

    let mut found_consensus = false;
    let mut found_companion = false;

    if let Some(keys_array) = secret_keys.as_array() {
        for key in keys_array {
            if let Some(name) = key.get_str("name")
                && let Some(value) = key.get_str("value")
            {
                if name == CONSENSUS_KEY_ALIAS && value.contains(signer_ip) {
                    found_consensus = true;
                }
                if name == COMPANION_KEY_ALIAS && value.contains(signer_ip) {
                    found_companion = true;
                }
            }
        }
    }

    if !found_consensus || !found_companion {
        anyhow::bail!("Keys validation failed: keys not found in filesystem with correct URIs");
    }

    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "multi-step key assignment and verification"
)]
fn assign_and_verify_keys(
    baker_key: &str,
    dry_run: bool,
    _verbose: bool,
    _auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    if dry_run {
        return Ok(());
    }

    // Get the public key hashes for the imported keys (in parallel, silent - progress shown in main)
    let (consensus_result, companion_result) = std::thread::scope(|s| {
        let config_ref = config;

        let consensus_handle = s.spawn(move || keys::get_key_hash(CONSENSUS_KEY_ALIAS, config_ref));
        let companion_handle = s.spawn(move || keys::get_key_hash(COMPANION_KEY_ALIAS, config_ref));

        (
            consensus_handle.join().unwrap(),
            companion_handle.join().unwrap(),
        )
    });

    let consensus_pkh = consensus_result?;
    let companion_pkh = companion_result?;

    // Check current key assignments on blockchain (silent - progress shown in main)
    let (consensus_matches, companion_matches) =
        match check_individual_keys_on_chain(baker_key, &consensus_pkh, &companion_pkh, config) {
            Ok((cons, comp)) => (cons, comp),
            Err(e) => {
                log::debug!("Could not verify current key state: {e}");
                (false, false)
            }
        };

    // Set consensus key only if needed
    if !consensus_matches {
        let set_consensus = run_octez_client_command(
            &[
                "set",
                "consensus",
                "key",
                "for",
                baker_key,
                "to",
                CONSENSUS_KEY_ALIAS,
            ],
            config,
        )?;

        if !set_consensus.status.success() {
            let stderr = String::from_utf8_lossy(&set_consensus.stderr);
            anyhow::bail!("Failed to set consensus key: {stderr}");
        }

        // Wait for consensus key operation to be included in a block before setting companion key (silent - progress shown in main)
        sleep(Duration::from_secs(5));

        // Poll for consensus key confirmation
        let mut consensus_confirmed = false;
        for i in 0..12 {
            log::debug!(
                "Polling for consensus key confirmation (attempt {}/12)",
                i + 1
            );

            match check_individual_keys_on_chain(baker_key, &consensus_pkh, &companion_pkh, config)
            {
                Ok((true, _)) => {
                    consensus_confirmed = true;
                    break;
                }
                Ok((false, _)) => {
                    if i < 11 {
                        sleep(Duration::from_secs(5));
                    }
                }
                Err(e) => {
                    log::debug!("Error checking consensus key status: {e}");
                    if i < 11 {
                        sleep(Duration::from_secs(5));
                    }
                }
            }
        }

        if !consensus_confirmed {
            anyhow::bail!(
                "Consensus key operation submitted but not confirmed after 60 seconds. Please check status manually before setting companion key."
            );
        }
    }

    // Set companion key only if needed
    if !companion_matches {
        let set_companion = run_octez_client_command(
            &[
                "set",
                "companion",
                "key",
                "for",
                baker_key,
                "to",
                COMPANION_KEY_ALIAS,
            ],
            config,
        )?;

        if !set_companion.status.success() {
            let stderr = String::from_utf8_lossy(&set_companion.stderr);
            anyhow::bail!("Failed to set companion key: {stderr}");
        }
    }

    // If both were already set, we're done
    if consensus_matches && companion_matches {
        return Ok(());
    }

    // Wait for operations to be included in a block (silent - progress shown in main)
    sleep(Duration::from_secs(5)); // Give some time for injection

    // Poll for up to 60 seconds
    let mut confirmed = false;
    for i in 0..12 {
        log::debug!("Polling for operation confirmation (attempt {}/12)", i + 1);

        // Check if keys are set on-chain
        match verify_keys_on_chain(baker_key, &consensus_pkh, &companion_pkh, config) {
            Ok(true) => {
                confirmed = true;
                break;
            }
            Ok(false) => {
                if i < 11 {
                    sleep(Duration::from_secs(5));
                }
            }
            Err(e) => {
                log::debug!("Error checking on-chain status: {e}");
                if i < 11 {
                    sleep(Duration::from_secs(5));
                }
            }
        }
    }

    if !confirmed {
        anyhow::bail!(
            "Operations submitted but not yet confirmed after 60 seconds. Check operations status manually with octez-client."
        );
    }

    Ok(())
}

fn verify_keys_on_chain(
    baker_key: &str,
    expected_consensus: &str,
    expected_companion: &str,
    config: &RussignolConfig,
) -> Result<bool> {
    let output = run_octez_client_command(
        &[
            "rpc",
            "get",
            &format!("/chains/main/blocks/head/context/delegates/{baker_key}"),
        ],
        config,
    )?;

    if !output.status.success() {
        return Ok(false);
    }

    let delegate_info: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse delegate info")?;

    // Check consensus key (active or pending)
    let consensus_key_obj = delegate_info.get_nested("consensus_key");

    let active_consensus = consensus_key_obj
        .and_then(|ck| ck.get_nested("active"))
        .and_then(|active| active.get_str("pkh"))
        .unwrap_or("");

    // Also check pendings array for consensus key
    let mut pending_consensus = false;
    if let Some(pendings) = consensus_key_obj
        .and_then(|ck| ck.get_nested("pendings"))
        .and_then(|p| p.as_array())
    {
        for pending in pendings {
            if let Some(pkh) = pending.get_str("pkh")
                && pkh == expected_consensus
            {
                pending_consensus = true;
                break;
            }
        }
    }

    let consensus_match = active_consensus == expected_consensus || pending_consensus;

    // Check companion key (active or pending)
    let companion_key_obj = delegate_info.get_nested("companion_key");

    let active_companion = companion_key_obj
        .and_then(|ck| ck.get_nested("active"))
        .and_then(|active| {
            if active.is_null() {
                None
            } else {
                active.get_str("pkh")
            }
        })
        .unwrap_or("");

    // Also check pendings array for companion key
    let mut pending_companion = false;
    if let Some(pendings) = companion_key_obj
        .and_then(|ck| ck.get_nested("pendings"))
        .and_then(|p| p.as_array())
    {
        for pending in pendings {
            if let Some(pkh) = pending.get_str("pkh")
                && pkh == expected_companion
            {
                pending_companion = true;
                break;
            }
        }
    }

    let companion_match = active_companion == expected_companion || pending_companion;

    log::debug!("On-chain active consensus key: {active_consensus}");
    log::debug!("Consensus key pending: {pending_consensus}");
    log::debug!("Expected consensus key: {expected_consensus}");
    log::debug!("On-chain active companion key: {active_companion}");
    log::debug!("Companion key pending: {pending_companion}");
    log::debug!("Expected companion key: {expected_companion}");

    if consensus_match && companion_match {
        Ok(true)
    } else {
        if !consensus_match {
            log::debug!("Consensus key mismatch");
        }
        if !companion_match {
            log::debug!("Companion key mismatch");
        }
        Ok(false)
    }
}

fn check_individual_keys_on_chain(
    baker_key: &str,
    expected_consensus: &str,
    expected_companion: &str,
    config: &RussignolConfig,
) -> Result<(bool, bool)> {
    let output = run_octez_client_command(
        &[
            "rpc",
            "get",
            &format!("/chains/main/blocks/head/context/delegates/{baker_key}"),
        ],
        config,
    )?;

    if !output.status.success() {
        anyhow::bail!("Failed to query delegate info from blockchain");
    }

    let delegate_info: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse delegate info")?;

    // Check consensus key (active or pending)
    let consensus_key_obj = delegate_info.get_nested("consensus_key");

    let active_consensus = consensus_key_obj
        .and_then(|ck| ck.get_nested("active"))
        .and_then(|active| active.get_str("pkh"))
        .unwrap_or("");

    // Also check pendings array for consensus key
    let mut pending_consensus = String::new();
    if let Some(pendings) = consensus_key_obj
        .and_then(|ck| ck.get_nested("pendings"))
        .and_then(|p| p.as_array())
    {
        for pending in pendings {
            if let Some(pkh) = pending.get_str("pkh")
                && pkh == expected_consensus
            {
                pending_consensus = pkh.to_string();
                break;
            }
        }
    }

    let consensus_match =
        active_consensus == expected_consensus || pending_consensus == expected_consensus;

    // Check companion key (active or pending)
    let companion_key_obj = delegate_info.get_nested("companion_key");

    let active_companion = companion_key_obj
        .and_then(|ck| ck.get_nested("active"))
        .and_then(|active| {
            if active.is_null() {
                None
            } else {
                active.get_str("pkh")
            }
        })
        .unwrap_or("");

    // Also check pendings array for companion key
    let mut pending_companion = String::new();
    if let Some(pendings) = companion_key_obj
        .and_then(|ck| ck.get_nested("pendings"))
        .and_then(|p| p.as_array())
    {
        for pending in pendings {
            if let Some(pkh) = pending.get_str("pkh")
                && pkh == expected_companion
            {
                pending_companion = pkh.to_string();
                break;
            }
        }
    }

    let companion_match =
        active_companion == expected_companion || pending_companion == expected_companion;

    log::debug!("On-chain active consensus key: {active_consensus}");
    log::debug!("On-chain pending consensus key: {pending_consensus}");
    log::debug!("Expected consensus key: {expected_consensus}");
    log::debug!("On-chain active companion key: {active_companion}");
    log::debug!("On-chain pending companion key: {pending_companion}");
    log::debug!("Expected companion key: {expected_companion}");

    if consensus_match {
        if pending_consensus.is_empty() {
            log::debug!("Consensus key is active and matches");
        } else {
            log::debug!("Consensus key is pending (will become active soon)");
        }
    } else {
        log::debug!("Consensus key mismatch (neither active nor pending)");
    }

    if companion_match {
        if pending_companion.is_empty() {
            log::debug!("Companion key is active and matches");
        } else {
            log::debug!("Companion key is pending (will become active soon)");
        }
    } else {
        log::debug!("Companion key mismatch (neither active nor pending)");
    }

    Ok((consensus_match, companion_match))
}

/// Import a key with backup before force overwrite
///
/// Handles the import flow with user prompts and optional backup
/// when forcing overwrite of an existing alias.
fn import_key_with_backup(
    alias: &str,
    key_hash: &str,
    secret_keys_file: &Path,
    backup_dir: &Path,
    auto_confirm: bool,
    verbose: bool,
    config: &RussignolConfig,
) -> Result<()> {
    match keys::import_key_from_signer(alias, key_hash, false, config) {
        Ok(()) => Ok(()),
        Err(e) if e.to_string().starts_with("alias_exists:") => {
            let should_overwrite = crate::utils::prompt_yes_no(
                &format!("Overwrite existing '{alias}'?"),
                auto_confirm,
            )?;

            if should_overwrite {
                // Backup secret_keys before forcing overwrite
                let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
                let backup_filename = format!("secret_keys.before-force-{timestamp}");
                backup::backup_file_if_exists(
                    secret_keys_file,
                    backup_dir,
                    &backup_filename,
                    verbose,
                )?;

                keys::import_key_from_signer(alias, key_hash, true, config)
            } else {
                anyhow::bail!("Cannot proceed without importing key '{alias}'");
            }
        }
        Err(e) => Err(e),
    }
}
