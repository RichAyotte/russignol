use crate::backup;
use crate::blockchain;
use crate::config::RussignolConfig;
use crate::constants::{COMPANION_KEY_ALIAS, CONSENSUS_KEY_ALIAS, ORANGE_RGB};
use crate::keys;
use crate::progress::{run_step, run_step_detail};
use crate::utils::{JsonValueExt, read_file, run_octez_client_command, success};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

/// Baker state captured from a single delegate RPC fetch.
///
/// Distinguishes three states: unregistered, registered-but-deactivated,
/// and registered-and-active. Fixes a bug where the old code conflated
/// "unregistered" and "deactivated" via `is_registered_delegate()`.
struct BakerStatus {
    alias: String,
    address: String,
    registered: bool,
    deactivated: bool,
    staked_balance: u64,
    full_balance: u64,
}

/// Select baker address interactively or from CLI args.
///
/// Returns `(alias, address)`. No RPC calls or mutations — purely selection.
fn select_baker(
    dry_run: bool,
    auto_confirm: bool,
    provided_baker_key: Option<&str>,
    config: &RussignolConfig,
) -> Result<(String, String)> {
    use inquire::{Select, ui::RenderConfig, ui::Styled};

    if dry_run {
        return Ok(("dry-run".to_string(), "tz1dummyKeyForDryRun".to_string()));
    }

    // If auto_confirm is enabled and a baker key was provided, use it directly
    if auto_confirm {
        if let Some(key) = provided_baker_key {
            let list_output = run_octez_client_command(&["list", "known", "addresses"], config)?;
            if list_output.status.success() {
                let stdout = String::from_utf8_lossy(&list_output.stdout);

                for line in stdout.lines() {
                    if let Some((alias_part, rest)) = line.split_once(':') {
                        let alias = alias_part.trim();
                        if let Some(addr) = rest.split_whitespace().next()
                            && (alias == key || addr == key)
                        {
                            return Ok((alias.to_string(), addr.to_string()));
                        }
                    }
                }

                anyhow::bail!(
                    "Provided baker key '{key}' not found in octez-client known addresses"
                );
            }
        }
        anyhow::bail!("--yes flag requires --baker-key to be specified");
    }

    // List known addresses and parse them
    let list_output = run_octez_client_command(&["list", "known", "addresses"], config)?;
    let mut choices: Vec<(String, String, String)> = Vec::new(); // (display, alias, address)

    if list_output.status.success() {
        let stdout = String::from_utf8_lossy(&list_output.stdout);

        for line in stdout.lines() {
            if let Some((alias_part, rest)) = line.split_once(':') {
                let alias = alias_part.trim();
                if let Some(addr) = rest.split_whitespace().next()
                    && addr.starts_with("tz")
                {
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

    let display_choices: Vec<String> = choices
        .iter()
        .map(|(display, _, _)| display.clone())
        .collect();

    let render_config = RenderConfig {
        prompt_prefix: Styled::new(">").with_fg(ORANGE_RGB),
        highlighted_option_prefix: Styled::new(">").with_fg(ORANGE_RGB),
        selected_option: Some(inquire::ui::StyleSheet::new().with_fg(ORANGE_RGB)),
        answer: inquire::ui::StyleSheet::new().with_fg(ORANGE_RGB),
        help_message: inquire::ui::StyleSheet::new().with_fg(ORANGE_RGB),
        ..Default::default()
    };

    println!();
    let selection = Select::new("Select baker address/alias:", display_choices.clone())
        .with_help_message("↑↓ to navigate, Enter to select")
        .with_render_config(render_config)
        .prompt()
        .context("Failed to get user selection")?;

    choices
        .iter()
        .find(|(display, _, _)| display == &selection)
        .map(|(_, alias, addr)| (alias.clone(), addr.clone()))
        .context("Selected address not found")
}

/// Validate baker against the blockchain with a single delegate RPC fetch.
///
/// Returns `BakerStatus` distinguishing unregistered, deactivated, and active.
/// Fixes a bug where `is_registered_delegate()` conflated unregistered and
/// deactivated bakers.
fn validate_baker(alias: &str, address: &str, config: &RussignolConfig) -> Result<BakerStatus> {
    let rpc_path = format!("/chains/main/blocks/head/context/delegates/{address}");

    run_step(
        "Validating baker",
        &format!("octez-client rpc get .../delegates/{address}"),
        || {
            let result = crate::utils::rpc_get_json(&rpc_path, config);

            if let Ok(delegate_info) = result {
                let deactivated = delegate_info.get_bool("deactivated").unwrap_or(false);
                let staked_balance = delegate_info
                    .get("total_staked")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let full_balance = delegate_info
                    .get("own_full_balance")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);

                log::info!(
                    "Baker {address}: registered=true, deactivated={deactivated}, \
                     staked={staked_balance}, balance={full_balance}"
                );

                Ok(BakerStatus {
                    alias: alias.to_string(),
                    address: address.to_string(),
                    registered: true,
                    deactivated,
                    staked_balance,
                    full_balance,
                })
            } else {
                log::info!("Baker {address}: not registered as delegate");
                Ok(BakerStatus {
                    alias: alias.to_string(),
                    address: address.to_string(),
                    registered: false,
                    deactivated: false,
                    staked_balance: 0,
                    full_balance: 0,
                })
            }
        },
    )
}

pub fn run(
    backup_dir: &Path,
    confirmation_config: &crate::confirmation::ConfirmationConfig,
    provided_baker_key: Option<&str>,
    russignol_config: &RussignolConfig,
) -> Result<String> {
    let dry_run = confirmation_config.dry_run;
    let auto_confirm = confirmation_config.auto_confirm;

    // ── Before confirmation (read-only) ──────────────────────────────────

    // Step 1: Select baker (interactive prompt or CLI arg)
    let (alias, address) =
        select_baker(dry_run, auto_confirm, provided_baker_key, russignol_config)?;

    // Step 2: Validate baker against blockchain (single delegate RPC)
    let baker = if dry_run {
        BakerStatus {
            alias,
            address: address.clone(),
            registered: true,
            deactivated: false,
            staked_balance: 0,
            full_balance: 0,
        }
    } else {
        validate_baker(&alias, &address, russignol_config)?
    };

    // Step 3: Show stake status if already set
    if baker.registered && baker.staked_balance > 0 {
        let staked_tez = blockchain::mutez_to_tez(baker.staked_balance);
        let pct = blockchain::percentage(baker.staked_balance, baker.full_balance);
        success(&format!(
            "Stake already set: {staked_tez:.2} ꜩ ({pct:.1}% of balance)"
        ));
    }

    // Step 4: Build dynamic mutations list based on baker state
    let mut actions = Vec::new();

    if !baker.registered {
        actions.push(crate::confirmation::MutationAction {
            description: "Register baker as delegate".to_string(),
            detailed_info: Some("Blockchain transaction to register as delegate".to_string()),
        });
        actions.push(crate::confirmation::MutationAction {
            description: "Configure staking parameters".to_string(),
            detailed_info: Some("Required for baker to participate in consensus".to_string()),
        });
    } else if baker.deactivated {
        actions.push(crate::confirmation::MutationAction {
            description: "Re-register baker as delegate".to_string(),
            detailed_info: Some("Baker is deactivated and needs re-registration".to_string()),
        });
        actions.push(crate::confirmation::MutationAction {
            description: "Configure staking parameters".to_string(),
            detailed_info: Some("Required for baker to participate in consensus".to_string()),
        });
    } else if baker.staked_balance == 0 {
        actions.push(crate::confirmation::MutationAction {
            description: "Configure staking parameters".to_string(),
            detailed_info: Some("Required for baker to participate in consensus".to_string()),
        });
    }

    // Step 6: Get confirmation for registration/staking actions (skip if nothing to do)
    if !actions.is_empty() {
        let mutations = crate::confirmation::PhaseMutations {
            phase_name: "Key Configuration".to_string(),
            actions,
        };

        match crate::confirmation::confirm_phase_mutations(&mutations, confirmation_config) {
            crate::confirmation::ConfirmationResult::Confirmed => {}
            crate::confirmation::ConfirmationResult::Skipped => {
                return Ok("tz1skipped".to_string());
            }
            crate::confirmation::ConfirmationResult::Cancelled => {
                anyhow::bail!("Setup cancelled by user");
            }
        }
    }

    // ── After confirmation (mutations) ───────────────────────────────────

    // Handle baker registration if needed
    if !dry_run {
        handle_baker_registration(&baker, auto_confirm, russignol_config)?;
    }

    // Check and set stake using pre-fetched BakerStatus
    if !dry_run
        && baker.registered
        && baker.staked_balance == 0
        && let Err(e) = check_and_set_stake(&baker, auto_confirm, russignol_config)
    {
        log::debug!("Stake check failed: {e}");
    }

    // Ensure signer is accessible and discover remote keys
    let remote_keys = if dry_run {
        Vec::new()
    } else {
        keys::wait_for_signer(auto_confirm, russignol_config)?
    };

    // Import keys and set them on-chain
    discover_and_import_keys(
        &baker.address,
        backup_dir,
        dry_run,
        confirmation_config.verbose,
        auto_confirm,
        &remote_keys,
        russignol_config,
    )?;

    Ok(baker.address)
}

/// Handle baker registration or re-registration based on `BakerStatus`.
#[expect(
    clippy::too_many_lines,
    reason = "registration/re-registration workflow with balance checks"
)]
#[expect(clippy::cast_precision_loss, reason = "display-only balance values")]
fn handle_baker_registration(
    baker: &BakerStatus,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    if baker.registered && baker.deactivated {
        // Baker is registered but deactivated — offer re-registration
        log::warn!(
            "Baker {} is deactivated and needs re-registration",
            baker.address
        );

        let should_reregister = crate::utils::prompt_yes_no(
            "Would you like to re-register the baker to reactivate it?",
            auto_confirm,
        )?;

        if should_reregister {
            log::info!(
                "User chose to re-register deactivated baker {}",
                baker.address
            );

            run_step(
                "Re-registering baker",
                &format!("octez-client register key {} as delegate", baker.alias),
                || {
                    let register_output = run_octez_client_command(
                        &["register", "key", &baker.alias, "as", "delegate"],
                        config,
                    )?;

                    if !register_output.status.success() {
                        let stderr = String::from_utf8_lossy(&register_output.stderr);
                        anyhow::bail!("Failed to re-register delegate: {stderr}");
                    }

                    log::info!("Baker {} successfully reactivated", baker.address);
                    Ok(())
                },
            )?;
        } else {
            log::info!(
                "User declined to re-register deactivated baker {}",
                baker.address
            );
            anyhow::bail!(
                "Baker {} is inactive and must be re-registered before continuing. You can re-register it manually with: octez-client register key {} as delegate",
                baker.address,
                baker.alias
            );
        }
    } else if !baker.registered {
        // Not registered yet — check balance, then offer registration
        run_step(
            "Checking baker balance",
            &format!(
                "octez-client rpc get .../contracts/{}/balance",
                baker.address
            ),
            || {
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

                let balance_output = run_octez_client_command(
                    &[
                        "rpc",
                        "get",
                        &format!(
                            "/chains/main/blocks/head/context/contracts/{}/balance",
                            baker.address
                        ),
                    ],
                    config,
                )?;

                if !balance_output.status.success() {
                    anyhow::bail!(
                        "Could not check balance for {}. The account may not exist on-chain or may need to be revealed.",
                        baker.address
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

                Ok(())
            },
        )?;

        // Ensure node is synced before prompting — otherwise registration will hang
        crate::system::wait_for_node_sync(config)?;

        let should_register =
            crate::utils::prompt_yes_no("Would you like to register it now?", auto_confirm)?;

        if should_register {
            run_step(
                "Registering baker as delegate",
                &format!("octez-client register key {} as delegate", baker.alias),
                || {
                    let register_output = run_octez_client_command(
                        &["register", "key", &baker.alias, "as", "delegate"],
                        config,
                    )?;

                    if !register_output.status.success() {
                        let stderr = String::from_utf8_lossy(&register_output.stderr);
                        anyhow::bail!("Failed to register delegate: {stderr}");
                    }

                    Ok(())
                },
            )?;
        } else {
            anyhow::bail!(
                "Address {} must be registered as a delegate before continuing. You can register it manually with: octez-client register key {} as delegate",
                baker.address,
                baker.alias
            );
        }
    }

    Ok(())
}

fn check_and_set_stake(
    baker: &BakerStatus,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    let staked_balance_tez = blockchain::mutez_to_tez(baker.staked_balance);
    let full_balance_tez = blockchain::mutez_to_tez(baker.full_balance);

    log::info!(
        "Baker {}: staked_balance={} mutez ({staked_balance_tez:.2} ꜩ), full_balance={} mutez ({full_balance_tez:.2} ꜩ)",
        baker.address,
        baker.staked_balance,
        baker.full_balance
    );

    if baker.staked_balance == 0 {
        log::warn!(
            "Baker {} has not set their stake (total_staked=0)",
            baker.address
        );

        let should_set_stake =
            crate::utils::prompt_yes_no("Would you like to set the stake now?", auto_confirm)?;

        if should_set_stake {
            let stake_amount = if auto_confirm {
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
                "Setting stake for baker {}: amount={stake_amount} ꜩ, alias={}",
                baker.address,
                baker.alias
            );

            run_step(
                "Setting stake",
                &format!("octez-client stake {stake_amount} for {}", baker.alias),
                || {
                    let stake_output = run_octez_client_command(
                        &["stake", &stake_amount, "for", &baker.alias],
                        config,
                    )?;

                    if !stake_output.status.success() {
                        let stderr = String::from_utf8_lossy(&stake_output.stderr);
                        log::error!(
                            "Failed to set stake for baker {}: {}",
                            baker.address,
                            stderr.trim()
                        );
                        anyhow::bail!("Failed to set stake: {stderr}");
                    }

                    log::info!(
                        "Stake operation submitted successfully for baker {}",
                        baker.address
                    );
                    Ok(())
                },
            )?;
        } else {
            log::info!("User declined to set stake for baker {}", baker.address);
        }
    } else {
        let stake_percentage = blockchain::percentage(baker.staked_balance, baker.full_balance);
        success(&format!(
            "Stake already set: {staked_balance_tez:.2} ꜩ ({stake_percentage:.1}% of balance)"
        ));
        log::info!(
            "Baker {} already has stake set: {staked_balance_tez:.2} ꜩ ({stake_percentage:.1}% of total balance)",
            baker.address
        );
    }

    Ok(())
}

fn discover_and_import_keys(
    baker_key: &str,
    backup_dir: &Path,
    dry_run: bool,
    verbose: bool,
    auto_confirm: bool,
    remote_keys: &[String],
    config: &RussignolConfig,
) -> Result<()> {
    let client_dir = &config.octez_client_dir;
    let secret_keys_file = client_dir.join("secret_keys");

    if dry_run {
        return Ok(());
    }

    let signer_uri = config.signer_uri();

    // Validate pre-discovered keys
    run_step_detail(
        "Discovering remote keys",
        &format!("octez-client list known remote keys {signer_uri}"),
        || {
            if remote_keys.len() < 2 {
                anyhow::bail!(
                    "Expected at least 2 remote keys but found {}. Please ensure the signer is properly configured.",
                    remote_keys.len()
                );
            }

            // Validate keys are distinct (defensive check against signer bugs)
            if remote_keys[0] == remote_keys[1] {
                anyhow::bail!(
                    "Signer returned duplicate keys - consensus and companion have the same public key hash"
                );
            }

            let detail = format!("found {} keys", remote_keys.len());
            Ok(((), detail))
        },
    )?;

    // Check which keys are already correctly imported
    let signer_ip = config.signer_ip();
    let (consensus_imported, companion_imported) = check_keys_correctly_imported(
        &secret_keys_file,
        &remote_keys[0],
        &remote_keys[1],
        signer_ip,
    )
    .unwrap_or((false, false));

    // Fast path: both keys imported AND set on-chain → skip all subprocess work
    if consensus_imported && companion_imported {
        let (ch, cph) = read_local_key_hashes(&secret_keys_file, signer_ip);
        if let (Some(consensus_hash), Some(companion_hash)) = (ch, cph)
            && let Ok((true, true)) =
                check_individual_keys_on_chain(baker_key, &consensus_hash, &companion_hash, config)
        {
            success(&format!("Consensus key set to {consensus_hash}"));
            success(&format!("Companion key set to {companion_hash}"));
            validate_imported_keys(client_dir, signer_ip, config)?;
            return Ok(());
        }
    }

    // ── Consensus key ───────────────────────────────────────────────────
    import_and_set_key(
        CONSENSUS_KEY_ALIAS,
        "consensus",
        &remote_keys[0],
        consensus_imported,
        baker_key,
        &secret_keys_file,
        backup_dir,
        signer_uri,
        verbose,
        auto_confirm,
        config,
    )?;

    // ── Companion key ───────────────────────────────────────────────────
    import_and_set_key(
        COMPANION_KEY_ALIAS,
        "companion",
        &remote_keys[1],
        companion_imported,
        baker_key,
        &secret_keys_file,
        backup_dir,
        signer_uri,
        verbose,
        auto_confirm,
        config,
    )?;

    // Final filesystem validation
    validate_imported_keys(client_dir, signer_ip, config)
}

/// Import a single key and set it on-chain, using one spinner that updates its
/// message across phases, then prints a final success line with the key hash.
#[expect(
    clippy::too_many_arguments,
    reason = "orchestrates prompt, import, and on-chain set"
)]
fn import_and_set_key(
    alias: &str,
    kind: &str,
    remote_key_hash: &str,
    already_imported: bool,
    baker_key: &str,
    secret_keys_file: &Path,
    backup_dir: &Path,
    signer_uri: &str,
    verbose: bool,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    // Prompt OUTSIDE the spinner so stdin isn't corrupted
    let force = if !already_imported && alias_exists_in_file(secret_keys_file, alias) {
        let should_overwrite =
            crate::utils::prompt_yes_no(&format!("Overwrite existing '{alias}'?"), auto_confirm)?;
        if !should_overwrite {
            anyhow::bail!("Cannot proceed without importing key '{alias}'");
        }
        let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let backup_filename = format!("secret_keys.before-force-{timestamp}");
        backup::backup_file_if_exists(secret_keys_file, backup_dir, &backup_filename, verbose)?;
        true
    } else {
        false
    };

    let spinner = crate::progress::create_spinner(&format!(
        "Importing {kind} key (octez-client import secret key {alias} {signer_uri}/{remote_key_hash})"
    ));

    let result = (|| -> Result<()> {
        // Import if needed
        if !already_imported {
            keys::import_key_from_signer(alias, remote_key_hash, force, config)?;
        }

        // Resolve the imported key's public key hash
        let pkh = keys::get_key_hash(alias, config)?;

        // Check if already set on-chain (pass pkh in the correct slot)
        let already_set = if kind == "consensus" {
            check_individual_keys_on_chain(baker_key, &pkh, "", config)
                .map(|(c, _)| c)
                .unwrap_or(false)
        } else {
            check_individual_keys_on_chain(baker_key, "", &pkh, config)
                .map(|(_, c)| c)
                .unwrap_or(false)
        };

        if !already_set {
            spinner.set_message(format!(
                "Setting {kind} key (octez-client set {kind} key for {baker_key} to {alias})"
            ));

            let output = run_octez_client_command(
                &["set", kind, "key", "for", baker_key, "to", alias],
                config,
            )?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // "already active" means the key is already set — not an error
                if !stderr.contains("already active") {
                    anyhow::bail!("Failed to set {kind} key: {stderr}");
                }
            }
        }

        spinner.finish_and_clear();
        let label = format!(
            "{}{} key set to {pkh}",
            &kind[..1].to_uppercase(),
            &kind[1..]
        );
        success(&label);
        Ok(())
    })();

    if result.is_err() {
        spinner.finish_and_clear();
    }
    result
}

fn validate_imported_keys(
    client_dir: &Path,
    signer_ip: &str,
    config: &RussignolConfig,
) -> Result<()> {
    run_step(
        "Validating imported keys",
        "octez-client list known addresses",
        || {
            let list_output = run_octez_client_command(&["list", "known", "addresses"], config)
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .context("Failed to list known addresses")?;

            let has_consensus = list_output.contains(CONSENSUS_KEY_ALIAS)
                && (list_output.contains("tcp sk known") || list_output.contains("tcp:sk known"));
            let has_companion = list_output.contains(COMPANION_KEY_ALIAS)
                && (list_output.contains("tcp sk known") || list_output.contains("tcp:sk known"));

            if !has_consensus || !has_companion {
                anyhow::bail!(
                    "Keys not found in octez-client after import (CLI validation failed)"
                );
            }

            validate_keys_in_filesystem(client_dir, signer_ip)?;

            Ok(())
        },
    )
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

/// Read the actual key hashes from the `secret_keys` file for our two aliases,
/// filtered by signer IP. Returns `(consensus_hash, companion_hash)` with `None`
/// for any alias that isn't found or can't be parsed.
fn read_local_key_hashes(
    secret_keys_file: &Path,
    signer_ip: &str,
) -> (Option<String>, Option<String>) {
    let content = read_file(secret_keys_file).ok();
    let keys: Option<serde_json::Value> = content.and_then(|c| serde_json::from_str(&c).ok());

    let mut consensus_hash = None;
    let mut companion_hash = None;

    if let Some(arr) = keys.as_ref().and_then(|v| v.as_array()) {
        for key in arr {
            if let Some(name) = key.get_str("name")
                && let Some(value) = key.get_str("value")
                && value.contains(signer_ip)
            {
                let hash = value
                    .rsplit('/')
                    .next()
                    .filter(|h| h.starts_with("tz"))
                    .map(String::from);

                if name == CONSENSUS_KEY_ALIAS {
                    consensus_hash = hash;
                } else if name == COMPANION_KEY_ALIAS {
                    companion_hash = hash;
                }
            }
        }
    }

    (consensus_hash, companion_hash)
}

fn alias_exists_in_file(secret_keys_file: &Path, alias: &str) -> bool {
    let Ok(content) = read_file(secret_keys_file) else {
        return false;
    };
    let Ok(keys) = serde_json::from_str::<serde_json::Value>(&content) else {
        return false;
    };
    keys.as_array()
        .is_some_and(|arr| arr.iter().any(|k| k.get_str("name") == Some(alias)))
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
