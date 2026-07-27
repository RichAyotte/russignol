use crate::backup;
use crate::blockchain;
use crate::config::RussignolConfig;
use crate::constants::ORANGE_RGB;
use crate::key_role::BakerKeyNames;
use crate::keys;
use crate::progress::{run_step, run_step_detail};
use crate::utils::{JsonValueExt, read_file, run_octez_client_command, success, warning};
use anyhow::{Context, Result};
use russignol_signer_lib::KeyRole;
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
            if let Some((alias, addr)) = blockchain::list_known_addresses(config)?
                .into_iter()
                .find(|(alias, addr)| alias == key || addr == key)
            {
                return Ok((alias, addr));
            }
            anyhow::bail!("Provided baker key '{key}' not found in octez-client known addresses");
        }
        anyhow::bail!("--yes flag requires --baker-key to be specified");
    }

    // List known addresses (local wallet read)
    let choices: Vec<(String, String, String)> = blockchain::list_known_addresses(config)?
        .into_iter()
        .map(|(alias, addr)| (format!("{alias} ({addr})"), alias, addr))
        .collect(); // (display, alias, address)

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

/// Parse a string-encoded mutez field from a delegate RPC object. A missing or
/// non-numeric value on a registered delegate is a malformed response, surfaced
/// as an error rather than silently defaulted to 0.
fn parse_mutez_field(delegate_info: &serde_json::Value, key: &str) -> Result<u64> {
    delegate_info
        .get(key)
        .and_then(|v| v.as_str())
        .with_context(|| format!("delegate info missing string field '{key}'"))?
        .parse::<u64>()
        .with_context(|| format!("delegate field '{key}' is not a valid mutez amount"))
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
        || match crate::utils::rpc_get_json(&rpc_path, config) {
            Ok(delegate_info) => {
                // A registered delegate always carries these fields; a missing or
                // malformed value is a bad response, surfaced rather than
                // defaulted to a healthy-looking zero/active.
                let deactivated = delegate_info
                    .get_bool("deactivated")
                    .context("delegate info missing 'deactivated' field")?;
                let staked_balance = parse_mutez_field(&delegate_info, "total_staked")?;
                let full_balance = parse_mutez_field(&delegate_info, "own_full_balance")?;

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
            }
            Err(e) => {
                // Distinguish "not a delegate" from "node unreachable": if a basic
                // node endpoint still answers, the delegate query legitimately
                // found nothing; otherwise the failure is transport-level and
                // must be surfaced, not reported as an unregistered baker.
                if crate::utils::rpc_get_json("/chains/main/blocks/head/header", config).is_ok() {
                    log::info!("Baker {address}: not registered as delegate");
                    Ok(BakerStatus {
                        alias: alias.to_string(),
                        address: address.to_string(),
                        registered: false,
                        deactivated: false,
                        staked_balance: 0,
                        full_balance: 0,
                    })
                } else {
                    Err(e).context(format!(
                        "Could not query delegate status for {address}; the node is unreachable"
                    ))
                }
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
        // Setup can still complete, but the operator must know stake was not set
        // so they can set it manually rather than believing it was configured.
        warning(&format!(
            "Could not set stake automatically: {e:#}. Set it manually with 'octez-client stake ...'."
        ));
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

    // Validate pre-discovered keys. remote_keys is device list_keys order =
    // KeyRole::ALL (roles first); zip is the sole consumer of that contract.
    run_step_detail(
        "Discovering remote keys",
        &format!("octez-client list known remote keys {signer_uri}"),
        || {
            if remote_keys.len() < KeyRole::COUNT {
                anyhow::bail!(
                    "Expected at least {} remote keys but found {}. Please ensure the signer is properly configured.",
                    KeyRole::COUNT,
                    remote_keys.len()
                );
            }

            // Distinct role pkhs (defensive check against signer bugs).
            for (i, role_a) in KeyRole::ALL.into_iter().enumerate() {
                for role_b in KeyRole::ALL.into_iter().skip(i + 1) {
                    if remote_keys[role_a.index()] == remote_keys[role_b.index()] {
                        anyhow::bail!(
                            "Signer returned duplicate keys - {} and {} have the same public key hash",
                            role_a.device_alias(),
                            role_b.device_alias()
                        );
                    }
                }
            }

            let detail = format!("found {} keys", remote_keys.len());
            Ok(((), detail))
        },
    )?;

    let signer_ip = config.signer_ip();
    let role_remote: Vec<(KeyRole, &str)> = KeyRole::ALL
        .into_iter()
        .map(|role| (role, remote_keys[role.index()].as_str()))
        .collect();

    // One parse of the wallet file answers every role, and it stays valid for
    // the loop below: importing one role never rewrites another role's entry.
    let imported = roles_correctly_imported(&secret_keys_file, &role_remote, signer_ip);

    // Fast path: every role imported AND set on-chain → skip all subprocess work
    if imported.iter().all(|&i| i) {
        let local = read_local_key_hashes(&secret_keys_file, signer_ip);
        let all_on_chain = fetch_delegate_info(baker_key, config).is_ok_and(|info| {
            KeyRole::ALL.into_iter().all(|role| {
                local[role.index()]
                    .as_ref()
                    .is_some_and(|hash| role_key_set_on_chain(&info, role, hash))
            })
        });
        if all_on_chain {
            for role in KeyRole::ALL {
                if let Some(hash) = &local[role.index()] {
                    success(&format!("{} set to {hash}", role.display_name()));
                }
            }
            validate_imported_keys(client_dir, signer_ip, config)?;
            return Ok(());
        }
    }

    for (role, remote_pkh) in role_remote {
        import_and_set_key(
            role,
            remote_pkh,
            imported[role.index()],
            baker_key,
            &secret_keys_file,
            backup_dir,
            signer_uri,
            verbose,
            auto_confirm,
            config,
        )?;
    }

    // Final filesystem validation
    validate_imported_keys(client_dir, signer_ip, config)
}

/// Import a single role key and set it on-chain, using one spinner that updates
/// its message across phases, then prints a final success line with the key hash.
#[expect(
    clippy::too_many_arguments,
    reason = "orchestrates prompt, import, and on-chain set"
)]
fn import_and_set_key(
    role: KeyRole,
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
    let alias = role.baker_alias();
    let kind = role.cli_key_kind();

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

        let already_set = fetch_delegate_info(baker_key, config)
            .is_ok_and(|info| role_key_set_on_chain(&info, role, &pkh));

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
        success(&format!("{} set to {pkh}", role.display_name()));
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
            let output = run_octez_client_command(&["list", "known", "addresses"], config)
                .context("Failed to list known addresses")?;
            // A non-zero exit yields empty stdout, which would read as "keys not
            // imported"; surface the command failure as itself instead.
            if !output.status.success() {
                anyhow::bail!(
                    "octez-client list known addresses failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            let list_output = String::from_utf8_lossy(&output.stdout).to_string();
            let tcp_known =
                list_output.contains("tcp sk known") || list_output.contains("tcp:sk known");
            let all_roles = tcp_known
                && KeyRole::ALL
                    .into_iter()
                    .all(|role| list_output.contains(role.baker_alias()));

            if !all_roles {
                anyhow::bail!(
                    "Keys not found in octez-client after import (CLI validation failed)"
                );
            }

            validate_keys_in_filesystem(client_dir, signer_ip)?;

            Ok(())
        },
    )
}

/// Whether the baker-wallet file holds each role pointing at its expected hash
/// on `signer_ip`. Slots in [`KeyRole::ALL`] order; one read and one parse
/// answers every role. An unreadable or unparseable file reports all-false.
fn roles_correctly_imported(
    secret_keys_file: &Path,
    role_remote: &[(KeyRole, &str)],
    signer_ip: &str,
) -> [bool; KeyRole::COUNT] {
    let mut imported = [false; KeyRole::COUNT];

    let Ok(content) = read_file(secret_keys_file) else {
        return imported;
    };
    let Ok(keys) = serde_json::from_str::<serde_json::Value>(&content) else {
        return imported;
    };
    let Some(arr) = keys.as_array() else {
        return imported;
    };

    for &(role, expected_hash) in role_remote {
        let alias = role.baker_alias();
        imported[role.index()] = arr.iter().any(|key| {
            key.get_str("name") == Some(alias)
                && key
                    .get_str("value")
                    .is_some_and(|value| value.contains(expected_hash) && value.contains(signer_ip))
        });
    }
    imported
}

/// Local baker-wallet pkh for each role (slots in [`KeyRole::ALL`] order),
/// filtered by signer IP. `None` when the alias is missing or unparseable.
fn read_local_key_hashes(
    secret_keys_file: &Path,
    signer_ip: &str,
) -> [Option<String>; KeyRole::COUNT] {
    let mut out: [Option<String>; KeyRole::COUNT] = std::array::from_fn(|_| None);

    let content = read_file(secret_keys_file).ok();
    let keys: Option<serde_json::Value> = content.and_then(|c| serde_json::from_str(&c).ok());

    if let Some(arr) = keys.as_ref().and_then(|v| v.as_array()) {
        for key in arr {
            if let Some(name) = key.get_str("name")
                && let Some(value) = key.get_str("value")
                && value.contains(signer_ip)
                && let Some(role) = KeyRole::ALL
                    .into_iter()
                    .find(|role| name == role.baker_alias())
            {
                out[role.index()] = value
                    .rsplit('/')
                    .next()
                    .filter(|h| h.starts_with("tz"))
                    .map(String::from);
            }
        }
    }

    out
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

    let secret_content = read_file(&secret_keys_file)?;
    let secret_keys: serde_json::Value =
        serde_json::from_str(&secret_content).context("Failed to parse secret_keys file")?;

    let mut found = [false; KeyRole::COUNT];

    if let Some(keys_array) = secret_keys.as_array() {
        for key in keys_array {
            if let Some(name) = key.get_str("name")
                && let Some(value) = key.get_str("value")
                && value.contains(signer_ip)
            {
                for role in KeyRole::ALL {
                    if name == role.baker_alias() {
                        found[role.index()] = true;
                    }
                }
            }
        }
    }

    if !found.iter().all(|&f| f) {
        anyhow::bail!("Keys validation failed: keys not found in filesystem with correct URIs");
    }

    Ok(())
}

/// One delegate RPC round-trip, answering [`role_key_set_on_chain`] for every
/// role. Callers that ask about more than one role must share a single fetch.
fn fetch_delegate_info(baker_key: &str, config: &RussignolConfig) -> Result<serde_json::Value> {
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

    serde_json::from_slice(&output.stdout).context("Failed to parse delegate info")
}

/// Whether `expected_pkh` is the active or pending key for `role` on-chain.
fn role_key_set_on_chain(
    delegate_info: &serde_json::Value,
    role: KeyRole,
    expected_pkh: &str,
) -> bool {
    let key_obj = delegate_info.get_nested(role.rpc_delegate_key_field());

    // Companion's active field may be JSON null; treat that as absent.
    let active = key_obj
        .and_then(|ck| ck.get_nested("active"))
        .and_then(|active| {
            if active.is_null() {
                None
            } else {
                active.get_str("pkh")
            }
        })
        .unwrap_or("");

    let mut pending_match = false;
    if let Some(pendings) = key_obj
        .and_then(|ck| ck.get_nested("pendings"))
        .and_then(|p| p.as_array())
    {
        pending_match = pendings
            .iter()
            .any(|pending| pending.get_str("pkh") == Some(expected_pkh));
    }

    let matches = active == expected_pkh || pending_match;
    log::debug!(
        "On-chain {} active={active:?} expected={expected_pkh:?} match={matches}",
        role.device_alias()
    );
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mutez_field_reads_a_string_encoded_amount() {
        let info = serde_json::json!({"total_staked": "1000000"});
        assert_eq!(parse_mutez_field(&info, "total_staked").unwrap(), 1_000_000);
    }

    #[test]
    fn parse_mutez_field_errors_rather_than_defaulting_to_zero() {
        // Missing field, and present-but-non-numeric, both surface as errors
        // instead of a fabricated 0 balance.
        let info = serde_json::json!({"total_staked": "1000000"});
        assert!(parse_mutez_field(&info, "own_full_balance").is_err());
        let bad = serde_json::json!({"total_staked": "not-a-number"});
        assert!(parse_mutez_field(&bad, "total_staked").is_err());
    }
}
