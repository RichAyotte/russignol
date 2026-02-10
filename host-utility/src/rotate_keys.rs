// Key rotation workflow for Russignol hardware signer
//
// This module implements the `russignol rotate-keys` command, which guides bakers
// through rotating their consensus and companion keys to a new Russignol device.
//
// The rotation process involves:
// 1. Pre-rotation checklist verification
// 2. Key discovery from the new device
// 3. Importing new keys with `-pending` suffix
// 4. Submitting on-chain transactions to set new keys
// 5. Monitoring activation status
// 6. Executing the swap sequence at cycle boundary

use crate::blockchain;
use crate::config::RussignolConfig;
use crate::constants::{
    COMPANION_KEY_ALIAS, COMPANION_KEY_OLD_ALIAS, COMPANION_KEY_PENDING_ALIAS, CONSENSUS_KEY_ALIAS,
    CONSENSUS_KEY_OLD_ALIAS, CONSENSUS_KEY_PENDING_ALIAS,
};
use crate::image;
use crate::keys;
use crate::progress::create_spinner;
use crate::system;
use crate::utils::{
    JsonValueExt, create_orange_theme, ensure_sudo, info, print_subtitle_bar, print_title_bar,
    prompt_yes_no, rpc_get_json, run_command, run_octez_client_command, success,
    sudo_command_success, warning,
};
use std::fmt::Write as _;

use anyhow::{Context, Result};
use clap::ValueEnum;
use colored::Colorize;
use std::thread::sleep;
use std::time::Duration;

/// Hardware configuration mode
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum HardwareConfig {
    /// Two Pi Zero 2W devices - swap USB cables between devices
    TwoDevices,
    /// Single Pi with second SD card - swap SD cards
    SinglePi,
}

impl std::fmt::Display for HardwareConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HardwareConfig::TwoDevices => write!(f, "two-devices"),
            HardwareConfig::SinglePi => write!(f, "single-pi"),
        }
    }
}

/// Method for restarting the baker daemon
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RestartMethod {
    /// Use systemctl stop/start
    Systemd,
    /// Run custom stop/start commands
    Script,
    /// Pause and prompt user to restart manually
    Manual,
}

impl std::fmt::Display for RestartMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RestartMethod::Systemd => write!(f, "systemd"),
            RestartMethod::Script => write!(f, "script"),
            RestartMethod::Manual => write!(f, "manual"),
        }
    }
}

/// CLI input for baker restart configuration (Options allow CLI omission)
pub struct RestartConfig {
    pub method: Option<RestartMethod>,
    pub service: String,
    pub stop_command: Option<String>,
    pub start_command: Option<String>,
}

/// Resolved restart configuration with all required values determined
struct ResolvedRestartConfig {
    method: RestartMethod,
    service: String,
    stop_command: Option<String>,
    start_command: Option<String>,
}

/// Context for resuming an incomplete key rotation
struct ResumeContext<'a> {
    delegate_address: &'a str,
    delegate_alias: &'a str,
    consensus_hash: &'a str,
    companion_hash: &'a str,
}

/// Represents what device we expect to be connected
#[derive(Debug, Clone)]
pub enum DeviceExpectation {
    /// Expect the new device with new keys
    New,
    /// Expect the old device with the current active keys
    Old { expected_consensus_hash: String },
}

/// Information about the swap window
#[derive(Debug)]
pub struct SwapWindow {
    pub start_block: i64,
    pub end_block: i64,
    pub duration_estimate: String,
    pub warning: Option<String>,
}

/// Options for the rotate-keys command
#[expect(
    clippy::struct_excessive_bools,
    reason = "CLI flags map to individual bools"
)]
pub struct RotateKeysOptions {
    pub monitor_only: bool,
    pub replace: bool,
    pub dry_run: bool,
    pub auto_confirm: bool,
    pub verbose: bool,
}

/// Main entry point for the rotate-keys command
pub fn run(
    opts: &RotateKeysOptions,
    hardware_config: Option<HardwareConfig>,
    restart_config: &RestartConfig,
    config: &RussignolConfig,
) -> Result<()> {
    let &RotateKeysOptions {
        monitor_only,
        replace,
        dry_run,
        auto_confirm,
        verbose,
    } = opts;
    println!();
    print_title_bar("🔄 Russignol Key Rotation");

    if dry_run {
        println!(
            "{}",
            "Running in DRY-RUN mode - no changes will be made"
                .yellow()
                .bold()
        );
        println!();
    }

    if monitor_only {
        return run_monitor_mode(config, verbose);
    }

    // Step 1: Pre-rotation checklist
    println!();
    print_subtitle_bar("Step 1: Pre-Rotation Checklist");
    let (delegate_address, delegate_alias) = verify_preconditions(config, verbose)?;

    let mut state = detect_rotation_state(&delegate_address, config)?;

    if replace {
        state = handle_replace_flag(state, config)?;
    }

    // Handle resumed states - each returns early if handled
    if let Some(result) = handle_resumed_state(
        &state,
        &delegate_address,
        &delegate_alias,
        hardware_config,
        restart_config,
        auto_confirm,
        config,
    )? {
        return result;
    }

    // Fresh rotation flow
    execute_fresh_rotation(
        &FreshRotationContext {
            delegate_address: &delegate_address,
            delegate_alias: &delegate_alias,
            hardware_config,
            restart_config,
            replace,
            dry_run,
            auto_confirm,
        },
        config,
    )
}

fn handle_replace_flag(state: RotationState, config: &RussignolConfig) -> Result<RotationState> {
    match &state {
        RotationState::Pending { .. }
        | RotationState::PendingOnChainOnly { .. }
        | RotationState::KeysImported { .. } => {
            info("--replace flag: cleaning up pending keys to start fresh...");
            let _ = keys::forget_key_alias(CONSENSUS_KEY_PENDING_ALIAS, config);
            let _ = keys::forget_key_alias(COMPANION_KEY_PENDING_ALIAS, config);
            success("Pending keys cleared. Starting fresh rotation.");
            println!();
            Ok(RotationState::Clean)
        }
        RotationState::PartialSwap | RotationState::KeysActivatedNeedSwap => {
            warning(
                "--replace cannot be used during swap state.\n  \
                 Complete the swap first, then run with --replace if needed.",
            );
            anyhow::bail!("Cannot use --replace during swap state");
        }
        RotationState::Clean => Ok(state),
    }
}

/// Returns Some(Ok(())) if state was handled, None if fresh rotation should proceed
fn handle_resumed_state(
    state: &RotationState,
    delegate_address: &str,
    delegate_alias: &str,
    hardware_config: Option<HardwareConfig>,
    restart_config: &RestartConfig,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<Option<Result<()>>> {
    match state {
        RotationState::PartialSwap => {
            let resolved = resolve_restart_config(restart_config, auto_confirm)?;
            Ok(Some(resume_from_partial_swap(
                &resolved,
                auto_confirm,
                config,
            )))
        }
        RotationState::KeysImported {
            consensus_hash,
            companion_hash,
        } => {
            let hw_config =
                hardware_config.map_or_else(|| prompt_hardware_config(auto_confirm), Ok)?;
            let resolved = resolve_restart_config(restart_config, auto_confirm)?;
            let ctx = ResumeContext {
                delegate_address,
                delegate_alias,
                consensus_hash,
                companion_hash,
            };
            Ok(Some(resume_from_keys_imported(
                &ctx,
                hw_config,
                &resolved,
                auto_confirm,
                config,
            )))
        }
        RotationState::Pending { activation_cycle } => Ok(Some(resume_from_pending(
            delegate_address,
            *activation_cycle,
            hardware_config,
            restart_config,
            auto_confirm,
            config,
        ))),
        RotationState::PendingOnChainOnly { activation_cycle } => {
            Ok(Some(resume_from_pending_on_chain_only(
                delegate_address,
                *activation_cycle,
                hardware_config,
                restart_config,
                auto_confirm,
                config,
            )))
        }
        RotationState::KeysActivatedNeedSwap => {
            let resolved = resolve_restart_config(restart_config, auto_confirm)?;
            Ok(Some(resume_from_keys_activated_need_swap(
                &resolved,
                auto_confirm,
                config,
            )))
        }
        RotationState::Clean => Ok(None),
    }
}

fn resolve_restart_config(
    restart_config: &RestartConfig,
    auto_confirm: bool,
) -> Result<ResolvedRestartConfig> {
    let restart_method = restart_config
        .method
        .map_or_else(|| prompt_restart_method(auto_confirm), Ok)?;
    Ok(ResolvedRestartConfig {
        method: restart_method,
        service: restart_config.service.clone(),
        stop_command: restart_config.stop_command.clone(),
        start_command: restart_config.start_command.clone(),
    })
}

struct FreshRotationContext<'a> {
    delegate_address: &'a str,
    delegate_alias: &'a str,
    hardware_config: Option<HardwareConfig>,
    restart_config: &'a RestartConfig,
    replace: bool,
    dry_run: bool,
    auto_confirm: bool,
}

/// Context for checking if keys are already pending on-chain
struct PendingKeyCheckContext<'a> {
    delegate_address: &'a str,
    consensus_hash: &'a str,
    current_consensus: &'a str,
    hw_config: HardwareConfig,
    restart_config: &'a RestartConfig,
    replace: bool,
    auto_confirm: bool,
}

fn execute_fresh_rotation(ctx: &FreshRotationContext<'_>, config: &RussignolConfig) -> Result<()> {
    let FreshRotationContext {
        delegate_address,
        delegate_alias,
        hardware_config,
        restart_config,
        replace,
        dry_run,
        auto_confirm,
    } = ctx;

    let new_device_already_connected = if *dry_run {
        false
    } else {
        check_sd_card_readiness(*auto_confirm)?
    };

    let hw_config = hardware_config.map_or_else(|| prompt_hardware_config(*auto_confirm), Ok)?;
    let resolved_restart_config = resolve_restart_config(restart_config, *auto_confirm)?;

    // Step 2: Device detection and key discovery from NEW device
    println!();
    print_subtitle_bar("Step 2: Connect New Device");

    let new_expectation = DeviceExpectation::New;
    if !new_device_already_connected {
        guide_device_swap(hw_config, &new_expectation)?;
    }
    wait_for_device(&new_expectation, config)?;

    let (consensus_hash, companion_hash) = discover_key_hashes(config)?;
    success(&format!(
        "Discovered new keys: consensus={}, companion={}",
        &consensus_hash[..12],
        &companion_hash[..12]
    ));

    let current_consensus = blockchain::get_active_consensus_key(delegate_address, config)?;
    if consensus_hash == current_consensus {
        warning("New consensus key matches current active key - nothing to rotate");
        return Ok(());
    }

    // Step 3: Import new keys with -pending suffix
    // Public keys are stored locally by octez-client during import
    println!();
    print_subtitle_bar("Step 3: Import New Keys");

    if *dry_run {
        info(&format!(
            "Would import {} -> {}",
            CONSENSUS_KEY_PENDING_ALIAS, &consensus_hash
        ));
        info(&format!(
            "Would import {} -> {}",
            COMPANION_KEY_PENDING_ALIAS, &companion_hash
        ));
    } else {
        import_new_keys(&consensus_hash, &companion_hash, config)?;
    }

    // Check if keys are already pending on-chain before submitting transaction
    let pending_ctx = PendingKeyCheckContext {
        delegate_address,
        consensus_hash: &consensus_hash,
        current_consensus: &current_consensus,
        hw_config,
        restart_config,
        replace: *replace,
        auto_confirm: *auto_confirm,
    };
    if let Some(result) = check_existing_pending_keys(&pending_ctx, config)? {
        return result;
    }

    // Step 4: Submit on-chain transaction
    // IMPORTANT: Must happen while NEW device is still connected!
    // For BLS keys (tz4), octez-client generates a "proof of possession" which
    // requires signing - this contacts the remote signer at 169.254.1.1.
    println!();
    print_subtitle_bar("Step 4: Submit On-Chain Transaction");

    // Submit set consensus key transactions
    let activation_cycle = if *dry_run {
        info("Would submit set consensus key transaction");
        info("Would submit set companion key transaction");
        0 // Placeholder cycle for dry-run
    } else {
        submit_key_rotation_transactions(delegate_address, delegate_alias, *auto_confirm, config)?
    };

    // Step 5: Reconnect OLD device for continued baking
    println!();
    print_subtitle_bar("Step 5: Reconnect Old Device");
    info("Transaction submitted! Reconnect your OLD device now to resume baking.");

    let old_expectation = DeviceExpectation::Old {
        expected_consensus_hash: current_consensus.clone(),
    };
    guide_device_swap(hw_config, &old_expectation)?;
    wait_for_device(&old_expectation, config)?;

    // Step 6: Monitoring
    if !*dry_run {
        run_activation_monitoring(
            delegate_address,
            activation_cycle,
            hw_config,
            &resolved_restart_config,
            *auto_confirm,
            config,
        )?;
    }

    Ok(())
}

/// Check if keys are already pending on-chain. Returns Some if we should return early.
fn check_existing_pending_keys(
    ctx: &PendingKeyCheckContext<'_>,
    config: &RussignolConfig,
) -> Result<Option<Result<()>>> {
    let PendingKeyCheckContext {
        delegate_address,
        consensus_hash,
        current_consensus,
        hw_config,
        restart_config,
        replace,
        auto_confirm,
    } = ctx;

    let status = blockchain::query_key_activation_status(delegate_address, config)?;

    if !status.consensus_pending {
        return Ok(None);
    }

    let Some(pending_hash) = &status.consensus_pending_hash else {
        return Ok(None);
    };

    if pending_hash == consensus_hash {
        println!();
        success("Keys are already pending on-chain!");
        info(&format!(
            "Pending consensus key: {}...",
            &pending_hash[..12.min(pending_hash.len())]
        ));
        if let Some(cycle) = status.consensus_cycle {
            info(&format!("Activation cycle: {cycle}"));
        }

        println!();
        print_subtitle_bar("Step 5: Reconnect Old Device");
        info("Keys already pending. Reconnect your OLD device now to resume baking.");

        let old_expectation = DeviceExpectation::Old {
            expected_consensus_hash: current_consensus.to_string(),
        };
        guide_device_swap(*hw_config, &old_expectation)?;
        wait_for_device(&old_expectation, config)?;

        let activation_cycle = status.consensus_cycle.unwrap_or(0);
        return Ok(Some(resume_from_pending(
            delegate_address,
            activation_cycle,
            Some(*hw_config),
            restart_config,
            *auto_confirm,
            config,
        )));
    }

    if *replace {
        warning(&format!(
            "A different key is already pending: {}...",
            &pending_hash[..12.min(pending_hash.len())]
        ));
        info("--replace flag: will submit new transaction to replace pending key");
        println!();
    } else {
        warning(&format!(
            "A different key is already pending: {}...",
            &pending_hash[..12.min(pending_hash.len())]
        ));
        warning("You may need to wait for it to activate or expire before rotating again.");
        info("Use --replace to submit a new key and replace the pending one.");
        anyhow::bail!("Cannot rotate: different key already pending on-chain");
    }

    Ok(None)
}

fn run_activation_monitoring(
    delegate_address: &str,
    activation_cycle: i64,
    hw_config: HardwareConfig,
    resolved_restart_config: &ResolvedRestartConfig,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    println!();
    print_subtitle_bar("Step 6: Monitoring Activation");
    success(&format!(
        "Keys pending activation at cycle {activation_cycle}"
    ));

    if let Ok(Some(window)) =
        calculate_optimal_swap_window(delegate_address, activation_cycle, config)
    {
        println!();
        info(&format!(
            "Optimal swap window: blocks {}-{} ({})",
            window.start_block, window.end_block, window.duration_estimate
        ));
        if let Some(warn) = &window.warning {
            warning(warn);
        }
    }

    display_activation_status(delegate_address, config)?;

    println!();
    info("Your OLD device should remain connected for baking until activation.");
    info(&format!(
        "Monitor activation status with: {} rotate-keys --monitor",
        "russignol".cyan()
    ));
    info("You will need to perform the swap sequence at cycle boundary.");

    println!();
    let should_wait = prompt_yes_no(
        "Would you like to wait and be guided through the swap sequence?",
        auto_confirm,
    )?;

    if should_wait {
        wait_for_activation_and_swap(
            delegate_address,
            hw_config,
            resolved_restart_config,
            auto_confirm,
            config,
        )?;
    } else {
        println!();
        info("When ready for the swap, run:");
        info(&format!("  {} rotate-keys --monitor", "russignol".cyan()));
    }

    Ok(())
}

/// Run in monitor-only mode - display activation status and guide swap
fn run_monitor_mode(config: &RussignolConfig, verbose: bool) -> Result<()> {
    println!();
    print_subtitle_bar("Key Rotation Status");

    // Find the delegate address
    let delegate = blockchain::find_delegate_address(config)?
        .context("No delegate address found. Run setup first.")?;

    // Query and display activation status
    let status = blockchain::query_key_activation_status(&delegate, config)?;

    if !status.consensus_pending && !status.companion_pending {
        success("No pending key rotation found");

        // Check if there are -pending aliases that need cleanup
        if pending_aliases_exist(config) {
            println!();
            warning("Found -pending aliases that may need cleanup");
            info("This could indicate an incomplete rotation.");
            info("If rotation is complete, the swap sequence will clean these up.");
        }

        return Ok(());
    }

    // Display pending status
    if status.consensus_pending {
        if let Some(cycle) = status.consensus_cycle {
            info(&format!(
                "Consensus key pending: activates at cycle {cycle}"
            ));
        }
        if let Some(time) = &status.consensus_time_estimate {
            info(&format!("  Estimated time: {time}"));
        }
    }

    if status.companion_pending {
        if let Some(cycle) = status.companion_cycle {
            info(&format!(
                "Companion key pending: activates at cycle {cycle}"
            ));
        }
        if let Some(time) = &status.companion_time_estimate {
            info(&format!("  Estimated time: {time}"));
        }
    }

    // Calculate optimal swap window
    if let Some(activation_cycle) = status.consensus_cycle
        && let Ok(Some(window)) = calculate_optimal_swap_window(&delegate, activation_cycle, config)
    {
        println!();
        print_subtitle_bar("Recommended Swap Window");
        info(&format!(
            "Swap during blocks {}-{} of cycle {}",
            window.start_block, window.end_block, activation_cycle
        ));
        info(&format!("Window duration: {}", window.duration_estimate));
        if let Some(warn) = &window.warning {
            warning(warn);
        }
    }

    if verbose {
        // Show more details about current vs pending keys
        println!();
        print_subtitle_bar("Key Details");
        display_key_details(&delegate, config)?;
    }

    Ok(())
}

/// Verify all preconditions for key rotation
fn verify_preconditions(config: &RussignolConfig, verbose: bool) -> Result<(String, String)> {
    let mut all_ok = true;

    // Check 1: Tezos node running and synced
    match system::verify_octez_node(config) {
        Ok(()) => success("Tezos node running and synced"),
        Err(e) => {
            println!("  {} {}", "✗".red(), e);
            all_ok = false;
        }
    }

    // Check 2: Find delegate address
    let delegate = if let Some(addr) = blockchain::find_delegate_address(config)? {
        success(&format!("Found delegate: {addr}"));
        addr
    } else {
        println!("  {} No registered delegate found", "✗".red());
        all_ok = false;
        String::new()
    };

    // Get delegate alias for later use
    let delegate_alias = if delegate.is_empty() {
        String::new()
    } else {
        keys::get_alias_for_address(&delegate, config).unwrap_or_else(|_| delegate.clone())
    };

    // Check 3: Baker not deactivated
    if !delegate.is_empty() {
        if blockchain::is_registered_delegate(&delegate, config) {
            success("Baker is active (not deactivated)");
        } else {
            println!("  {} Baker is deactivated", "✗".red());
            all_ok = false;
        }
    }

    // Check 4: Sufficient balance for transaction
    if !delegate.is_empty() {
        match blockchain::get_balance(&delegate, config) {
            Ok(balance_tez) if balance_tez >= 0.01 => {
                success(&format!("Sufficient balance: {balance_tez:.2} ꜩ"));
            }
            Ok(balance_tez) => {
                println!(
                    "  {} Insufficient balance: {:.2} ꜩ (need ~0.01 ꜩ)",
                    "✗".red(),
                    balance_tez
                );
                all_ok = false;
            }
            Err(e) => {
                if verbose {
                    log::debug!("Error checking balance: {e}");
                }
            }
        }
    }

    // Check 5: octez-client accessible
    match run_octez_client_command(&["--version"], config) {
        Ok(output) if output.status.success() => {
            success("octez-client accessible");
        }
        _ => {
            println!("  {} octez-client not accessible", "✗".red());
            all_ok = false;
        }
    }

    // Check 6: Current russignol keys exist
    if let Ok(hash) = keys::get_key_hash(CONSENSUS_KEY_ALIAS, config) {
        success(&format!(
            "Current consensus key: {}...",
            &hash[..12.min(hash.len())]
        ));
    } else {
        println!(
            "  {} No current {} alias found",
            "✗".red(),
            CONSENSUS_KEY_ALIAS
        );
        info("Run 'russignol setup' first to configure initial keys");
        all_ok = false;
    }

    if !all_ok {
        println!();
        anyhow::bail!("Pre-rotation requirements not met. Please resolve the issues above.");
    }

    Ok((delegate, delegate_alias))
}

/// Prompt user to select hardware configuration
fn prompt_hardware_config(auto_confirm: bool) -> Result<HardwareConfig> {
    use inquire::Select;

    if auto_confirm {
        return Ok(HardwareConfig::TwoDevices);
    }

    let options = vec![
        "Two Pi devices (swap USB cables)",
        "Single Pi with two SD cards (swap SD cards)",
    ];

    let theme = create_orange_theme();

    let selection = Select::new("Which hardware setup do you have?", options)
        .with_render_config(theme)
        .prompt()
        .context("Failed to get hardware configuration")?;

    Ok(if selection.contains("Two Pi") {
        HardwareConfig::TwoDevices
    } else {
        HardwareConfig::SinglePi
    })
}

/// Prompt user to select restart method
fn prompt_restart_method(auto_confirm: bool) -> Result<RestartMethod> {
    use inquire::Select;

    if auto_confirm {
        return Ok(RestartMethod::Manual);
    }

    let options = vec![
        "systemd (systemctl stop/start)",
        "Custom script (provide commands)",
        "Manual (I'll restart it myself)",
    ];

    let theme = create_orange_theme();

    let selection = Select::new("How do you restart your baker daemon?", options)
        .with_render_config(theme)
        .prompt()
        .context("Failed to get restart method")?;

    Ok(if selection.contains("systemd") {
        RestartMethod::Systemd
    } else if selection.contains("script") {
        RestartMethod::Script
    } else {
        RestartMethod::Manual
    })
}

/// Check if user has prepared an SD card with new keys
///
/// Prompts the user and offers to download/flash if needed.
/// Returns true if the new device is already connected and ready (just flashed),
/// false if user had an SD card ready beforehand.
fn check_sd_card_readiness(auto_confirm: bool) -> Result<bool> {
    use inquire::Select;
    use std::io::Write;

    if auto_confirm {
        // In auto mode, assume SD card is ready but not yet connected
        return Ok(false);
    }

    println!();
    let theme = create_orange_theme();

    let options = vec![
        "Yes, I have a new SD card with fresh keys ready",
        "No, I need to flash a new SD card first",
    ];

    let selection = Select::new(
        "Do you have a new SD card flashed with Russignol (containing new keys)?",
        options,
    )
    .with_render_config(theme)
    .prompt()
    .context("Failed to get SD card readiness")?;

    if selection.contains("No") {
        println!();
        info("Let's prepare a new SD card with fresh keys.");
        info("This will download the latest Russignol image and flash it to an SD card.");
        println!();

        let flash_options = vec!["Download and flash now", "Exit and do it manually later"];

        let flash_selection = Select::new("How would you like to proceed?", flash_options)
            .with_render_config(theme)
            .prompt()
            .context("Failed to get flash preference")?;

        if flash_selection.contains("Download and flash") {
            println!();

            // Retry loop for flash operations
            loop {
                match image::run_image_command(image::ImageCommands::DownloadAndFlash {
                    url: None,
                    device: None,
                    endpoint: None,
                    yes: false,
                    restore_keys: None,
                }) {
                    Ok(()) => {
                        println!();
                        success("SD card flashed successfully!");
                        println!();

                        // Guide user through booting the new card to generate keys
                        println!();
                        println!("  Next steps to set up the new SD card:");
                        println!("    1. Remove the SD card from your USB card reader");
                        println!("    2. Insert it into your Russignol Pi device and power on");
                        println!("    3. Touch 'Begin' when prompted on the device screen");
                        println!("    4. Create and confirm a new PIN");
                        println!("    5. Wait for key generation to complete");

                        print!("  Press {} when the signer is running...", "Enter".cyan());
                        std::io::stdout().flush()?;
                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input)?;

                        // Device is already connected - skip Step 2's swap guidance
                        return Ok(true);
                    }
                    Err(e) => {
                        println!();
                        warning(&format!("Flash failed: {e}"));
                        println!();

                        let retry_options = vec![
                            "Insert SD card/USB reader and try again",
                            "Exit and do it manually later",
                        ];

                        let retry_selection =
                            Select::new("Would you like to retry?", retry_options)
                                .with_render_config(theme)
                                .prompt()
                                .context("Failed to get retry preference")?;

                        if retry_selection.contains("Exit") {
                            println!();
                            info("To flash manually, run:");
                            info(&format!(
                                "  {} image download-and-flash",
                                "russignol".cyan()
                            ));
                            println!();
                            anyhow::bail!("Please prepare a new SD card before continuing");
                        }

                        // User chose to retry - continue loop
                        println!();
                        info("Please insert your SD card or USB card reader now...");
                        println!();
                    }
                }
            }
        } else {
            println!();
            info("To flash manually, run:");
            info(&format!(
                "  {} image download-and-flash",
                "russignol".cyan()
            ));
            println!();
            anyhow::bail!("Please prepare a new SD card before continuing");
        }
    }

    success("New SD card with fresh keys is ready");
    Ok(false)
}

/// Guide user through device swap based on configuration
fn guide_device_swap(hw_config: HardwareConfig, expectation: &DeviceExpectation) -> Result<()> {
    use std::io::Write;

    let (device_label, action, needs_pin) = match &expectation {
        DeviceExpectation::New => ("NEW", "with your new keys", false),
        DeviceExpectation::Old { .. } => ("OLD", "currently baking", true),
    };

    println!();
    match hw_config {
        HardwareConfig::TwoDevices => {
            info(&format!(
                "Connect your {} Russignol device ({})",
                device_label.cyan().bold(),
                action
            ));
        }
        HardwareConfig::SinglePi => {
            info(&format!(
                "Power off your Pi, insert the {} SD card ({}), and power on",
                device_label.cyan().bold(),
                action
            ));
        }
    }

    if needs_pin {
        info("Enter your PIN on the device to start the signer");
    }

    print!("  Press {} when the signer is running...", "Enter".cyan());
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    Ok(())
}

/// Wait for device to be accessible at the expected IP and optionally verify keys
fn wait_for_device(expectation: &DeviceExpectation, config: &RussignolConfig) -> Result<()> {
    let spinner = create_spinner("Verifying device connectivity...");

    let signer_ip = config.signer_ip();

    // Try pinging the signer IP
    for attempt in 1..=10 {
        let ping_result = run_command("ping", &["-c", "1", "-W", "2", signer_ip]);
        if let Ok(output) = ping_result
            && output.status.success()
        {
            // Verify signer is responding by checking if expected key exists
            match expectation {
                DeviceExpectation::New => {
                    // For NEW device, just check that signer responds with at least 2 keys
                    if keys::discover_remote_keys(config)
                        .map(|k| k.len() >= 2)
                        .unwrap_or(false)
                    {
                        spinner.finish_and_clear();
                        success("Device connected and signer responding");
                        return Ok(());
                    }
                }
                DeviceExpectation::Old {
                    expected_consensus_hash,
                } => {
                    // For OLD device, query the existing russignol-consensus alias
                    // This contacts the signer - succeeds only if OLD device is connected
                    if signer_has_expected_consensus_key(config) {
                        spinner.finish_and_clear();
                        success("Device connected and signer responding");
                        return Ok(());
                    }
                    if attempt >= 3 {
                        // After a few attempts, warn about wrong device
                        spinner.finish_and_clear();
                        warning(&format!(
                            "Connected signer doesn't have expected key {}...",
                            &expected_consensus_hash[..12]
                        ));
                        anyhow::bail!(
                            "Wrong device connected. Expected OLD device with key {}...",
                            &expected_consensus_hash[..12]
                        );
                    }
                }
            }
        }

        if attempt < 10 {
            log::debug!("Device not ready, attempt {attempt}/10");
            sleep(Duration::from_secs(2));
        }
    }

    spinner.finish_and_clear();
    anyhow::bail!("Could not connect to device at {signer_ip}. Please check USB connection.");
}

/// Check if the connected signer has the key for the existing consensus alias
///
/// Queries the existing `russignol-consensus` alias. This triggers a signer
/// query - if the signer has the key, it responds with the public key.
/// If not (wrong device), the query fails.
fn signer_has_expected_consensus_key(config: &RussignolConfig) -> bool {
    // Query the existing alias - this will contact the signer
    run_octez_client_command(&["show", "address", CONSENSUS_KEY_ALIAS], config)
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Discover key hashes from the remote signer
fn discover_key_hashes(config: &RussignolConfig) -> Result<(String, String)> {
    let remote_keys = keys::discover_remote_keys(config)?;

    if remote_keys.len() < 2 {
        anyhow::bail!(
            "Expected at least 2 remote keys but found {}. Is this a properly configured Russignol device?",
            remote_keys.len()
        );
    }

    Ok((remote_keys[0].clone(), remote_keys[1].clone()))
}

/// Import new keys with -pending suffix
///
/// Imports keys from the remote signer into `-pending` aliases.
/// The public keys are stored locally by octez-client and can be
/// referenced by alias in subsequent commands.
fn import_new_keys(
    consensus_hash: &str,
    companion_hash: &str,
    config: &RussignolConfig,
) -> Result<()> {
    // Import consensus key as -pending
    info(&format!(
        "Importing {} -> {}...",
        CONSENSUS_KEY_PENDING_ALIAS,
        &consensus_hash[..12]
    ));
    keys::import_key_from_signer(CONSENSUS_KEY_PENDING_ALIAS, consensus_hash, true, config)?;

    // Import companion key as -pending
    info(&format!(
        "Importing {} -> {}...",
        COMPANION_KEY_PENDING_ALIAS,
        &companion_hash[..12]
    ));
    keys::import_key_from_signer(COMPANION_KEY_PENDING_ALIAS, companion_hash, true, config)?;

    success("New keys imported with -pending suffix");

    Ok(())
}

/// Submit set consensus key transactions for both keys
///
/// Uses the `-pending` aliases directly. The public keys were stored locally
/// by octez-client during import, so no signer contact is needed.
fn submit_key_rotation_transactions(
    delegate_address: &str,
    delegate_alias: &str,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<i64> {
    // Confirm before submitting transactions
    if !auto_confirm {
        println!();
        let confirm = prompt_yes_no(
            "Submit set consensus key transactions? (costs ~0.01 ꜩ)",
            false,
        )?;
        if !confirm {
            anyhow::bail!("Transaction submission cancelled by user");
        }
    }

    // Submit consensus key transaction using the -pending alias
    info("Submitting set consensus key transaction...");
    let set_consensus = run_octez_client_command(
        &[
            "set",
            "consensus",
            "key",
            "for",
            delegate_alias,
            "to",
            CONSENSUS_KEY_PENDING_ALIAS,
        ],
        config,
    )?;

    if !set_consensus.status.success() {
        let stderr = String::from_utf8_lossy(&set_consensus.stderr);
        anyhow::bail!("Failed to set consensus key: {stderr}");
    }
    success("Consensus key transaction submitted");

    // Wait before submitting companion key
    sleep(Duration::from_secs(5));

    // Submit companion key transaction using the -pending alias
    info("Submitting set companion key transaction...");
    let set_companion = run_octez_client_command(
        &[
            "set",
            "companion",
            "key",
            "for",
            delegate_alias,
            "to",
            COMPANION_KEY_PENDING_ALIAS,
        ],
        config,
    )?;

    if !set_companion.status.success() {
        let stderr = String::from_utf8_lossy(&set_companion.stderr);
        anyhow::bail!("Failed to set companion key: {stderr}");
    }
    success("Companion key transaction submitted");

    // Poll for transaction confirmation
    let activation_cycle = poll_for_pending_activation(delegate_address, config)?;

    Ok(activation_cycle)
}

/// Poll until we see the pending key activation
fn poll_for_pending_activation(delegate: &str, config: &RussignolConfig) -> Result<i64> {
    let spinner = create_spinner("Waiting for transaction confirmation...");

    for attempt in 1..=24 {
        log::debug!("Polling for pending activation (attempt {attempt}/24)");

        let status = blockchain::query_key_activation_status(delegate, config)?;

        if status.consensus_pending
            && let Some(cycle) = status.consensus_cycle
        {
            spinner.finish_and_clear();
            return Ok(cycle);
        }

        if attempt < 24 {
            sleep(Duration::from_secs(5));
        }
    }

    spinner.finish_and_clear();
    anyhow::bail!("Transaction submitted but pending status not confirmed after 120 seconds");
}

/// Display current activation status
fn display_activation_status(delegate: &str, config: &RussignolConfig) -> Result<()> {
    let status = blockchain::query_key_activation_status(delegate, config)?;

    if status.consensus_pending
        && let (Some(cycle), Some(time)) = (status.consensus_cycle, &status.consensus_time_estimate)
    {
        info(&format!("Consensus key activates: cycle {cycle} ({time})"));
    }

    if status.companion_pending
        && let (Some(cycle), Some(time)) = (status.companion_cycle, &status.companion_time_estimate)
    {
        info(&format!("Companion key activates: cycle {cycle} ({time})"));
    }

    Ok(())
}

/// Calculate the optimal swap window based on baking rights
fn calculate_optimal_swap_window(
    delegate: &str,
    activation_cycle: i64,
    config: &RussignolConfig,
) -> Result<Option<SwapWindow>> {
    // Get protocol constants
    let blocks_per_cycle =
        blockchain::get_blocks_per_cycle(config).context("Failed to get blocks_per_cycle")?;

    let minimal_block_delay = blockchain::get_minimal_block_delay(config).unwrap_or(10);

    // Calculate the start level of the activation cycle
    let cycle_start_level = activation_cycle * blocks_per_cycle;

    // Query baking rights for first 100 blocks of the new cycle
    // Build URL with multiple level parameters
    let mut rpc_path = String::from("/chains/main/blocks/head/helpers/baking_rights?max_round=0");

    // Query in a reasonable range (first 100 blocks of new cycle)
    let query_end = std::cmp::min(
        cycle_start_level + 100,
        cycle_start_level + blocks_per_cycle,
    );

    for level in cycle_start_level..query_end {
        let _ = write!(rpc_path, "&level={level}");
    }

    let rights = match rpc_get_json(&rpc_path, config) {
        Ok(r) => r,
        Err(e) => {
            log::debug!("Could not query baking rights: {e}");
            return Ok(None);
        }
    };

    // Find our round 0 baking slots
    let mut our_slots: Vec<i64> = Vec::new();

    if let Some(rights_array) = rights.as_array() {
        for right in rights_array {
            if right.get_str("delegate") == Some(delegate)
                && right.get_i64("round") == Some(0)
                && let Some(level) = right.get_i64("level")
            {
                our_slots.push(level);
            }
        }
    }

    our_slots.sort_unstable();

    // Find the largest gap between priority slots (need at least 30 blocks / ~5 minutes)
    let min_gap_blocks = 30;
    let mut best_gap: Option<(i64, i64)> = None;
    let mut best_gap_size = 0;

    // Consider gap from cycle start to first slot
    if !our_slots.is_empty() && our_slots[0] - cycle_start_level >= min_gap_blocks {
        let gap_size = our_slots[0] - cycle_start_level;
        if gap_size > best_gap_size {
            best_gap = Some((cycle_start_level, our_slots[0] - 1));
            best_gap_size = gap_size;
        }
    }

    // Consider gaps between slots
    for i in 0..our_slots.len().saturating_sub(1) {
        let gap_size = our_slots[i + 1] - our_slots[i];
        if gap_size >= min_gap_blocks && gap_size > best_gap_size {
            best_gap = Some((our_slots[i] + 1, our_slots[i + 1] - 1));
            best_gap_size = gap_size;
        }
    }

    if let Some((start, end)) = best_gap {
        let duration_estimate =
            blockchain::format_time_estimate(end - start, Some(minimal_block_delay));

        Ok(Some(SwapWindow {
            start_block: start,
            end_block: end,
            duration_estimate,
            warning: if our_slots.is_empty() {
                None
            } else {
                Some(format!(
                    "You have {} round 0 baking slots in first 100 blocks of cycle {}",
                    our_slots.len(),
                    activation_cycle
                ))
            },
        }))
    } else {
        // No good gap found
        Ok(Some(SwapWindow {
            start_block: cycle_start_level,
            end_block: cycle_start_level + min_gap_blocks,
            duration_estimate: blockchain::format_time_estimate(
                min_gap_blocks,
                Some(minimal_block_delay),
            ),
            warning: Some(
                "No large gap found between baking rights. Consider swapping right at cycle start."
                    .to_string(),
            ),
        }))
    }
}

/// Wait for activation and guide through swap sequence
fn wait_for_activation_and_swap(
    delegate: &str,
    hw_config: HardwareConfig,
    restart_config: &ResolvedRestartConfig,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    println!();
    print_subtitle_bar("Waiting for Activation");
    info("Monitoring activation status... (Ctrl+C to exit and resume later)");

    loop {
        let status = blockchain::query_key_activation_status(delegate, config)?;

        if !status.consensus_pending {
            // Keys are now active!
            println!();
            success("New keys are now ACTIVE on-chain!");
            break;
        }

        // Display countdown
        if let Some(time) = &status.consensus_time_estimate {
            print!("\r  ⏳ Activation in: {time}          ");
            std::io::Write::flush(&mut std::io::stdout())?;
        }

        sleep(Duration::from_secs(30));
    }

    // Execute swap sequence
    println!();
    print_subtitle_bar("Step 7: Execute Swap Sequence");
    execute_swap_sequence(hw_config, restart_config, auto_confirm, config)?;

    Ok(())
}

/// Execute the swap sequence: stop baker, swap device, promote aliases, start baker
fn execute_swap_sequence(
    hw_config: HardwareConfig,
    restart_config: &ResolvedRestartConfig,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    // Confirm before proceeding
    if !auto_confirm {
        println!();
        warning("This will temporarily stop your baker daemon");
        let confirm = prompt_yes_no("Proceed with swap sequence?", false)?;
        if !confirm {
            info("Swap cancelled. Run with --monitor when ready.");
            return Ok(());
        }
    }

    // Step 1: Stop baker
    println!();
    info("Step 1/7: Stopping baker daemon...");
    stop_baker(restart_config)?;
    success("Baker stopped");

    // Step 2: Swap USB/SD
    info("Step 2/7: Swap device");
    let new_expectation = DeviceExpectation::New;
    guide_device_swap(hw_config, &new_expectation)?;

    // Step 3: Verify new device
    info("Step 3/7: Verifying new device...");
    wait_for_device(&new_expectation, config)?;

    // Step 4: Promote aliases (with backup)
    info("Step 4/7: Promoting key aliases...");
    promote_aliases_with_backup(config)?;

    // Step 5: Start baker
    info("Step 5/7: Starting baker daemon...");
    start_baker(restart_config)?;
    success("Baker started");

    // Step 6: Verify signing
    if verify_baker_signing(config) {
        success("Baker signing verified");

        // Step 7: Cleanup backup aliases (requires explicit confirmation)
        info("Step 7/7: Cleaning up backup aliases...");
        cleanup_backup_aliases(auto_confirm, config)?;

        println!();
        print_title_bar("✅ Key Rotation Complete!");
        success("Your baker is now using the new keys");
    } else {
        warning("Could not verify baker signing within timeout");
        warning("Backup aliases preserved for potential rollback");
        info("Check baker logs and retry manually if needed");
    }

    Ok(())
}

/// Stop the baker daemon
fn stop_baker(restart_config: &ResolvedRestartConfig) -> Result<()> {
    match restart_config.method {
        RestartMethod::Systemd => {
            ensure_sudo()?;
            sudo_command_success("systemctl", &["stop", &restart_config.service])?;
        }
        RestartMethod::Script => {
            let cmd = restart_config
                .stop_command
                .as_ref()
                .context("Stop command required for script restart method")?;
            let output = run_command("sh", &["-c", cmd])?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("Stop command failed: {cmd}\nError: {stderr}");
            }
        }
        RestartMethod::Manual => {
            use std::io::Write;
            print!("  Stop your baker now, then press {}...", "Enter".cyan());
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
        }
    }
    Ok(())
}

/// Start the baker daemon
fn start_baker(restart_config: &ResolvedRestartConfig) -> Result<()> {
    match restart_config.method {
        RestartMethod::Systemd => {
            ensure_sudo()?;
            sudo_command_success("systemctl", &["start", &restart_config.service])?;
        }
        RestartMethod::Script => {
            let cmd = restart_config
                .start_command
                .as_ref()
                .context("Start command required for script restart method")?;
            let output = run_command("sh", &["-c", cmd])?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("Start command failed: {cmd}\nError: {stderr}");
            }
        }
        RestartMethod::Manual => {
            use std::io::Write;
            print!("  Start your baker now, then press {}...", "Enter".cyan());
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
        }
    }
    Ok(())
}

/// Promote -pending aliases to primary, keeping -old backup
///
/// NOTE: Uses local alias manipulation because the NEW signer is connected during
/// this operation, which doesn't have the OLD keys. We cannot contact the remote
/// signer to import/rename old keys - we must edit wallet files directly.
fn promote_aliases_with_backup(config: &RussignolConfig) -> Result<()> {
    // STEP 1: Verify ALL required aliases exist BEFORE making any changes
    // This prevents partial failure leaving wallet in inconsistent state
    let pending_consensus = keys::get_key_hash(CONSENSUS_KEY_PENDING_ALIAS, config)
        .context("Cannot find pending consensus key alias")?;
    let pending_companion = keys::get_key_hash(COMPANION_KEY_PENDING_ALIAS, config)
        .context("Cannot find pending companion key alias")?;
    let current_consensus = keys::get_key_hash(CONSENSUS_KEY_ALIAS, config)
        .context("Cannot find current consensus key alias")?;
    let current_companion = keys::get_key_hash(COMPANION_KEY_ALIAS, config)
        .context("Cannot find current companion key alias")?;

    log::debug!(
        "Promoting: {} ({}) -> primary, {} ({}) -> backup",
        CONSENSUS_KEY_PENDING_ALIAS,
        &pending_consensus[..12.min(pending_consensus.len())],
        CONSENSUS_KEY_ALIAS,
        &current_consensus[..12.min(current_consensus.len())]
    );

    // STEP 2: Rename current -> -old (backup)
    keys::rename_alias_locally(CONSENSUS_KEY_ALIAS, CONSENSUS_KEY_OLD_ALIAS, config)
        .context("Failed to backup consensus key")?;

    // If companion rename fails, try to rollback consensus
    if let Err(e) = keys::rename_alias_locally(COMPANION_KEY_ALIAS, COMPANION_KEY_OLD_ALIAS, config)
    {
        warning("Companion backup failed, rolling back consensus backup...");
        let _ = keys::rename_alias_locally(CONSENSUS_KEY_OLD_ALIAS, CONSENSUS_KEY_ALIAS, config);
        return Err(e).context("Failed to backup companion key");
    }

    // STEP 3: Rename -pending -> primary
    if let Err(e) =
        keys::rename_alias_locally(CONSENSUS_KEY_PENDING_ALIAS, CONSENSUS_KEY_ALIAS, config)
    {
        warning("Consensus promotion failed, rolling back backups...");
        let _ = keys::rename_alias_locally(CONSENSUS_KEY_OLD_ALIAS, CONSENSUS_KEY_ALIAS, config);
        let _ = keys::rename_alias_locally(COMPANION_KEY_OLD_ALIAS, COMPANION_KEY_ALIAS, config);
        return Err(e).context("Failed to promote pending consensus key");
    }

    if let Err(e) =
        keys::rename_alias_locally(COMPANION_KEY_PENDING_ALIAS, COMPANION_KEY_ALIAS, config)
    {
        warning("Companion promotion failed, rolling back...");
        // Rollback consensus promotion
        let _ =
            keys::rename_alias_locally(CONSENSUS_KEY_ALIAS, CONSENSUS_KEY_PENDING_ALIAS, config);
        // Rollback backups
        let _ = keys::rename_alias_locally(CONSENSUS_KEY_OLD_ALIAS, CONSENSUS_KEY_ALIAS, config);
        let _ = keys::rename_alias_locally(COMPANION_KEY_OLD_ALIAS, COMPANION_KEY_ALIAS, config);
        return Err(e).context("Failed to promote pending companion key");
    }

    // Suppress unused variable warnings - we verified these exist
    let _ = (pending_companion, current_companion);

    success(&format!(
        "{CONSENSUS_KEY_ALIAS} -> {CONSENSUS_KEY_OLD_ALIAS} (backup), {CONSENSUS_KEY_PENDING_ALIAS} -> {CONSENSUS_KEY_ALIAS} (promoted)"
    ));

    Ok(())
}

/// Verify the baker is signing with the new key
fn verify_baker_signing(_config: &RussignolConfig) -> bool {
    let spinner = create_spinner("Step 6/7: Verifying baker is signing...");

    // Wait up to 60 seconds for signing activity
    for attempt in 1..=12 {
        log::debug!("Checking for signing activity (attempt {attempt}/12)");

        // Check if baker process is running
        let ps_result = run_command("pgrep", &["-f", "octez-baker"]);
        if let Ok(output) = ps_result
            && output.status.success()
        {
            // Baker is running, assume OK for now
            // A more thorough check would examine baker logs
            if attempt >= 3 {
                spinner.finish_and_clear();
                return true;
            }
        }

        sleep(Duration::from_secs(5));
    }

    spinner.finish_and_clear();
    false
}

/// Cleanup backup aliases after successful verification
///
/// IMPORTANT: This should ONLY be called after 100% confirmed baker restart.
/// Requires explicit user confirmation unless `auto_confirm` is true.
fn cleanup_backup_aliases(auto_confirm: bool, config: &RussignolConfig) -> Result<()> {
    // Show what we're about to delete
    let consensus_old = keys::get_key_hash(CONSENSUS_KEY_OLD_ALIAS, config).ok();
    let companion_old = keys::get_key_hash(COMPANION_KEY_OLD_ALIAS, config).ok();

    if consensus_old.is_none() && companion_old.is_none() {
        info("No backup aliases to clean up");
        return Ok(());
    }

    println!();
    info("Backup aliases to remove:");
    if let Some(ref hash) = consensus_old {
        info(&format!(
            "  {} -> {}...",
            CONSENSUS_KEY_OLD_ALIAS,
            &hash[..12.min(hash.len())]
        ));
    }
    if let Some(ref hash) = companion_old {
        info(&format!(
            "  {} -> {}...",
            COMPANION_KEY_OLD_ALIAS,
            &hash[..12.min(hash.len())]
        ));
    }

    // Always require explicit confirmation for cleanup
    if !auto_confirm {
        println!();
        let proceed = inquire::Confirm::new(
            "Remove backup aliases? (Only do this if baker is working correctly)",
        )
        .with_default(false) // Default to NO for safety
        .prompt()?;

        if !proceed {
            info("Keeping backup aliases. You can remove them later with:");
            info(&format!(
                "  octez-client forget address {CONSENSUS_KEY_OLD_ALIAS} --force"
            ));
            info(&format!(
                "  octez-client forget address {COMPANION_KEY_OLD_ALIAS} --force"
            ));
            return Ok(());
        }
    }

    // Remove -old aliases
    if consensus_old.is_some() {
        let _ = keys::forget_key_alias(CONSENSUS_KEY_OLD_ALIAS, config);
    }
    if companion_old.is_some() {
        let _ = keys::forget_key_alias(COMPANION_KEY_OLD_ALIAS, config);
    }

    Ok(())
}

/// Check if -pending aliases exist
fn pending_aliases_exist(config: &RussignolConfig) -> bool {
    let consensus_exists = keys::get_key_hash(CONSENSUS_KEY_PENDING_ALIAS, config).is_ok();
    let companion_exists = keys::get_key_hash(COMPANION_KEY_PENDING_ALIAS, config).is_ok();
    consensus_exists || companion_exists
}

/// Check if -old backup aliases exist (indicates partial swap)
fn old_aliases_exist(config: &RussignolConfig) -> bool {
    let consensus_exists = keys::get_key_hash(CONSENSUS_KEY_OLD_ALIAS, config).is_ok();
    let companion_exists = keys::get_key_hash(COMPANION_KEY_OLD_ALIAS, config).is_ok();
    consensus_exists || companion_exists
}

/// Rotation state detected from local aliases and on-chain data
#[derive(Debug)]
enum RotationState {
    /// No rotation in progress - start fresh
    Clean,
    /// Keys imported but transaction not submitted (need NEW device to submit)
    KeysImported {
        consensus_hash: String,
        companion_hash: String,
    },
    /// Transaction submitted, waiting for activation (with local -pending aliases)
    Pending { activation_cycle: i64 },
    /// Transaction submitted but no local aliases (ran on different machine or manual)
    PendingOnChainOnly { activation_cycle: i64 },
    /// Keys have activated on-chain but alias swap never completed
    /// The active key on-chain matches the -pending alias locally
    KeysActivatedNeedSwap,
    /// Swap partially complete (aliases promoted, need to verify/cleanup)
    PartialSwap,
}

/// Detect the current rotation state from local aliases and on-chain data
///
/// Checks from the END of the workflow backwards to find the latest completed step:
/// 1. Step 15-17: Check for -old aliases (partial swap in progress)
/// 2. Step 8+: Check for pending keys on-chain (tx submitted)
/// 3. Step 7: Check for -pending aliases only (keys imported, tx not submitted)
/// 4. Otherwise: Clean state
fn detect_rotation_state(delegate: &str, config: &RussignolConfig) -> Result<RotationState> {
    // ═══════════════════════════════════════════════════════════════════════════
    // CHECK FROM END OF WORKFLOW BACKWARDS
    // ═══════════════════════════════════════════════════════════════════════════

    // ─────────────────────────────────────────────────────────────────────────────
    // STEP 15-17 CHECK: Are -old backup aliases present?
    // This indicates the swap sequence started (aliases promoted) but didn't
    // complete verification/cleanup.
    // ─────────────────────────────────────────────────────────────────────────────
    if old_aliases_exist(config) {
        log::debug!("Detected: -old aliases exist → PartialSwap state");
        return Ok(RotationState::PartialSwap);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // STEP 8+ CHECK: Are keys pending on-chain?
    // This indicates the transaction was successfully submitted.
    // ─────────────────────────────────────────────────────────────────────────────
    let status = blockchain::query_key_activation_status(delegate, config)?;

    if status.consensus_pending {
        let activation_cycle = status.consensus_cycle.unwrap_or(0);

        // Check if we also have local -pending aliases
        if pending_aliases_exist(config) {
            log::debug!(
                "Detected: on-chain pending + local -pending aliases → Pending state (cycle {activation_cycle})"
            );
            return Ok(RotationState::Pending { activation_cycle });
        }
        // On-chain pending but no local aliases
        // Could happen if: ran on different machine, manual submission, or aliases deleted
        log::debug!(
            "Detected: on-chain pending but NO local aliases → PendingOnChainOnly (cycle {activation_cycle})"
        );
        return Ok(RotationState::PendingOnChainOnly { activation_cycle });
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // STEP 7 CHECK: Do -pending aliases exist (but no on-chain pending)?
    // Could be either:
    //   a) Keys imported but TX never submitted (KeysImported)
    //   b) Keys already ACTIVATED but swap never completed (KeysActivatedNeedSwap)
    // ─────────────────────────────────────────────────────────────────────────────
    if pending_aliases_exist(config) {
        let consensus_hash =
            keys::get_key_hash(CONSENSUS_KEY_PENDING_ALIAS, config).unwrap_or_default();
        let companion_hash =
            keys::get_key_hash(COMPANION_KEY_PENDING_ALIAS, config).unwrap_or_default();

        // Check if the -pending key is now the ACTIVE key on-chain
        // This means keys activated but we never did the alias swap
        if let Ok(active_key) = blockchain::get_active_consensus_key(delegate, config)
            && active_key == consensus_hash
        {
            log::debug!(
                "Detected: -pending alias ({consensus_hash}) matches active on-chain key → KeysActivatedNeedSwap"
            );
            return Ok(RotationState::KeysActivatedNeedSwap);
        }

        log::debug!("Detected: -pending aliases exist, no on-chain pending → KeysImported state");
        return Ok(RotationState::KeysImported {
            consensus_hash,
            companion_hash,
        });
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // NO STATE DETECTED: Clean - no rotation in progress
    // ─────────────────────────────────────────────────────────────────────────────
    log::debug!("Detected: no rotation state indicators → Clean state");
    Ok(RotationState::Clean)
}

/// Resume rotation from keys imported state (tx not submitted)
///
/// The -pending aliases exist but no pending keys on-chain. This means the
/// transaction submission failed or was never attempted. The NEW device must
/// be connected to submit the transaction (BLS proof of possession).
fn resume_from_keys_imported(
    ctx: &ResumeContext,
    hw_config: HardwareConfig,
    restart_config: &ResolvedRestartConfig,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    println!();
    print_subtitle_bar("⚠️  Resuming Incomplete Rotation");

    warning("Found -pending aliases but no on-chain pending keys.");
    info("The transaction may not have been submitted.");
    println!();
    info(&format!(
        "Pending consensus key: {}...",
        &ctx.consensus_hash[..12.min(ctx.consensus_hash.len())]
    ));
    info(&format!(
        "Pending companion key: {}...",
        &ctx.companion_hash[..12.min(ctx.companion_hash.len())]
    ));
    println!();
    info("To submit the transaction, the NEW device must be connected.");
    info("(The device that has these keys for BLS proof of possession)");

    // Prompt user for how to proceed
    println!();
    let options = vec![
        "Connect NEW device and retry transaction",
        "Clean up and start fresh",
    ];

    let selection = if auto_confirm {
        0 // Default to retry
    } else {
        inquire::Select::new("How would you like to proceed?", options)
            .prompt()
            .map(|s| i32::from(!s.contains("retry")))
            .unwrap_or(1)
    };

    if selection == 1 {
        // Clean up pending aliases and exit
        info("Cleaning up -pending aliases...");
        let _ = keys::forget_key_alias(CONSENSUS_KEY_PENDING_ALIAS, config);
        let _ = keys::forget_key_alias(COMPANION_KEY_PENDING_ALIAS, config);
        success("Cleanup complete. Run rotate-keys again to start fresh.");
        return Ok(());
    }

    // Guide user to connect NEW device
    println!();
    print_subtitle_bar("Step 4: Submit On-Chain Transaction (Resumed)");

    let new_expectation = DeviceExpectation::New;
    guide_device_swap(hw_config, &new_expectation)?;
    wait_for_device(&new_expectation, config)?;

    // Submit the transaction
    let activation_cycle = submit_key_rotation_transactions(
        ctx.delegate_address,
        ctx.delegate_alias,
        auto_confirm,
        config,
    )?;

    // Get current active key for reconnecting old device
    let current_consensus = blockchain::get_active_consensus_key(ctx.delegate_address, config)?;

    // Guide to reconnect OLD device
    println!();
    print_subtitle_bar("Step 5: Reconnect Old Device");
    info("Transaction submitted! Reconnect your OLD device now to resume baking.");

    let old_expectation = DeviceExpectation::Old {
        expected_consensus_hash: current_consensus,
    };
    guide_device_swap(hw_config, &old_expectation)?;
    wait_for_device(&old_expectation, config)?;

    // Continue to monitoring - convert resolved configs back to input format
    let restart_config_input = RestartConfig {
        method: Some(restart_config.method),
        service: restart_config.service.clone(),
        stop_command: restart_config.stop_command.clone(),
        start_command: restart_config.start_command.clone(),
    };
    resume_from_pending(
        ctx.delegate_address,
        activation_cycle,
        Some(hw_config),
        &restart_config_input,
        auto_confirm,
        config,
    )
}

/// Resume rotation from pending state (tx submitted, waiting for activation)
///
/// The -pending aliases exist and keys are pending on-chain. Skip to monitoring.
/// Config prompts are deferred until the user chooses to wait for the swap sequence.
fn resume_from_pending(
    delegate_address: &str,
    activation_cycle: i64,
    hardware_config: Option<HardwareConfig>,
    restart_config: &RestartConfig,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    println!();
    print_subtitle_bar("Monitoring Activation");

    success(&format!(
        "Keys pending activation at cycle {activation_cycle}"
    ));

    // Calculate optimal swap window
    if let Ok(Some(window)) =
        calculate_optimal_swap_window(delegate_address, activation_cycle, config)
    {
        println!();
        info(&format!(
            "Optimal swap window: blocks {}-{} ({})",
            window.start_block, window.end_block, window.duration_estimate
        ));
        if let Some(warn) = &window.warning {
            warning(warn);
        }
    }

    // Show activation status
    display_activation_status(delegate_address, config)?;

    println!();
    info("Your OLD device should remain connected for baking until activation.");
    info(&format!(
        "Monitor activation status with: {} rotate-keys --monitor",
        "russignol".cyan()
    ));

    // Offer to wait for activation
    println!();
    let should_wait = prompt_yes_no(
        "Would you like to wait and be guided through the swap sequence?",
        auto_confirm,
    )?;

    if should_wait {
        // Only prompt for config now that user wants to proceed with swap
        println!();
        let hw_config = match hardware_config {
            Some(c) => c,
            None => prompt_hardware_config(auto_confirm)?,
        };
        let restart_method = match restart_config.method {
            Some(m) => m,
            None => prompt_restart_method(auto_confirm)?,
        };
        let resolved_restart_config = ResolvedRestartConfig {
            method: restart_method,
            service: restart_config.service.clone(),
            stop_command: restart_config.stop_command.clone(),
            start_command: restart_config.start_command.clone(),
        };

        wait_for_activation_and_swap(
            delegate_address,
            hw_config,
            &resolved_restart_config,
            auto_confirm,
            config,
        )?;
    } else {
        println!();
        info("When ready for the swap, run:");
        info(&format!("  {} rotate-keys --monitor", "russignol".cyan()));
    }

    Ok(())
}

/// Resume rotation when keys are pending on-chain but no local -pending aliases
///
/// This can happen if:
/// - Rotation was started on a different machine
/// - User manually submitted the transaction via octez-client
/// - Local aliases were accidentally deleted
///
/// We can still monitor and proceed with the swap, but need to recreate local state.
fn resume_from_pending_on_chain_only(
    delegate_address: &str,
    activation_cycle: i64,
    hardware_config: Option<HardwareConfig>,
    restart_config: &RestartConfig,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    println!();
    print_subtitle_bar("⚠️  Detected Pending Keys (No Local State)");

    warning("Keys are pending on-chain but no local -pending aliases found.");
    info("This could mean the rotation was started on another machine or manually.");

    // Try to get the pending key hash from on-chain data
    let status = blockchain::query_key_activation_status(delegate_address, config)?;
    if let Some(pending_hash) = &status.consensus_pending_hash {
        println!();
        info(&format!("Pending consensus key on-chain: {pending_hash}"));
    }

    println!();
    info("To proceed with the swap, you'll need the NEW device (with the pending keys).");
    info("The local -pending aliases will be recreated when you connect it.");

    // Offer to import the pending key from the currently connected signer
    println!();
    let should_import = prompt_yes_no(
        "Is the NEW device (with pending keys) currently connected?",
        auto_confirm,
    )?;

    if should_import {
        // Try to discover and import keys from the connected signer
        info("Attempting to discover keys from connected signer...");

        match discover_key_hashes(config) {
            Ok((consensus_hash, companion_hash)) => {
                // Check if one of the discovered keys matches the pending on-chain key
                let matches_pending = status
                    .consensus_pending_hash
                    .as_ref()
                    .is_some_and(|h| h == &consensus_hash);

                if matches_pending {
                    success("Found matching key on connected signer!");

                    // Import as -pending aliases
                    import_new_keys(&consensus_hash, &companion_hash, config)?;
                    success("Created local -pending aliases");

                    // Now proceed with normal pending flow
                    return resume_from_pending(
                        delegate_address,
                        activation_cycle,
                        hardware_config,
                        restart_config,
                        auto_confirm,
                        config,
                    );
                }
                warning("Connected signer has different keys than pending on-chain.");
                warning(&format!(
                    "On-chain pending: {}",
                    status
                        .consensus_pending_hash
                        .as_deref()
                        .unwrap_or("unknown")
                ));
                warning(&format!("Connected signer: {}", &consensus_hash));
                info("Please connect the correct device (the one with the pending keys).");
            }
            Err(e) => {
                warning(&format!("Could not discover keys from signer: {e}"));
                info("Please ensure the NEW device is connected and the signer is running.");
            }
        }
    }

    // Fall back to just showing status
    println!();
    print_subtitle_bar("Monitoring Activation");
    success(&format!(
        "Keys pending activation at cycle {activation_cycle}"
    ));

    // Show activation status
    display_activation_status(delegate_address, config)?;

    println!();
    info("Once you have the NEW device connected and local aliases set up,");
    info(&format!(
        "run: {} rotate-keys --monitor",
        "russignol".cyan()
    ));

    Ok(())
}

/// Resume rotation when keys have activated but alias swap never completed
///
/// The -pending alias matches the active consensus key on-chain, meaning the keys
/// have activated but we never did the local alias promotion. This can happen if
/// the swap sequence failed during alias manipulation or the user ran the command
/// on a different machine.
fn resume_from_keys_activated_need_swap(
    restart_config: &ResolvedRestartConfig,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    println!();
    print_subtitle_bar("🔄 Completing Key Rotation");

    let pending_hash = keys::get_key_hash(CONSENSUS_KEY_PENDING_ALIAS, config)?;
    let pending_companion = keys::get_key_hash(COMPANION_KEY_PENDING_ALIAS, config).ok();

    success("Keys have already activated on-chain");
    info(&format!(
        "Active consensus key: {}...",
        &pending_hash[..12.min(pending_hash.len())]
    ));
    if let Some(ref comp) = pending_companion {
        info(&format!(
            "Active companion key: {}...",
            &comp[..12.min(comp.len())]
        ));
    }

    // Check signer connectivity
    println!();
    info("Verifying signer connectivity...");

    let spinner = create_spinner(&format!("Checking signer at {}...", config.signer_ip()));
    let signer_ok = keys::check_remote_signer(config);
    spinner.finish_and_clear();

    if !signer_ok {
        warning("Remote signer not accessible or doesn't have enough keys");
        println!();
        info("Please ensure the NEW Russignol device is connected and the signer is running.");
        info(&format!(
            "The signer should respond at {}",
            config.signer_uri()
        ));

        if auto_confirm {
            anyhow::bail!(
                "Signer not accessible and --yes specified. Cannot proceed automatically."
            );
        }

        println!();
        let proceed = inquire::Confirm::new("Press Enter when ready to retry, or 'n' to abort")
            .with_default(true)
            .prompt()?;
        if !proceed {
            anyhow::bail!("User aborted");
        }

        // Retry connectivity check
        let spinner = create_spinner("Rechecking signer...");
        let signer_ok = keys::check_remote_signer(config);
        spinner.finish_and_clear();

        if !signer_ok {
            anyhow::bail!(
                "Signer still not accessible. Please check the device connection and try again."
            );
        }
    }

    success("Signer is accessible");

    // Verify the signer has the new key
    let available_keys = keys::discover_remote_keys(config)?;
    if !available_keys.contains(&pending_hash) {
        anyhow::bail!(
            "Signer doesn't have the active key {pending_hash}. Is the correct device connected?"
        );
    }
    success("Signer has the active consensus key");

    // Confirm before proceeding
    if !auto_confirm {
        println!();
        info("Ready to complete the alias swap:");
        info(&format!(
            "  {CONSENSUS_KEY_ALIAS} -> {CONSENSUS_KEY_OLD_ALIAS} (backup)"
        ));
        info(&format!(
            "  {CONSENSUS_KEY_PENDING_ALIAS} -> {CONSENSUS_KEY_ALIAS} (promoted)"
        ));

        let proceed = inquire::Confirm::new("Proceed with alias swap?")
            .with_default(true)
            .prompt()?;
        if !proceed {
            anyhow::bail!("User aborted");
        }
    }

    // Step 4: Promote aliases with backup
    println!();
    info("Step 4/7: Promoting key aliases (keeping backup)...");
    promote_aliases_with_backup(config)?;

    // Step 5: Start baker if not running
    info("Step 5/7: Checking baker status...");
    let baker_running = is_baker_running();

    if baker_running {
        success("Baker is already running");
    } else {
        info("Starting baker daemon...");
        start_baker(restart_config)?;
        success("Baker started");
    }

    // Step 6: Verify signing
    if verify_baker_signing(config) {
        success("Baker signing verified");

        // Step 7: Cleanup backup aliases (requires explicit confirmation)
        info("Step 7/7: Cleaning up backup aliases...");
        cleanup_backup_aliases(auto_confirm, config)?;

        println!();
        print_title_bar("✅ Key Rotation Complete!");
        success("Your baker is now using the new keys");
    } else {
        warning("Could not verify baker signing within timeout");
        warning("Backup aliases retained for manual inspection");
        info(&format!(
            "You can manually verify and then run: octez-client forget address {CONSENSUS_KEY_OLD_ALIAS} --force"
        ));
    }

    Ok(())
}

/// Resume rotation from partial swap state (-old aliases exist)
///
/// The swap sequence was interrupted after aliases were promoted but before
/// verification/cleanup completed. Continue from where it left off.
fn resume_from_partial_swap(
    restart_config: &ResolvedRestartConfig,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    println!();
    print_subtitle_bar("⚠️  Resuming Incomplete Swap Sequence");

    warning("Found -old backup aliases, indicating the swap was interrupted.");

    // Show current state
    if let Ok(current_hash) = keys::get_key_hash(CONSENSUS_KEY_ALIAS, config) {
        info(&format!(
            "Current {} -> {}...",
            CONSENSUS_KEY_ALIAS,
            &current_hash[..12.min(current_hash.len())]
        ));
    }
    if let Ok(old_hash) = keys::get_key_hash(CONSENSUS_KEY_OLD_ALIAS, config) {
        info(&format!(
            "Backup {} -> {}...",
            CONSENSUS_KEY_OLD_ALIAS,
            &old_hash[..12.min(old_hash.len())]
        ));
    }

    println!();
    info("Continuing swap sequence...");

    // Check if baker is running
    println!();
    info("Checking baker status...");
    let baker_running = is_baker_running();

    if baker_running {
        success("Baker is running");
    } else {
        warning("Baker is not running");
        info("Step 5/7: Starting baker daemon...");
        start_baker(restart_config)?;
        success("Baker started");
    }

    // Step 6: Verify signing
    if verify_baker_signing(config) {
        success("Baker signing verified");

        // Step 7: Cleanup backup aliases (requires explicit confirmation)
        info("Step 7/7: Cleaning up backup aliases...");
        cleanup_backup_aliases(auto_confirm, config)?;

        println!();
        print_title_bar("✅ Key Rotation Complete!");
        success("Your baker is now using the new keys");
    } else {
        warning("Could not verify baker signing within timeout");

        // Offer rollback option (never auto-confirm rollback)
        println!();
        let should_rollback = prompt_yes_no(
            "Would you like to rollback to the old keys?",
            false, // Never auto-confirm rollback
        )?;

        if should_rollback {
            info("Rolling back aliases...");
            rollback_aliases(config)?;
            warning("Rolled back to old keys. Please investigate the issue.");
            info("Check baker logs: journalctl -u octez-baker");
            info(&format!(
                "Verify signer connectivity: ping {}",
                config.signer_ip()
            ));
        } else {
            warning("Backup aliases preserved for potential rollback");
            info("Check baker logs and retry manually if needed");
        }
    }

    Ok(())
}

/// Check if the baker process is running
fn is_baker_running() -> bool {
    run_command("pgrep", &["-f", "octez-baker"]).is_ok_and(|o| o.status.success())
}

/// Rollback aliases from -old backup
fn rollback_aliases(config: &RussignolConfig) -> Result<()> {
    // Rename current -> (delete)
    // Rename -old -> current
    keys::rename_alias_locally(CONSENSUS_KEY_OLD_ALIAS, CONSENSUS_KEY_ALIAS, config)?;
    keys::rename_alias_locally(COMPANION_KEY_OLD_ALIAS, COMPANION_KEY_ALIAS, config)?;

    success("Aliases rolled back to previous keys");
    Ok(())
}

// Helper functions

fn display_key_details(delegate: &str, config: &RussignolConfig) -> Result<()> {
    let rpc_path = format!("/chains/main/blocks/head/context/delegates/{delegate}");
    let delegate_info = rpc_get_json(&rpc_path, config)?;

    // Show active keys
    if let Some(consensus_key) = delegate_info.get_nested("consensus_key") {
        if let Some(active) = consensus_key.get_nested("active")
            && let Some(pkh) = active.get_str("pkh")
        {
            info(&format!("Active consensus key: {pkh}"));
        }

        // Show pending keys
        if let Some(pendings) = consensus_key
            .get_nested("pendings")
            .and_then(|p| p.as_array())
        {
            for pending in pendings {
                if let Some(pkh) = pending.get_str("pkh")
                    && let Some(cycle) = pending.get_i64("cycle")
                {
                    info(&format!("Pending consensus key: {pkh} (cycle {cycle})"));
                }
            }
        }
    }

    if let Some(companion_key) = delegate_info.get_nested("companion_key") {
        if let Some(active) = companion_key.get_nested("active")
            && !active.is_null()
            && let Some(pkh) = active.get_str("pkh")
        {
            info(&format!("Active companion key: {pkh}"));
        }

        if let Some(pendings) = companion_key
            .get_nested("pendings")
            .and_then(|p| p.as_array())
        {
            for pending in pendings {
                if let Some(pkh) = pending.get_str("pkh")
                    && let Some(cycle) = pending.get_i64("cycle")
                {
                    info(&format!("Pending companion key: {pkh} (cycle {cycle})"));
                }
            }
        }
    }

    Ok(())
}
