use anyhow::Result;
use colored::Colorize;
use std::sync::mpsc;

// Import shared modules
use crate::blockchain;
use crate::config::RussignolConfig;
use crate::constants::{COMPANION_KEY_ALIAS, CONSENSUS_KEY_ALIAS, USB_VID_PID};
use crate::hardware;
use crate::keys;
use crate::progress::{self, CheckEvent};
use crate::system;
use crate::utils::print_title_bar;

pub fn run_status(verbose: bool, config: &RussignolConfig) {
    // Don't print title and separator yet - progress bar will include title
    println!();

    // Create progress tracking using shared progress module
    let total_checks = 17; // Total number of individual checks
    let (progress_tx, progress_handle) = progress::create_concurrent_progress(total_checks);

    // Fetch all data concurrently with progress tracking
    let tx1 = progress_tx.clone();
    let tx2 = progress_tx.clone();
    let tx3 = progress_tx.clone();
    let tx4 = progress_tx.clone();
    let tx5 = progress_tx.clone();

    let (hardware_data, system_data, connectivity_data, keys_data, delegate_result) =
        std::thread::scope(|s| {
            let config_ref = config;

            let h1 = s.spawn(move || fetch_hardware_data(&tx1));
            let h2 = s.spawn(move || fetch_system_data(&tx2, config_ref));
            let h3 = s.spawn(move || fetch_connectivity_data(&tx3, config_ref));
            let h4 = s.spawn(move || fetch_keys_data(&tx4, config_ref));
            let h5 = s.spawn(move || find_delegate_address_tracked(&tx5, config_ref));

            (
                h1.join().unwrap(),
                h2.join().unwrap(),
                h3.join().unwrap(),
                h4.join().unwrap(),
                h5.join().unwrap(),
            )
        });

    // Fetch blockchain and rights data concurrently (they depend on delegate_result)
    let tx6 = progress_tx.clone();
    let tx7 = progress_tx.clone();

    let (blockchain_data, rights_data) = std::thread::scope(|s| {
        let delegate_ref = &delegate_result;
        let config_ref = config;

        let h6 = s.spawn(move || fetch_blockchain_data(delegate_ref, &tx6, config_ref));
        let h7 = s.spawn(move || fetch_rights_data(delegate_ref, &tx7, config_ref));

        (h6.join().unwrap(), h7.join().unwrap())
    });

    // Drop the main sender to signal completion
    drop(progress_tx);

    // Wait for progress indicator to finish
    let _ = progress_handle.join();

    // NOW print the title and separator (progress line was cleared)
    print_title_bar("🔐 Russignol Signer Status");

    // Display all results sequentially (no interleaved output)
    display_hardware_status(verbose, hardware_data);
    display_system_status(verbose, system_data);
    display_connectivity_status(verbose, &connectivity_data, config.signer_uri());
    display_keys_and_blockchain_status(verbose, &delegate_result, &keys_data, &blockchain_data);
    display_baking_rights(verbose, &delegate_result, rights_data);
}

// Data structures to hold fetched results
struct HardwareData {
    device_detected: Result<()>,
    serial: Option<String>,
    mac: Option<String>,
}

struct SystemData {
    dependencies: Result<()>,
    node_block: Result<Option<i64>>,
    client_dir: Result<()>,
    plugdev: Result<()>,
}

struct KeysData {
    consensus_exists: bool,
    consensus_hash: Option<String>,
    companion_exists: bool,
    companion_hash: Option<String>,
}

struct BlockchainData {
    delegate_registered: bool,
    key_activation: Option<blockchain::KeyActivationStatus>,
    staking_info: Option<(i64, i64, f64, bool)>,
}

struct RightsData {
    baking: Option<(i64, String)>,
    attesting: Option<(i64, String)>,
}

struct ConnectivityData {
    interface_ok: bool,
    ip_assigned: bool,
    remote_signer: bool,
}

// Fetch functions (run concurrently)
fn fetch_hardware_data(progress: &mpsc::Sender<CheckEvent>) -> HardwareData {
    let tx1 = progress.clone();
    let tx2 = progress.clone();
    let tx3 = progress.clone();

    let (device_detected, serial, mac) = std::thread::scope(|s| {
        let h1 = s.spawn(move || {
            let _ = tx1.send(CheckEvent::Started("Detecting USB"));
            let result = hardware::detect_hardware_device();
            let _ = tx1.send(CheckEvent::Completed("Detecting USB"));
            result
        });

        let h2 = s.spawn(move || {
            let _ = tx2.send(CheckEvent::Started("Reading serial"));
            let result = hardware::get_usb_serial_number();
            let _ = tx2.send(CheckEvent::Completed("Reading serial"));
            result
        });

        let h3 = s.spawn(move || {
            let _ = tx3.send(CheckEvent::Started("Reading MAC"));
            let result = hardware::get_mac_address();
            let _ = tx3.send(CheckEvent::Completed("Reading MAC"));
            result
        });

        (h1.join().unwrap(), h2.join().unwrap(), h3.join().unwrap())
    });

    HardwareData {
        device_detected,
        serial: serial.ok().flatten(),
        mac: mac.ok().flatten(),
    }
}

fn fetch_system_data(progress: &mpsc::Sender<CheckEvent>, config: &RussignolConfig) -> SystemData {
    let tx1 = progress.clone();
    let tx2 = progress.clone();
    let tx3 = progress.clone();
    let tx4 = progress.clone();

    let (dependencies, node_block, client_dir, plugdev) = std::thread::scope(|s| {
        let config_ref = config;

        let h1 = s.spawn(move || {
            let _ = tx1.send(CheckEvent::Started("Verifying deps"));
            let result = system::verify_dependencies();
            let _ = tx1.send(CheckEvent::Completed("Verifying deps"));
            result
        });

        let h2 = s.spawn(move || {
            let _ = tx2.send(CheckEvent::Started("Checking node"));
            let result = system::get_node_block_height(config_ref);
            let _ = tx2.send(CheckEvent::Completed("Checking node"));
            result
        });

        let h3 = s.spawn(move || {
            let _ = tx3.send(CheckEvent::Started("Checking client"));
            let result = system::verify_octez_client_directory(config_ref);
            let _ = tx3.send(CheckEvent::Completed("Checking client"));
            result
        });

        let h4 = s.spawn(move || {
            let _ = tx4.send(CheckEvent::Started("Checking plugdev"));
            let result = system::check_plugdev_membership().and_then(|(in_group, _)| {
                if in_group {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Not in plugdev"))
                }
            });
            let _ = tx4.send(CheckEvent::Completed("Checking plugdev"));
            result
        });

        (
            h1.join().unwrap(),
            h2.join().unwrap(),
            h3.join().unwrap(),
            h4.join().unwrap(),
        )
    });

    SystemData {
        dependencies,
        node_block,
        client_dir,
        plugdev,
    }
}

fn fetch_connectivity_data(
    progress: &mpsc::Sender<CheckEvent>,
    config: &RussignolConfig,
) -> ConnectivityData {
    let tx1 = progress.clone();
    let tx2 = progress.clone();
    let tx3 = progress.clone();

    let (interface_ok, ip_assigned, remote_signer) = std::thread::scope(|s| {
        let config_ref = config;

        let h1 = s.spawn(move || {
            let _ = tx1.send(CheckEvent::Started("Finding interface"));
            let result = hardware::find_russignol_network_interface();
            let _ = tx1.send(CheckEvent::Completed("Finding interface"));
            result
        });

        let h2 = s.spawn(move || {
            let _ = tx2.send(CheckEvent::Started("Checking IP"));
            let result = crate::phase2::check_ip_assigned();
            let _ = tx2.send(CheckEvent::Completed("Checking IP"));
            result
        });

        let h3 = s.spawn(move || {
            let _ = tx3.send(CheckEvent::Started("Pinging signer"));
            let result = keys::check_remote_signer(config_ref);
            let _ = tx3.send(CheckEvent::Completed("Pinging signer"));
            result
        });

        (h1.join().unwrap(), h2.join().unwrap(), h3.join().unwrap())
    });

    ConnectivityData {
        interface_ok,
        ip_assigned: ip_assigned.unwrap_or(false),
        remote_signer,
    }
}

fn fetch_keys_data(progress: &mpsc::Sender<CheckEvent>, config: &RussignolConfig) -> KeysData {
    let tx1 = progress.clone();
    let tx2 = progress.clone();

    // Check if keys exist
    let (consensus_exists, companion_exists) = std::thread::scope(|s| {
        let config_ref = config;

        let h1 = s.spawn(move || {
            let _ = tx1.send(CheckEvent::Started("Checking consensus"));
            let result = keys::check_key_alias_exists(CONSENSUS_KEY_ALIAS, config_ref);
            let _ = tx1.send(CheckEvent::Completed("Checking consensus"));
            result
        });

        let h2 = s.spawn(move || {
            let _ = tx2.send(CheckEvent::Started("Checking companion"));
            let result = keys::check_key_alias_exists(COMPANION_KEY_ALIAS, config_ref);
            let _ = tx2.send(CheckEvent::Completed("Checking companion"));
            result
        });

        (h1.join().unwrap(), h2.join().unwrap())
    });

    // Then fetch hashes for existing keys (these are quick operations, no progress update needed)
    let consensus_hash = if consensus_exists {
        keys::get_key_hash(CONSENSUS_KEY_ALIAS, config).ok()
    } else {
        None
    };

    let companion_hash = if companion_exists {
        keys::get_key_hash(COMPANION_KEY_ALIAS, config).ok()
    } else {
        None
    };

    KeysData {
        consensus_exists,
        consensus_hash,
        companion_exists,
        companion_hash,
    }
}

fn find_delegate_address_tracked(
    progress: &mpsc::Sender<CheckEvent>,
    config: &RussignolConfig,
) -> Result<Option<String>> {
    let _ = progress.send(CheckEvent::Started("Finding delegate"));
    let result = blockchain::find_delegate_address(config);
    let _ = progress.send(CheckEvent::Completed("Finding delegate"));
    result
}

fn fetch_blockchain_data(
    delegate_result: &Result<Option<String>>,
    progress: &mpsc::Sender<CheckEvent>,
    config: &RussignolConfig,
) -> BlockchainData {
    if let Ok(Some(delegate)) = delegate_result {
        let tx1 = progress.clone();
        let tx2 = progress.clone();

        let (key_activation, staking_info) = std::thread::scope(|s| {
            let delegate_ref = delegate;
            let config_ref = config;

            let h1 = s.spawn(move || {
                let _ = tx1.send(CheckEvent::Started("Querying activation"));
                let result = blockchain::query_key_activation_status(delegate_ref, config_ref);
                let _ = tx1.send(CheckEvent::Completed("Querying activation"));
                result
            });

            let h2 = s.spawn(move || {
                let _ = tx2.send(CheckEvent::Started("Querying staking"));
                let result = blockchain::query_staking_info(delegate_ref, config_ref);
                let _ = tx2.send(CheckEvent::Completed("Querying staking"));
                result
            });

            (h1.join().unwrap(), h2.join().unwrap())
        });

        // Check if delegate is registered (doesn't require extra progress notification)
        let delegate_registered = blockchain::is_registered_delegate(delegate, config);

        BlockchainData {
            delegate_registered,
            key_activation: key_activation.ok(),
            staking_info: staking_info.ok(),
        }
    } else {
        // Still count these as "checked" even if skipped (send start+complete for each)
        let _ = progress.send(CheckEvent::Started("Querying activation"));
        let _ = progress.send(CheckEvent::Completed("Querying activation"));
        let _ = progress.send(CheckEvent::Started("Querying staking"));
        let _ = progress.send(CheckEvent::Completed("Querying staking"));

        BlockchainData {
            delegate_registered: false,
            key_activation: None,
            staking_info: None,
        }
    }
}

fn fetch_rights_data(
    delegate_result: &Result<Option<String>>,
    progress: &mpsc::Sender<CheckEvent>,
    config: &RussignolConfig,
) -> RightsData {
    if let Ok(Some(delegate)) = delegate_result {
        let tx1 = progress.clone();
        let tx2 = progress.clone();

        let (baking, attesting) = std::thread::scope(|s| {
            let delegate_ref = delegate;
            let config_ref = config;

            let h1 = s.spawn(move || {
                let _ = tx1.send(CheckEvent::Started("Fetching baking"));
                let result = blockchain::query_next_baking_rights(delegate_ref, config_ref);
                let _ = tx1.send(CheckEvent::Completed("Fetching baking"));
                result
            });

            let h2 = s.spawn(move || {
                let _ = tx2.send(CheckEvent::Started("Fetching attesting"));
                let result = blockchain::query_next_attesting_rights(delegate_ref, config_ref);
                let _ = tx2.send(CheckEvent::Completed("Fetching attesting"));
                result
            });

            (h1.join().unwrap(), h2.join().unwrap())
        });

        RightsData {
            baking: baking.ok().flatten(),
            attesting: attesting.ok().flatten(),
        }
    } else {
        // Still count these as "checked" even if skipped (send start+complete for each)
        let _ = progress.send(CheckEvent::Started("Fetching baking"));
        let _ = progress.send(CheckEvent::Completed("Fetching baking"));
        let _ = progress.send(CheckEvent::Started("Fetching attesting"));
        let _ = progress.send(CheckEvent::Completed("Fetching attesting"));

        RightsData {
            baking: None,
            attesting: None,
        }
    }
}

fn display_hardware_status(verbose: bool, data: HardwareData) {
    println!("{}", "Hardware:".bold());

    // Check for hardware device
    match data.device_detected {
        Ok(()) => {
            println!("  {} Russignol Signer USB device detected", "✓".green());

            if let Some(serial) = data.serial {
                println!("      Serial: {serial}");
            }
            if let Some(mac) = data.mac {
                println!("      MAC address: {mac}");
            }

            if verbose {
                println!("      VID:PID: {USB_VID_PID}");
            }
        }
        Err(e) => {
            println!("  {} Russignol Signer USB device not detected", "✗".red());
            if verbose {
                println!("      Error: {e}");
            }
        }
    }

    println!();
}

fn display_system_status(verbose: bool, data: SystemData) {
    println!("{}", "System Configuration:".bold());

    // Check dependencies
    match data.dependencies {
        Ok(()) => {
            println!(
                "  {} All dependencies available (octez-client, octez-node, ps, grep, ip, ping, udevadm, lsusb)",
                "✓".green()
            );
        }
        Err(e) => {
            println!("  {} Missing dependencies", "✗".red());
            if verbose {
                println!("      Error: {e}");
            }
        }
    }

    // Check octez-node
    match data.node_block {
        Ok(Some(level)) => {
            println!(
                "  {} Octez node running and synced (block {})",
                "✓".green(),
                level
            );
        }
        Ok(None) => {
            println!("  {} Octez node running and synced", "✓".green());
        }
        Err(e) => {
            println!("  {} Octez node not available", "✗".red());
            if verbose {
                println!("      Error: {e}");
            }
        }
    }

    // Check octez-client directory
    match data.client_dir {
        Ok(()) => {
            println!("  {} Octez client directory configured", "✓".green());
            if verbose {
                let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
                println!("      Directory: {home}/.tezos-client");
            }
        }
        Err(e) => {
            println!("  {} Octez client directory missing", "✗".red());
            if verbose {
                println!("      Error: {e}");
            }
        }
    }

    // Check plugdev membership
    let username = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    match data.plugdev {
        Ok(()) => {
            println!("  {} User '{}' in plugdev group", "✓".green(), username);
        }
        Err(e) => {
            println!("  {} User '{}' not in plugdev group", "✗".red(), username);
            if verbose {
                println!("      Error: {e}");
            }
        }
    }

    println!();
}

fn display_connectivity_status(verbose: bool, data: &ConnectivityData, signer_uri: &str) {
    println!("{}", "Connectivity:".bold());

    // Check network interface and IP assignment
    if data.interface_ok && data.ip_assigned {
        println!(
            "  {} Network interface 'russignol' configured (169.254.1.2/30)",
            "✓".green()
        );
        if verbose {
            println!("      Host IP: 169.254.1.2/30");
            println!("      Signer IP: 169.254.1.1/30");
        }
    } else if data.interface_ok {
        println!(
            "  {} Network interface found but IP not assigned",
            "✗".red()
        );
    } else {
        println!("  {} Network interface not configured", "✗".red());
    }

    // Check signer connectivity
    if data.remote_signer {
        println!("  {} Signer connectivity verified", "✓".green());
        if verbose {
            println!("      Signer address: {signer_uri}");
        }
    } else {
        println!("  {} Signer not accessible at {signer_uri}", "✗".red());
    }

    println!();
}

fn display_keys_and_blockchain_status(
    verbose: bool,
    delegate_result: &Result<Option<String>>,
    keys_data: &KeysData,
    blockchain_data: &BlockchainData,
) {
    println!("{}", "Keys & Blockchain Status:".bold());

    if !display_delegate_status(verbose, delegate_result, blockchain_data) {
        return;
    }

    display_consensus_key_status(verbose, keys_data, blockchain_data);
    display_companion_key_status(verbose, keys_data, blockchain_data);
    display_staking_status(verbose, blockchain_data);

    println!();
}

/// Returns false if we should return early (no delegate configured)
fn display_delegate_status(
    verbose: bool,
    delegate_result: &Result<Option<String>>,
    blockchain_data: &BlockchainData,
) -> bool {
    match delegate_result {
        Ok(Some(addr)) => {
            if blockchain_data.delegate_registered {
                println!("  {} Baker/Delegate: {} (Registered)", "✓".green(), addr);
            } else {
                println!(
                    "  {} Baker/Delegate: {} (Not registered)",
                    "?".yellow(),
                    addr
                );
            }
            true
        }
        Ok(None) => {
            println!("  {} Baker/Delegate: not configured", "?".yellow());
            if verbose {
                println!("      No baker key found");
            }
            println!();
            false
        }
        Err(e) => {
            println!(
                "  {} Could not query baker/delegate status (RPC unavailable)",
                "?".yellow()
            );
            if verbose {
                println!("      Error: {e}");
            }
            println!();
            false
        }
    }
}

fn display_consensus_key_status(
    verbose: bool,
    keys_data: &KeysData,
    blockchain_data: &BlockchainData,
) {
    if !keys_data.consensus_exists {
        println!("  {} Consensus key: not imported", "✗".red());
        return;
    }

    let key_info = keys_data.consensus_hash.as_ref().map_or_else(
        || CONSENSUS_KEY_ALIAS.to_string(),
        |hash| format!("{CONSENSUS_KEY_ALIAS} ({hash})"),
    );

    match &blockchain_data.key_activation {
        Some(status) if status.consensus_pending => {
            println!(
                "  {} Consensus key: {} - Pending (cycle {})",
                "⏳".yellow(),
                key_info,
                status.consensus_cycle.unwrap()
            );
            if verbose {
                println!(
                    "      Activation: {}",
                    status.consensus_time_estimate.as_ref().unwrap()
                );
            }
        }
        Some(_) => {
            println!("  {} Consensus key: {} - Active", "✓".green(), key_info);
        }
        None => {
            println!(
                "  {} Consensus key: {} - Activation status unavailable",
                "?".yellow(),
                key_info
            );
        }
    }
}

fn display_companion_key_status(
    verbose: bool,
    keys_data: &KeysData,
    blockchain_data: &BlockchainData,
) {
    if !keys_data.companion_exists {
        println!("  {} Companion key: not imported", "✗".red());
        return;
    }

    let key_info = keys_data.companion_hash.as_ref().map_or_else(
        || COMPANION_KEY_ALIAS.to_string(),
        |hash| format!("{COMPANION_KEY_ALIAS} ({hash})"),
    );

    match &blockchain_data.key_activation {
        Some(status) if status.companion_pending => {
            println!(
                "  {} Companion key: {} - Pending (cycle {})",
                "⏳".yellow(),
                key_info,
                status.companion_cycle.unwrap()
            );
            if verbose {
                println!(
                    "      Activation: {}",
                    status.companion_time_estimate.as_ref().unwrap()
                );
            }
        }
        Some(status) if status.companion_active => {
            println!("  {} Companion key: {} - Active", "✓".green(), key_info);
        }
        Some(_) => {
            println!("  {} Companion key: {} - Not set", "?".yellow(), key_info);
        }
        None => {
            println!(
                "  {} Companion key: {} - Activation status unavailable",
                "?".yellow(),
                key_info
            );
        }
    }
}

fn display_staking_status(verbose: bool, blockchain_data: &BlockchainData) {
    match blockchain_data.staking_info {
        Some((staked, total, percentage, staking_enabled)) => {
            if staking_enabled {
                println!(
                    "  {} Staking: {} ꜩ ({:.1}% of balance)",
                    "✓".green(),
                    blockchain::format_tez(staked),
                    percentage
                );
                if verbose {
                    println!("      Total balance: {} ꜩ", blockchain::format_tez(total));
                    println!("      Staked amount: {} ꜩ", blockchain::format_tez(staked));
                }
            } else {
                println!("  {} Staking: not enabled", "?".yellow());
                if verbose {
                    println!("      Total balance: {} ꜩ", blockchain::format_tez(total));
                }
            }
        }
        None => {
            println!(
                "  {} Could not query staking info (RPC unavailable)",
                "?".yellow()
            );
        }
    }
}

fn display_baking_rights(
    _verbose: bool,
    delegate_result: &Result<Option<String>>,
    data: RightsData,
) {
    println!("{}", "Baking Rights:".bold());

    // Use pre-fetched delegate address
    match delegate_result {
        Ok(Some(addr)) => {
            // Always show which delegate is being queried
            println!("  Delegate: {addr}");
        }
        Ok(None) => {
            println!("  {} No delegate configured", "?".yellow());
            println!();
            return;
        }
        Err(_) => {
            println!("  {} Could not query (RPC unavailable)", "?".yellow());
            println!();
            return;
        }
    }

    // Display baking rights
    match data.baking {
        Some((level, time_estimate)) => {
            println!("  • Next block: level {level} ({time_estimate})");
        }
        None => {
            println!("  • No upcoming baking rights found (searched next 2 cycles at round 0)");
        }
    }

    // Display attestation rights
    match data.attesting {
        Some((level, time_estimate)) => {
            println!("  • Next attestation: level {level} ({time_estimate})");
        }
        None => {
            println!("  • No upcoming attesting rights found");
        }
    }

    println!();
}

// All helper functions now use shared modules:
// - hardware::{get_usb_serial_number, get_mac_address}
// - system::{get_node_block_height, check_plugdev_membership}
// - keys::{check_key_alias_exists, get_key_hash, check_remote_signer}
// - blockchain::{find_delegate_address, is_registered_delegate, query_staking_info, format_tez}
