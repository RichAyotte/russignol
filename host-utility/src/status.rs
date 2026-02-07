use anyhow::Result;
use colored::Colorize;

// Import shared modules
use crate::blockchain;
use crate::config::RussignolConfig;
use crate::constants::{
    COMPANION_KEY_ALIAS, CONSENSUS_KEY_ALIAS, NETWORK_CONFIG_PATH, NM_CONNECTION_PATH, USB_VID_PID,
};
use crate::hardware;
use crate::keys;
use crate::progress;
use crate::system;
use crate::utils::print_title_bar;

pub fn run_status(verbose: bool, config: &RussignolConfig) {
    println!();

    let spinner = progress::create_spinner("Gathering status...");

    // Fetch all data sequentially
    spinner.set_message("Checking hardware...");
    let hardware_data = fetch_hardware_data();

    spinner.set_message("Checking system...");
    let system_data = fetch_system_data(config);

    spinner.set_message("Checking connectivity...");
    let connectivity_data = fetch_connectivity_data(config);

    spinner.set_message("Checking keys...");
    let keys_data = fetch_keys_data(config);

    spinner.set_message("Finding delegate...");
    let delegate_result = blockchain::find_delegate_address(config);

    spinner.set_message("Querying blockchain...");
    let blockchain_data = fetch_blockchain_data(&delegate_result, config);

    spinner.set_message("Fetching baking rights...");
    let rights_data = fetch_rights_data(&delegate_result, config);

    spinner.finish_and_clear();

    print_title_bar("🔐 Russignol Signer Status");

    // Display all results
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
    power_info: Option<hardware::UsbPowerInfo>,
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
    network_backend: Option<&'static str>,
}

// Fetch functions
fn fetch_hardware_data() -> HardwareData {
    let device_detected = hardware::detect_hardware_device();
    let serial = hardware::get_usb_serial_number();
    let mac = hardware::get_mac_address();
    let power_info = hardware::get_usb_power_info();

    HardwareData {
        device_detected,
        serial: serial.ok().flatten(),
        mac: mac.ok().flatten(),
        power_info: power_info.ok().flatten(),
    }
}

fn fetch_system_data(config: &RussignolConfig) -> SystemData {
    let dependencies = system::verify_dependencies();
    let node_block = system::get_node_block_height(config);
    let client_dir = system::verify_octez_client_directory(config);
    let plugdev = system::check_plugdev_membership().and_then(|(in_group, _)| {
        if in_group {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Not in plugdev"))
        }
    });

    SystemData {
        dependencies,
        node_block,
        client_dir,
        plugdev,
    }
}

fn fetch_connectivity_data(config: &RussignolConfig) -> ConnectivityData {
    let interface_ok = hardware::find_russignol_network_interface();
    let ip_assigned = crate::phase2::check_ip_assigned();
    let remote_signer = keys::check_remote_signer(config);

    // Infer which network backend is configured from files on disk
    let network_backend = if std::path::Path::new(NETWORK_CONFIG_PATH).exists() {
        Some("systemd-networkd")
    } else if std::path::Path::new(NM_CONNECTION_PATH).exists() {
        Some("NetworkManager")
    } else {
        None
    };

    ConnectivityData {
        interface_ok,
        ip_assigned: ip_assigned.unwrap_or(false),
        remote_signer,
        network_backend,
    }
}

fn fetch_keys_data(config: &RussignolConfig) -> KeysData {
    let consensus_exists = keys::check_key_alias_exists(CONSENSUS_KEY_ALIAS, config);
    let companion_exists = keys::check_key_alias_exists(COMPANION_KEY_ALIAS, config);

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

fn fetch_blockchain_data(
    delegate_result: &Result<Option<String>>,
    config: &RussignolConfig,
) -> BlockchainData {
    if let Ok(Some(delegate)) = delegate_result {
        let key_activation = blockchain::query_key_activation_status(delegate, config);
        let staking_info = blockchain::query_staking_info(delegate, config);
        let delegate_registered = blockchain::is_registered_delegate(delegate, config);

        BlockchainData {
            delegate_registered,
            key_activation: key_activation.ok(),
            staking_info: staking_info.ok(),
        }
    } else {
        BlockchainData {
            delegate_registered: false,
            key_activation: None,
            staking_info: None,
        }
    }
}

fn fetch_rights_data(
    delegate_result: &Result<Option<String>>,
    config: &RussignolConfig,
) -> RightsData {
    if let Ok(Some(delegate)) = delegate_result {
        let baking = blockchain::query_next_baking_rights(delegate, config);
        let attesting = blockchain::query_next_attesting_rights(delegate, config);

        RightsData {
            baking: baking.ok().flatten(),
            attesting: attesting.ok().flatten(),
        }
    } else {
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

            // Display USB connection info
            if let Some(ref power_info) = data.power_info {
                if power_info.behind_hub {
                    if let Some(ref hub_info) = power_info.hub_info {
                        let power_type = if hub_info.is_bus_powered {
                            "bus-powered"
                        } else {
                            "self-powered"
                        };
                        println!(
                            "      USB connection: Through {} hub ({})",
                            power_type, hub_info.hub_path
                        );
                    } else {
                        println!("      USB connection: Through hub");
                    }
                } else {
                    println!("      USB connection: Direct");
                }
            }

            if verbose {
                println!("      VID:PID: {USB_VID_PID}");
                if let Some(ref power_info) = data.power_info {
                    println!("      Device power: {}mA", power_info.device_power_ma);
                    if let Some(ref hub_info) = power_info.hub_info {
                        println!("      Hub power: {}mA", hub_info.hub_power_ma);
                    }
                }
            }

            // Check for power budget warning
            if let Some(ref power_info) = data.power_info
                && let Some(ref hub_info) = power_info.hub_info
                && hub_info.is_bus_powered
                && hub_info.total_power_draw_ma > hub_info.power_budget_ma
            {
                println!(
                    "  {} Bus-powered hub - power budget exceeded ({}mA / {}mA)",
                    "⚠".yellow(),
                    hub_info.total_power_draw_ma,
                    hub_info.power_budget_ma
                );
                println!("      Devices on hub:");
                for device in &hub_info.devices {
                    let suffix = if device.path == power_info.device_path {
                        " (this device)"
                    } else {
                        ""
                    };
                    println!(
                        "        {:<24} {:>3}mA{}",
                        device.product, device.power_ma, suffix
                    );
                }
                println!(
                    "      Remove other devices, use a self-powered hub, or connect directly."
                );
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
            if let Some(backend) = data.network_backend {
                println!("      Backend: {backend}");
            }
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
