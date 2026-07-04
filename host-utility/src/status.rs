use anyhow::Result;
use colored::{ColoredString, Colorize};

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

/// Outcome of a yes/no health probe that can also fail to run.
///
/// `Unknown` keeps "the check could not be evaluated" distinct from `Bad` ("the
/// check ran and the answer is no"), so status never renders a red ✗ or exits
/// unhealthy for a component whose state it could not determine.
enum Probe {
    Good,
    Bad,
    Unknown(String),
}

impl Probe {
    fn from_bool(b: bool) -> Self {
        if b { Probe::Good } else { Probe::Bad }
    }

    fn from_result(r: Result<bool>) -> Self {
        match r {
            Ok(true) => Probe::Good,
            Ok(false) => Probe::Bad,
            Err(e) => Probe::Unknown(format!("{e:#}")),
        }
    }
}

/// The glyph a probe renders as, decoupled from the coloured string so the
/// state→marker mapping is unit-testable without ANSI codes.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Marker {
    Ok,
    Bad,
    Unknown,
}

impl Marker {
    fn glyph(self) -> ColoredString {
        match self {
            Marker::Ok => "✓".green(),
            Marker::Bad => "✗".red(),
            Marker::Unknown => "?".yellow(),
        }
    }
}

fn probe_marker(p: &Probe) -> Marker {
    match p {
        Probe::Good => Marker::Ok,
        Probe::Bad => Marker::Bad,
        Probe::Unknown(_) => Marker::Unknown,
    }
}

/// Overall health for the exit code: unhealthy when any probe could not be
/// evaluated (`Unknown`), or a critical component is in a `Bad` state. A `Bad`
/// non-critical probe (e.g. no plugdev membership) still counts as healthy.
fn overall_healthy(probes: &[(&Probe, bool)]) -> bool {
    probes.iter().all(|(p, critical)| match p {
        Probe::Good => true,
        Probe::Bad => !*critical,
        Probe::Unknown(_) => false,
    })
}

/// Run the status command, printing the report and returning whether the system
/// is healthy (see [`overall_healthy`]); `false` maps to a non-zero exit code.
pub fn run_status(verbose: bool, config: &RussignolConfig) -> bool {
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

    // Compute health before display consumes the by-value data structs.
    let healthy = status_is_healthy(
        &system_data,
        &keys_data,
        &connectivity_data,
        &blockchain_data,
        &rights_data,
        &delegate_result,
    );

    // Display all results
    display_hardware_status(verbose, hardware_data);
    display_system_status(verbose, system_data);
    display_connectivity_status(verbose, &connectivity_data, config.signer_uri());
    display_keys_and_blockchain_status(verbose, &delegate_result, &keys_data, &blockchain_data);
    display_baking_rights(verbose, &delegate_result, &rights_data);

    healthy
}

// Data structures to hold fetched results
struct HardwareData {
    device_detected: Result<()>,
    serial: Option<String>,
    mac: Option<String>,
    power_info: Result<Option<hardware::UsbPowerInfo>>,
}

struct SystemData {
    dependencies: Result<()>,
    /// The commands `dependencies` actually checked (endpoint-dependent).
    dependency_list: String,
    node_block: Result<Option<i64>>,
    client_dir: Result<()>,
    plugdev: Probe,
}

struct KeysData {
    consensus: Probe,
    consensus_hash: Option<String>,
    companion: Probe,
    companion_hash: Option<String>,
}

struct BlockchainData {
    delegate_registered: Probe,
    key_activation: Option<blockchain::KeyActivationStatus>,
    staking_info: Option<(i64, i64, f64, bool)>,
}

struct RightsData {
    baking: Result<Option<(i64, String)>>,
    attesting: Result<Option<(i64, String)>>,
}

struct ConnectivityData {
    interface: Probe,
    ip_assigned: Probe,
    remote_signer: Probe,
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
        power_info,
    }
}

fn fetch_system_data(config: &RussignolConfig) -> SystemData {
    let dependencies = crate::deps::verify_dependencies(&config.rpc_endpoint);
    let dependency_list = crate::deps::required_octez_commands(&config.rpc_endpoint)
        .into_iter()
        .chain(crate::constants::SYSTEM_COMMANDS.iter().copied())
        .collect::<Vec<_>>()
        .join(", ");
    let node_block = system::get_node_block_height(config);
    let client_dir = system::verify_octez_client_directory(config);
    let plugdev = match system::check_plugdev_membership() {
        Ok((in_group, _)) => Probe::from_bool(in_group),
        Err(e) => Probe::Unknown(format!("{e:#}")),
    };

    SystemData {
        dependencies,
        dependency_list,
        node_block,
        client_dir,
        plugdev,
    }
}

fn fetch_connectivity_data(config: &RussignolConfig) -> ConnectivityData {
    let interface = Probe::from_bool(hardware::find_russignol_network_interface());
    let ip_assigned = Probe::from_result(crate::phase2::check_ip_assigned());
    // Distinguish "signer unreachable" (Unknown) from "reachable but too few
    // keys" (Bad) so the report and exit code do not conflate the two.
    let remote_signer = match keys::discover_remote_keys(config) {
        Ok(keys) => Probe::from_bool(keys.len() >= 2),
        Err(e) => Probe::Unknown(format!("{e:#}")),
    };

    // Infer which network backend is configured from files on disk
    let network_backend = if std::path::Path::new(NETWORK_CONFIG_PATH).exists() {
        Some("systemd-networkd")
    } else if std::path::Path::new(NM_CONNECTION_PATH).exists() {
        Some("NetworkManager")
    } else {
        None
    };

    ConnectivityData {
        interface,
        ip_assigned,
        remote_signer,
        network_backend,
    }
}

fn fetch_keys_data(config: &RussignolConfig) -> KeysData {
    let consensus = Probe::from_result(keys::check_key_alias_exists(CONSENSUS_KEY_ALIAS, config));
    let companion = Probe::from_result(keys::check_key_alias_exists(COMPANION_KEY_ALIAS, config));

    let consensus_hash = if matches!(consensus, Probe::Good) {
        keys::get_key_hash(CONSENSUS_KEY_ALIAS, config).ok()
    } else {
        None
    };

    let companion_hash = if matches!(companion, Probe::Good) {
        keys::get_key_hash(COMPANION_KEY_ALIAS, config).ok()
    } else {
        None
    };

    KeysData {
        consensus,
        consensus_hash,
        companion,
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
        let delegate_registered =
            Probe::from_result(blockchain::is_registered_delegate(delegate, config));

        BlockchainData {
            delegate_registered,
            key_activation: key_activation.ok(),
            staking_info: staking_info.ok(),
        }
    } else {
        BlockchainData {
            delegate_registered: Probe::Bad,
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
        RightsData {
            baking: blockchain::query_next_baking_rights(delegate, config),
            attesting: blockchain::query_next_attesting_rights(delegate, config),
        }
    } else {
        RightsData {
            baking: Ok(None),
            attesting: Ok(None),
        }
    }
}

/// Probe view of a `Result<_>` that fails only when the query could not run.
fn query_probe<T>(r: &Result<T>) -> Probe {
    match r {
        Ok(_) => Probe::Good,
        Err(e) => Probe::Unknown(format!("{e:#}")),
    }
}

/// Overall health: any `Unknown` probe or any critical `Bad` makes the system
/// unhealthy. Critical components are the imported keys, the node, and the
/// signer; everything else contributes only through its `Unknown` state.
fn status_is_healthy(
    system: &SystemData,
    keys: &KeysData,
    connectivity: &ConnectivityData,
    blockchain: &BlockchainData,
    rights: &RightsData,
    delegate_result: &Result<Option<String>>,
) -> bool {
    let node = query_probe(&system.node_block);
    let delegate = query_probe(delegate_result);
    let baking = query_probe(&rights.baking);
    let attesting = query_probe(&rights.attesting);

    let mut probes: Vec<(&Probe, bool)> = vec![
        (&keys.consensus, true),
        (&keys.companion, true),
        (&node, true),
        (&connectivity.remote_signer, true),
        (&connectivity.interface, false),
        (&connectivity.ip_assigned, false),
        (&system.plugdev, false),
        (&baking, false),
        (&attesting, false),
        (&delegate, false),
    ];
    // Registration only means anything once a delegate address is configured.
    if matches!(delegate_result, Ok(Some(_))) {
        probes.push((&blockchain.delegate_registered, false));
    }

    overall_healthy(&probes)
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
            if let Ok(Some(ref power_info)) = data.power_info {
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
                if let Ok(Some(ref power_info)) = data.power_info {
                    println!("      Device power: {}mA", power_info.device_power_ma);
                    if let Some(ref hub_info) = power_info.hub_info {
                        println!("      Hub power: {}mA", hub_info.hub_power_ma);
                    }
                }
            }

            // A failed power probe must not silently hide an over-budget hub.
            if let Err(ref e) = data.power_info {
                println!("  {} Could not determine USB power budget", "?".yellow());
                if verbose {
                    println!("      Error: {e:#}");
                }
            }

            // Check for power budget warning
            if let Ok(Some(ref power_info)) = data.power_info
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
                "  {} All dependencies available ({})",
                "✓".green(),
                data.dependency_list
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
    match &data.plugdev {
        Probe::Good => {
            println!(
                "  {} User '{}' in plugdev group",
                Marker::Ok.glyph(),
                username
            );
        }
        Probe::Bad => {
            println!(
                "  {} User '{}' not in plugdev group",
                Marker::Bad.glyph(),
                username
            );
        }
        Probe::Unknown(e) => {
            println!(
                "  {} Could not determine plugdev membership for '{}'",
                Marker::Unknown.glyph(),
                username
            );
            if verbose {
                println!("      Error: {e}");
            }
        }
    }

    println!();
}

fn display_connectivity_status(verbose: bool, data: &ConnectivityData, signer_uri: &str) {
    println!("{}", "Connectivity:".bold());

    // Network interface + IP assignment, rendered as a single line.
    let combined_marker = match &data.interface {
        Probe::Good => probe_marker(&data.ip_assigned),
        other => probe_marker(other),
    };
    match (&data.interface, &data.ip_assigned) {
        (Probe::Good, Probe::Good) => {
            println!(
                "  {} Network interface 'russignol' configured (169.254.1.2/30)",
                combined_marker.glyph()
            );
            if verbose {
                println!("      Host IP: 169.254.1.2/30");
                println!("      Signer IP: 169.254.1.1/30");
                if let Some(backend) = data.network_backend {
                    println!("      Backend: {backend}");
                }
            }
        }
        (Probe::Good, Probe::Bad) => {
            println!(
                "  {} Network interface found but IP not assigned",
                combined_marker.glyph()
            );
        }
        (Probe::Good, Probe::Unknown(e)) => {
            println!(
                "  {} Network interface found but IP assignment could not be determined",
                combined_marker.glyph()
            );
            if verbose {
                println!("      Error: {e}");
            }
        }
        (Probe::Unknown(e), _) => {
            println!(
                "  {} Network interface state could not be determined",
                combined_marker.glyph()
            );
            if verbose {
                println!("      Error: {e}");
            }
        }
        (Probe::Bad, _) => {
            println!(
                "  {} Network interface not configured",
                combined_marker.glyph()
            );
        }
    }

    // Check signer connectivity
    let signer_marker = probe_marker(&data.remote_signer);
    match &data.remote_signer {
        Probe::Good => {
            println!("  {} Signer connectivity verified", signer_marker.glyph());
            if verbose {
                println!("      Signer address: {signer_uri}");
            }
        }
        Probe::Bad => {
            println!(
                "  {} Signer reachable but fewer than 2 keys present",
                signer_marker.glyph()
            );
        }
        Probe::Unknown(e) => {
            println!(
                "  {} Signer not accessible at {signer_uri}",
                signer_marker.glyph()
            );
            if verbose {
                println!("      Error: {e}");
            }
        }
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
            match &blockchain_data.delegate_registered {
                Probe::Good => {
                    println!("  {} Baker/Delegate: {} (Registered)", "✓".green(), addr);
                }
                Probe::Bad => {
                    println!(
                        "  {} Baker/Delegate: {} (Not registered)",
                        "?".yellow(),
                        addr
                    );
                }
                Probe::Unknown(e) => {
                    println!(
                        "  {} Baker/Delegate: {} (registration unverified)",
                        "?".yellow(),
                        addr
                    );
                    if verbose {
                        println!("      Error: {e}");
                    }
                }
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
    match &keys_data.consensus {
        Probe::Bad => {
            println!("  {} Consensus key: not imported", Marker::Bad.glyph());
            return;
        }
        Probe::Unknown(e) => {
            println!(
                "  {} Consensus key: could not check wallet",
                Marker::Unknown.glyph()
            );
            if verbose {
                println!("      Error: {e}");
            }
            return;
        }
        Probe::Good => {}
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
    match &keys_data.companion {
        Probe::Bad => {
            println!("  {} Companion key: not imported", Marker::Bad.glyph());
            return;
        }
        Probe::Unknown(e) => {
            println!(
                "  {} Companion key: could not check wallet",
                Marker::Unknown.glyph()
            );
            if verbose {
                println!("      Error: {e}");
            }
            return;
        }
        Probe::Good => {}
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
    verbose: bool,
    delegate_result: &Result<Option<String>>,
    data: &RightsData,
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
    match &data.baking {
        Ok(Some((level, time_estimate))) => {
            println!("  • Next block: level {level} ({time_estimate})");
        }
        Ok(None) => {
            println!("  • No upcoming baking rights found (searched next 2 cycles at round 0)");
        }
        Err(e) => {
            println!(
                "  {} Could not query baking rights (RPC unavailable)",
                "?".yellow()
            );
            if verbose {
                println!("      Error: {e:#}");
            }
        }
    }

    // Display attestation rights
    match &data.attesting {
        Ok(Some((level, time_estimate))) => {
            println!("  • Next attestation: level {level} ({time_estimate})");
        }
        Ok(None) => {
            println!("  • No upcoming attesting rights found");
        }
        Err(e) => {
            println!(
                "  {} Could not query attesting rights (RPC unavailable)",
                "?".yellow()
            );
            if verbose {
                println!("      Error: {e:#}");
            }
        }
    }

    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_marker_maps_each_state() {
        assert_eq!(probe_marker(&Probe::Good), Marker::Ok);
        assert_eq!(probe_marker(&Probe::Bad), Marker::Bad);
        assert_eq!(probe_marker(&Probe::Unknown("x".into())), Marker::Unknown);
    }

    #[test]
    fn overall_healthy_when_every_probe_is_good() {
        assert!(overall_healthy(&[
            (&Probe::Good, true),
            (&Probe::Good, false),
        ]));
    }

    #[test]
    fn any_unknown_probe_is_unhealthy() {
        // Unknown makes the system unhealthy regardless of criticality.
        assert!(!overall_healthy(&[(&Probe::Unknown("x".into()), false)]));
        assert!(!overall_healthy(&[(&Probe::Unknown("x".into()), true)]));
    }

    #[test]
    fn only_critical_bad_probes_are_unhealthy() {
        assert!(!overall_healthy(&[(&Probe::Bad, true)]));
        // A bad non-critical probe (e.g. plugdev) does not fail the exit code.
        assert!(overall_healthy(&[(&Probe::Bad, false)]));
    }
}
