use crate::backup;
use crate::constants::{
    NETWORK_CONFIG_PATH, NETWORKMANAGER_CONFIG_PATH, NM_CONNECTION_PATH, UDEV_RULE_PATH,
};
use crate::hardware;
use crate::progress::run_step;
use crate::system;
use crate::utils::{
    command_exists, ensure_sudo, is_service_active, run_command, sudo_command_quiet,
    sudo_command_success_quiet,
};
use anyhow::{Context, Result};
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

// Udev rule content
const UDEV_RULE_CONTENT: &str = r#"SUBSYSTEM=="net", ACTION=="add", ATTRS{idVendor}=="1d6b", ATTRS{idProduct}=="0104", ATTRS{manufacturer}=="Russignol", NAME="russignol"
"#;

// Network configuration content
const NETWORK_CONFIG_CONTENT: &str = r"[Match]
Name=russignol

[Link]
RequiredForOnline=no

[Network]
Address=169.254.1.2/30
LinkLocalAddressing=no
IPv6AcceptRA=no
";

// NetworkManager configuration content (unmanaged — used with systemd-networkd backend)
const NETWORKMANAGER_CONFIG_CONTENT: &str = r"[keyfile]
unmanaged-devices=interface-name:russignol
";

// NetworkManager connection profile (used with NetworkManager backend)
const NM_CONNECTION_CONTENT: &str = r"[connection]
id=russignol
type=ethernet
interface-name=russignol
autoconnect=yes

[ipv4]
method=manual
addresses=169.254.1.2/30

[ipv6]
method=disabled
";

/// Which network management service is in use on this system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NetworkBackend {
    /// systemd-networkd
    #[value(name = "networkd")]
    SystemdNetworkd,
    /// `NetworkManager`
    #[value(name = "nm")]
    NetworkManager,
}

impl std::fmt::Display for NetworkBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkBackend::SystemdNetworkd => write!(f, "networkd"),
            NetworkBackend::NetworkManager => write!(f, "nm"),
        }
    }
}

/// Detect the active network management backend.
///
/// If `override_backend` is `Some`, returns it immediately.
/// Otherwise prefers systemd-networkd if both are running (preserves existing behaviour).
/// Bails if neither is active or if `systemctl` is missing.
fn detect_network_backend(override_backend: Option<NetworkBackend>) -> Result<NetworkBackend> {
    if let Some(backend) = override_backend {
        return Ok(backend);
    }

    anyhow::ensure!(
        command_exists("systemctl"),
        "systemctl not found — cannot detect network backend"
    );

    if is_service_active("systemd-networkd") {
        return Ok(NetworkBackend::SystemdNetworkd);
    }

    if is_service_active("NetworkManager") {
        anyhow::ensure!(
            command_exists("nmcli"),
            "NetworkManager is active but nmcli is not installed"
        );
        return Ok(NetworkBackend::NetworkManager);
    }

    anyhow::bail!("Neither systemd-networkd nor NetworkManager is running")
}

// Helper function to check if a file needs to be updated
fn file_needs_update(path: &str, expected_content: &str) -> bool {
    match std::fs::read_to_string(path) {
        Ok(current_content) => current_content != expected_content,
        Err(_) => true, // File doesn't exist or can't be read, needs update
    }
}

pub fn run(
    backup_dir: &Path,
    config: &crate::confirmation::ConfirmationConfig,
    russignol_config: &crate::config::RussignolConfig,
    network_backend_override: Option<NetworkBackend>,
) -> Result<()> {
    // Skip network setup when using a remote signer
    if russignol_config.signer_endpoint.is_some() {
        log::info!(
            "Skipping network setup (using remote signer at {})",
            russignol_config.signer_uri()
        );
        return Ok(());
    }

    let backend = detect_network_backend(network_backend_override)?;
    log::info!("Detected network backend: {backend:?}");

    let udev_needs_update = file_needs_update(UDEV_RULE_PATH, UDEV_RULE_CONTENT);
    let network_files_change = network_files_need_update(backend);

    let actions = build_mutation_actions(backend, udev_needs_update, network_files_change);
    if actions.is_empty() {
        return Ok(());
    }

    let mutations = crate::confirmation::PhaseMutations {
        phase_name: "System Configuration".to_string(),
        actions,
    };

    match crate::confirmation::confirm_phase_mutations(&mutations, config) {
        crate::confirmation::ConfirmationResult::Confirmed => {}
        crate::confirmation::ConfirmationResult::Skipped => return Ok(()),
        crate::confirmation::ConfirmationResult::Cancelled => {
            anyhow::bail!("Setup cancelled by user");
        }
    }

    system::check_plugdev_with_warning()?;

    if !config.dry_run {
        ensure_sudo()?;
    }

    apply_network_config(
        backend,
        backup_dir,
        config,
        udev_needs_update,
        network_files_change,
    )
}

fn network_files_need_update(backend: NetworkBackend) -> bool {
    match backend {
        NetworkBackend::SystemdNetworkd => {
            file_needs_update(NETWORK_CONFIG_PATH, NETWORK_CONFIG_CONTENT)
                || file_needs_update(NETWORKMANAGER_CONFIG_PATH, NETWORKMANAGER_CONFIG_CONTENT)
        }
        NetworkBackend::NetworkManager => {
            file_needs_update(NM_CONNECTION_PATH, NM_CONNECTION_CONTENT)
        }
    }
}

fn build_mutation_actions(
    backend: NetworkBackend,
    udev_needs_update: bool,
    network_files_change: bool,
) -> Vec<crate::confirmation::MutationAction> {
    let mut actions = Vec::new();

    if udev_needs_update {
        actions.push(crate::confirmation::MutationAction {
            description: format!("Write udev rule to {UDEV_RULE_PATH}"),
            detailed_info: Some("Configures USB device naming for russignol interface".to_string()),
        });
    }

    match backend {
        NetworkBackend::SystemdNetworkd => {
            if file_needs_update(NETWORK_CONFIG_PATH, NETWORK_CONFIG_CONTENT) {
                actions.push(crate::confirmation::MutationAction {
                    description: format!("Write network config to {NETWORK_CONFIG_PATH}"),
                    detailed_info: Some("Sets up systemd-networkd for 169.254.1.2/30".to_string()),
                });
            }
            if file_needs_update(NETWORKMANAGER_CONFIG_PATH, NETWORKMANAGER_CONFIG_CONTENT) {
                actions.push(crate::confirmation::MutationAction {
                    description: format!(
                        "Write NetworkManager config to {NETWORKMANAGER_CONFIG_PATH}"
                    ),
                    detailed_info: Some(
                        "Prevents NetworkManager from managing russignol interface".to_string(),
                    ),
                });
            }
            if network_files_change {
                actions.push(crate::confirmation::MutationAction {
                    description: "Reload systemd-networkd service".to_string(),
                    detailed_info: Some("Applies network configuration changes".to_string()),
                });
                actions.push(crate::confirmation::MutationAction {
                    description: "Reload NetworkManager service (if running)".to_string(),
                    detailed_info: Some(
                        "Ensures NetworkManager recognizes unmanaged interface".to_string(),
                    ),
                });
            }
        }
        NetworkBackend::NetworkManager => {
            if file_needs_update(NM_CONNECTION_PATH, NM_CONNECTION_CONTENT) {
                actions.push(crate::confirmation::MutationAction {
                    description: format!("Write NetworkManager connection to {NM_CONNECTION_PATH}"),
                    detailed_info: Some(
                        "Creates NM connection profile for 169.254.1.2/30".to_string(),
                    ),
                });
            }
            if network_files_change {
                actions.push(crate::confirmation::MutationAction {
                    description: "Activate NetworkManager connection".to_string(),
                    detailed_info: Some(
                        "Runs nmcli connection reload and activates russignol profile".to_string(),
                    ),
                });
            }
        }
    }

    actions
}

fn apply_network_config(
    backend: NetworkBackend,
    backup_dir: &Path,
    config: &crate::confirmation::ConfirmationConfig,
    udev_needs_update: bool,
    network_files_change: bool,
) -> Result<()> {
    match backend {
        NetworkBackend::SystemdNetworkd => {
            // Install NM unmanaged config before udev rule so NetworkManager won't
            // interfere when the udev trigger fires or the device reconnects
            if file_needs_update(NETWORKMANAGER_CONFIG_PATH, NETWORKMANAGER_CONFIG_CONTENT) {
                install_nm_unmanaged_config(backup_dir, config)?;
            }

            if udev_needs_update {
                manage_udev_rule(backup_dir, config.dry_run, config.verbose)?;
            }

            if network_files_change {
                manage_network_config_networkd(backup_dir, config)?;
            }
        }
        NetworkBackend::NetworkManager => {
            if udev_needs_update {
                manage_udev_rule(backup_dir, config.dry_run, config.verbose)?;
            }

            if network_files_change {
                manage_network_config_nm(backup_dir, config)?;
            }
        }
    }

    Ok(())
}

// check_plugdev_membership moved to system::check_plugdev_with_warning()

fn manage_udev_rule(backup_dir: &Path, dry_run: bool, verbose: bool) -> Result<()> {
    let rule_path = Path::new(UDEV_RULE_PATH);

    // Backup existing rule if it exists
    if rule_path.exists() {
        backup::backup_file_if_exists(rule_path, backup_dir, "20-russignol.rules", verbose)?;
    }

    if dry_run {
        return Ok(());
    }

    run_step(
        "Installing udev rule",
        &format!("sudo cp <rule> {UDEV_RULE_PATH}"),
        || {
            let temp_file = create_temp_file()?;
            std::fs::write(&temp_file, UDEV_RULE_CONTENT)
                .context("Failed to write temporary udev rule file")?;
            sudo_command_success_quiet("mv", &[&temp_file, UDEV_RULE_PATH])?;
            sudo_command_success_quiet("chmod", &["644", UDEV_RULE_PATH])?;
            Ok(())
        },
    )?;

    run_step(
        "Reloading udev rules",
        "sudo udevadm control --reload-rules",
        || {
            sudo_command_success_quiet("udevadm", &["control", "--reload-rules"])?;
            sudo_command_success_quiet("udevadm", &["trigger", "--subsystem-match=net"])?;
            Ok(())
        },
    )?;

    run_step(
        "Waiting for network interface",
        "ip link show russignol",
        || {
            for _ in 0..45 {
                if hardware::find_russignol_network_interface() {
                    return Ok(());
                }
                sleep(Duration::from_secs(1));
            }
            anyhow::bail!(
                "russignol network interface not detected after udev configuration. Please check hardware connection and udev rule."
            )
        },
    )
}

// find_russignol_network_interface moved to hardware::find_russignol_network_interface()

/// Install `NetworkManager` unmanaged config early so NM won't interfere with the
/// russignol interface when the udev rule triggers or the device reconnects.
fn install_nm_unmanaged_config(
    backup_dir: &Path,
    config: &crate::confirmation::ConfirmationConfig,
) -> Result<()> {
    if config.dry_run {
        return Ok(());
    }

    let nm_path = Path::new(NETWORKMANAGER_CONFIG_PATH);
    if nm_path.exists() {
        backup::backup_file_if_exists(
            nm_path,
            backup_dir,
            "unmanaged-russignol.conf",
            config.verbose,
        )?;
    }

    run_step(
        "Installing NM unmanaged config",
        &format!("sudo cp <config> {NETWORKMANAGER_CONFIG_PATH}"),
        || {
            let nm_dir = nm_path.parent().unwrap();
            sudo_command_success_quiet("mkdir", &["-p", &nm_dir.to_string_lossy()])?;
            create_network_file(NETWORKMANAGER_CONFIG_PATH, NETWORKMANAGER_CONFIG_CONTENT)?;

            // Reload NM so it picks up the unmanaged config immediately
            if is_service_active("NetworkManager") {
                let _ = sudo_command_quiet("systemctl", &["reload", "NetworkManager"]);
            }
            Ok(())
        },
    )
}

fn manage_network_config_networkd(
    backup_dir: &Path,
    config: &crate::confirmation::ConfirmationConfig,
) -> Result<()> {
    if config.dry_run {
        return Ok(());
    }

    // Backup and create systemd-networkd configuration if needed
    if file_needs_update(NETWORK_CONFIG_PATH, NETWORK_CONFIG_CONTENT) {
        let network_path = Path::new(NETWORK_CONFIG_PATH);
        if network_path.exists() {
            backup::backup_file_if_exists(
                network_path,
                backup_dir,
                "80-russignol.network",
                config.verbose,
            )?;
        }

        run_step(
            "Installing network config",
            &format!("sudo cp <config> {NETWORK_CONFIG_PATH}"),
            || create_network_file(NETWORK_CONFIG_PATH, NETWORK_CONFIG_CONTENT),
        )?;
    }

    // NM config already installed by install_nm_unmanaged_config() before
    // the udev rule — restart remaining networking services
    run_step(
        "Reloading network services",
        "sudo systemctl reload systemd-networkd",
        || {
            let _ = sudo_command_quiet("systemctl", &["reload", "systemd-networkd"]);
            if is_service_active("NetworkManager") {
                let _ = sudo_command_quiet("systemctl", &["reload", "NetworkManager"]);
            }
            Ok(())
        },
    )?;

    validate_network_connectivity()
}

fn manage_network_config_nm(
    backup_dir: &Path,
    config: &crate::confirmation::ConfirmationConfig,
) -> Result<()> {
    if config.dry_run {
        return Ok(());
    }

    // Backup existing connection profile if present
    let nm_conn_path = Path::new(NM_CONNECTION_PATH);
    if nm_conn_path.exists() {
        backup::backup_file_if_exists(
            nm_conn_path,
            backup_dir,
            "russignol.nmconnection",
            config.verbose,
        )?;
    }

    run_step(
        "Installing NM connection",
        &format!("sudo cp <config> {NM_CONNECTION_PATH}"),
        || {
            let nm_conn_dir = nm_conn_path.parent().unwrap();
            sudo_command_success_quiet("mkdir", &["-p", &nm_conn_dir.to_string_lossy()])?;

            let temp_file = create_temp_file()?;
            std::fs::write(&temp_file, NM_CONNECTION_CONTENT)
                .context("Failed to write temporary NM connection file")?;
            sudo_command_success_quiet("mv", &[&temp_file, NM_CONNECTION_PATH])?;
            sudo_command_success_quiet("chown", &["root:root", NM_CONNECTION_PATH])?;
            sudo_command_success_quiet("chmod", &["600", NM_CONNECTION_PATH])?;
            Ok(())
        },
    )?;

    run_step(
        "Activating NM connection",
        "sudo nmcli connection up russignol",
        || {
            sudo_command_success_quiet("nmcli", &["connection", "reload"])?;
            sudo_command_success_quiet("nmcli", &["connection", "up", "russignol"])?;
            Ok(())
        },
    )?;

    validate_network_connectivity()
}

/// Wait for IP assignment, then verify ping and TCP reachability to the signer.
fn validate_network_connectivity() -> Result<()> {
    run_step(
        "Verifying network connectivity",
        "ping -c 3 169.254.1.1",
        || {
            // Wait for IP assignment
            let mut ip_assigned = false;
            for _ in 0..10 {
                if check_ip_assigned()? {
                    ip_assigned = true;
                    break;
                }
                sleep(Duration::from_secs(1));
            }

            if !ip_assigned {
                anyhow::bail!(
                    "Failed to configure network interface. IP 169.254.1.2 not assigned after 10 seconds."
                );
            }

            // Ping test
            let ping_output = run_command("ping", &["-c", "3", "-W", "2", "169.254.1.1"])?;
            if !ping_output.status.success() {
                anyhow::bail!(
                    "Network interface configured but signer at 169.254.1.1 not reachable via ping"
                );
            }

            // TCP connection test to signer service
            let _ = std::net::TcpStream::connect("169.254.1.1:7732");

            Ok(())
        },
    )
}

/// Create a temporary file using mktemp
fn create_temp_file() -> Result<String> {
    let output = run_command("mktemp", &[])?;
    if !output.status.success() {
        anyhow::bail!("mktemp failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn create_network_file(path: &str, content: &str) -> Result<()> {
    let temp_file = create_temp_file()?;
    std::fs::write(&temp_file, content).context("Failed to write temporary network config file")?;

    sudo_command_success_quiet("mv", &[&temp_file, path])?;
    sudo_command_success_quiet("chmod", &["644", path])?;

    Ok(())
}

pub fn check_ip_assigned() -> Result<bool> {
    let output = run_command("ip", &["addr", "show"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    Ok(stdout.contains("169.254.1.2"))
}
