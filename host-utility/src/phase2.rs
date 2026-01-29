use crate::backup;
use crate::constants::{NETWORK_CONFIG_PATH, NETWORKMANAGER_CONFIG_PATH, UDEV_RULE_PATH};
use crate::hardware;
use crate::system;
use crate::utils::{command_exists, run_command, sudo_command, sudo_command_success};
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

// NetworkManager configuration content
const NETWORKMANAGER_CONFIG_CONTENT: &str = r"[keyfile]
unmanaged-devices=interface-name:russignol
";

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
) -> Result<()> {
    // Skip network setup when using a remote signer
    if russignol_config.signer_endpoint.is_some() {
        log::info!(
            "Skipping network setup (using remote signer at {})",
            russignol_config.signer_uri()
        );
        return Ok(());
    }

    // Check which files actually need to be changed
    let udev_needs_update = file_needs_update(UDEV_RULE_PATH, UDEV_RULE_CONTENT);
    let network_needs_update = file_needs_update(NETWORK_CONFIG_PATH, NETWORK_CONFIG_CONTENT);
    let nm_needs_update =
        file_needs_update(NETWORKMANAGER_CONFIG_PATH, NETWORKMANAGER_CONFIG_CONTENT);

    let any_network_files_change = network_needs_update || nm_needs_update;

    // Build mutation list for only files that need to change
    let mut actions = Vec::new();

    if udev_needs_update {
        actions.push(crate::confirmation::MutationAction {
            description: format!("Write udev rule to {UDEV_RULE_PATH}"),
            detailed_info: Some("Configures USB device naming for russignol interface".to_string()),
        });
    }

    if network_needs_update {
        actions.push(crate::confirmation::MutationAction {
            description: format!("Write network config to {NETWORK_CONFIG_PATH}"),
            detailed_info: Some("Sets up systemd-networkd for 169.254.1.2/30".to_string()),
        });
    }

    if nm_needs_update {
        actions.push(crate::confirmation::MutationAction {
            description: format!("Write NetworkManager config to {NETWORKMANAGER_CONFIG_PATH}"),
            detailed_info: Some(
                "Prevents NetworkManager from managing russignol interface".to_string(),
            ),
        });
    }

    if any_network_files_change {
        actions.push(crate::confirmation::MutationAction {
            description: "Restart systemd-networkd service".to_string(),
            detailed_info: Some("Applies network configuration changes".to_string()),
        });
        actions.push(crate::confirmation::MutationAction {
            description: "Restart NetworkManager service (if running)".to_string(),
            detailed_info: Some(
                "Ensures NetworkManager recognizes unmanaged interface".to_string(),
            ),
        });
    }

    // If no changes needed, skip confirmation
    if actions.is_empty() {
        return Ok(());
    }

    let mutations = crate::confirmation::PhaseMutations {
        phase_name: "System Configuration".to_string(),
        actions,
    };

    // Get confirmation
    match crate::confirmation::confirm_phase_mutations(&mutations, config) {
        crate::confirmation::ConfirmationResult::Confirmed => {
            // Continue with phase
        }
        crate::confirmation::ConfirmationResult::Skipped => {
            return Ok(()); // Return success but skip phase
        }
        crate::confirmation::ConfirmationResult::Cancelled => {
            anyhow::bail!("Setup cancelled by user");
        }
    }

    // plugdev Group Membership Check (silent - progress shown in main)
    system::check_plugdev_with_warning()?;

    // Udev Rule Management and Validation (silent - progress shown in main)
    if udev_needs_update {
        manage_udev_rule(backup_dir, config.dry_run, config.verbose)?;
    }

    // Network Configuration and Validation (silent - progress shown in main)
    if any_network_files_change {
        manage_network_config(backup_dir, config, network_needs_update, nm_needs_update)?;
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

    // Write the udev rule
    let temp_file = create_temp_file()?;
    std::fs::write(&temp_file, UDEV_RULE_CONTENT)
        .context("Failed to write temporary udev rule file")?;

    // Move to /etc/udev/rules.d/ with sudo
    sudo_command_success("mv", &[&temp_file, UDEV_RULE_PATH])?;
    sudo_command_success("chmod", &["644", UDEV_RULE_PATH])?;

    // Reload udev rules
    sudo_command_success("udevadm", &["control", "--reload-rules"])?;
    sudo_command_success("udevadm", &["trigger", "--subsystem-match=net"])?;

    // Wait and validate network interface appears (silent - progress shown in main)
    let mut interface_found = false;

    for _ in 0..10 {
        if hardware::find_russignol_network_interface() {
            interface_found = true;
            break;
        }
        sleep(Duration::from_secs(1));
    }

    if !interface_found {
        anyhow::bail!(
            "russignol network interface not detected after udev configuration. Please check hardware connection and udev rule."
        );
    }

    Ok(())
}

// find_russignol_network_interface moved to hardware::find_russignol_network_interface()

fn manage_network_config(
    backup_dir: &Path,
    config: &crate::confirmation::ConfirmationConfig,
    network_needs_update: bool,
    nm_needs_update: bool,
) -> Result<()> {
    if config.dry_run {
        return Ok(());
    }

    // Backup and create systemd-networkd configuration if needed
    if network_needs_update {
        let network_path = Path::new(NETWORK_CONFIG_PATH);
        if network_path.exists() {
            backup::backup_file_if_exists(
                network_path,
                backup_dir,
                "80-russignol.network",
                config.verbose,
            )?;
        }
        create_network_file(NETWORK_CONFIG_PATH, NETWORK_CONFIG_CONTENT)?;
    }

    // Backup and create NetworkManager configuration if needed
    if nm_needs_update {
        let nm_path = Path::new(NETWORKMANAGER_CONFIG_PATH);
        if nm_path.exists() {
            backup::backup_file_if_exists(
                nm_path,
                backup_dir,
                "unmanaged-russignol.conf",
                config.verbose,
            )?;
        }
        let nm_dir = Path::new(NETWORKMANAGER_CONFIG_PATH).parent().unwrap();
        sudo_command_success("mkdir", &["-p", &nm_dir.to_string_lossy()])?;
        create_network_file(NETWORKMANAGER_CONFIG_PATH, NETWORKMANAGER_CONFIG_CONTENT)?;
    }

    // Restart networking services (only if we changed something)
    restart_networking_services();

    // Wait and validate (silent - progress shown in main)
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

    // Ping test to signer (silent - progress shown in main)
    let ping_output = run_command("ping", &["-c", "3", "-W", "2", "169.254.1.1"])?;
    if !ping_output.status.success() {
        anyhow::bail!(
            "Network interface configured but signer at 169.254.1.1 not reachable via ping"
        );
    }

    // TCP connection test to signer service (silent - progress shown in main)
    let _ = std::net::TcpStream::connect("169.254.1.1:7732");

    Ok(())
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

    sudo_command_success("mv", &[&temp_file, path])?;
    sudo_command_success("chmod", &["644", path])?;

    Ok(())
}

fn restart_networking_services() {
    // Try to restart systemd-networkd
    if command_exists("systemctl") {
        let _ = sudo_command("systemctl", &["restart", "systemd-networkd"]);

        // Also try NetworkManager if it's running
        let nm_status = run_command("systemctl", &["is-active", "NetworkManager"]);
        if let Ok(output) = nm_status
            && String::from_utf8_lossy(&output.stdout).trim() == "active"
        {
            let _ = sudo_command("systemctl", &["restart", "NetworkManager"]);
        }
    }
}

pub fn check_ip_assigned() -> Result<bool> {
    let output = run_command("ip", &["addr", "show"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    Ok(stdout.contains("169.254.1.2"))
}
