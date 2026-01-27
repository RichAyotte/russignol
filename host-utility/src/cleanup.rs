use crate::config::RussignolConfig;
use crate::constants::{COMPANION_KEY_ALIAS, CONSENSUS_KEY_ALIAS};
use crate::utils::{
    command_exists, info, print_title_bar, run_command, run_octez_client_command, success,
    sudo_command, warning,
};
use anyhow::Result;
use colored::Colorize;
use std::io::Write;

const UDEV_RULE_PATH: &str = "/etc/udev/rules.d/20-russignol.rules";
const NETWORK_CONFIG_PATH: &str = "/etc/systemd/network/80-russignol.network";
const NETWORKMANAGER_CONFIG_PATH: &str = "/etc/NetworkManager/conf.d/unmanaged-russignol.conf";

pub fn run_cleanup(dry_run: bool, config: &RussignolConfig) -> Result<()> {
    print_title_bar("🧹 Russignol Cleanup");
    println!();

    if !dry_run {
        // Prompt for confirmation
        print!(
            "{}",
            "Are you sure you want to remove all russignol configuration? (yes/no): ".yellow()
        );
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() != "yes" {
            println!("Cleanup cancelled.");
            return Ok(());
        }
        println!();
    }

    // Remove system files
    info("Removing system configuration files...");
    remove_system_files(dry_run);

    // Reload udev and restart networking
    if !dry_run {
        info("Reloading udev rules...");
        let _ = sudo_command("udevadm", &["control", "--reload-rules"]);
        let _ = sudo_command("udevadm", &["trigger"]);

        info("Restarting networking services...");
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

    // Optionally remove keys
    println!();
    remove_keys(dry_run, config)?;

    // Verify removal
    if !dry_run {
        info("Verifying removal...");
        verify_cleanup(config);
    }

    println!();
    success("Cleanup complete. All russignol system configuration has been removed.");
    println!();

    Ok(())
}

fn remove_system_files(dry_run: bool) {
    let files = vec![
        UDEV_RULE_PATH,
        NETWORK_CONFIG_PATH,
        NETWORKMANAGER_CONFIG_PATH,
    ];

    for file in files {
        let path = std::path::Path::new(file);
        if path.exists() {
            if dry_run {
                info(&format!("Would remove {file}"));
            } else {
                match sudo_command("rm", &["-f", file]) {
                    Ok(output) if output.status.success() => {
                        success(&format!("Removed {file}"));
                    }
                    Ok(output) => {
                        warning(&format!(
                            "Failed to remove {}: {}",
                            file,
                            String::from_utf8_lossy(&output.stderr)
                        ));
                    }
                    Err(e) => {
                        warning(&format!("Failed to remove {file}: {e}"));
                    }
                }
            }
        } else {
            log::debug!("File {file} does not exist, skipping");
        }
    }
}

fn remove_keys(dry_run: bool, config: &RussignolConfig) -> Result<()> {
    if dry_run {
        info("Would prompt to remove imported keys");
        return Ok(());
    }

    print!(
        "{}",
        format!(
            "Do you want to remove the imported keys ({CONSENSUS_KEY_ALIAS} and {COMPANION_KEY_ALIAS})? (yes/no): "
        )
        .yellow()
    );
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() != "yes" {
        info("Keeping imported keys");
        return Ok(());
    }

    println!();
    info(&format!(
        "Removing imported keys from {}...",
        config.octez_client_dir.display()
    ));

    // Remove consensus key
    let output = run_octez_client_command(
        &["forget", "address", CONSENSUS_KEY_ALIAS, "--force"],
        config,
    );

    match output {
        Ok(output) if output.status.success() => {
            success(&format!("Removed {CONSENSUS_KEY_ALIAS} key"));
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("no public key hash alias named") {
                warning(&format!("Failed to remove {CONSENSUS_KEY_ALIAS}: {stderr}"));
            }
        }
        Err(e) => {
            warning(&format!("Failed to remove {CONSENSUS_KEY_ALIAS}: {e}"));
        }
    }

    // Remove companion key
    let output = run_octez_client_command(
        &["forget", "address", COMPANION_KEY_ALIAS, "--force"],
        config,
    );

    match output {
        Ok(output) if output.status.success() => {
            success(&format!("Removed {COMPANION_KEY_ALIAS} key"));
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("no public key hash alias named") {
                warning(&format!("Failed to remove {COMPANION_KEY_ALIAS}: {stderr}"));
            }
        }
        Err(e) => {
            warning(&format!("Failed to remove {COMPANION_KEY_ALIAS}: {e}"));
        }
    }

    Ok(())
}

fn verify_cleanup(config: &RussignolConfig) {
    let mut all_removed = true;

    // Check system files
    for file in &[
        UDEV_RULE_PATH,
        NETWORK_CONFIG_PATH,
        NETWORKMANAGER_CONFIG_PATH,
    ] {
        if std::path::Path::new(file).exists() {
            warning(&format!("File still exists: {file}"));
            all_removed = false;
        }
    }

    // Check if keys are still listed
    if let Ok(output) = run_octez_client_command(&["list", "known", "addresses"], config) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains(CONSENSUS_KEY_ALIAS) {
            warning(&format!("{CONSENSUS_KEY_ALIAS} key still exists"));
            all_removed = false;
        }
        if stdout.contains(COMPANION_KEY_ALIAS) {
            warning(&format!("{COMPANION_KEY_ALIAS} key still exists"));
            all_removed = false;
        }
    }

    if all_removed {
        success("All system configuration successfully removed");
    }
}
