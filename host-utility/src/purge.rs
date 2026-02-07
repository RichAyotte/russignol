use crate::config::RussignolConfig;
use crate::constants::{
    COMPANION_KEY_ALIAS, CONSENSUS_KEY_ALIAS, NETWORK_CONFIG_PATH, NETWORKMANAGER_CONFIG_PATH,
    NM_CONNECTION_PATH, UDEV_RULE_PATH,
};
use crate::progress::create_spinner;
use crate::utils::{
    info, is_service_active, run_command, run_octez_client_command, success, warning,
};
use anyhow::Result;
use std::io::Write;

const ALL_CONFIG_FILES: &[&str] = &[
    UDEV_RULE_PATH,
    NETWORK_CONFIG_PATH,
    NETWORKMANAGER_CONFIG_PATH,
    NM_CONNECTION_PATH,
];

pub fn run_purge(dry_run: bool, config: &RussignolConfig) -> Result<()> {
    // Determine which actions are needed
    let files_to_remove: Vec<&str> = ALL_CONFIG_FILES
        .iter()
        .copied()
        .filter(|f| std::path::Path::new(f).exists())
        .collect();
    let reload_udev = files_to_remove.contains(&UDEV_RULE_PATH);
    let reload_networkd =
        files_to_remove.contains(&NETWORK_CONFIG_PATH) && is_service_active("systemd-networkd");
    let reload_nm = (files_to_remove.contains(&NETWORKMANAGER_CONFIG_PATH)
        || files_to_remove.contains(&NM_CONNECTION_PATH))
        && is_service_active("NetworkManager");

    let known = run_octez_client_command(&["list", "known", "addresses"], config)
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let keys_to_remove: Vec<&str> = [CONSENSUS_KEY_ALIAS, COMPANION_KEY_ALIAS]
        .into_iter()
        .filter(|a| known.contains(a))
        .collect();

    let has_config = !files_to_remove.is_empty();
    let has_keys = !keys_to_remove.is_empty();

    if !has_config && !has_keys {
        info("No russignol configuration found. System is clean.");
        return Ok(());
    }

    // Build command list for system config removal
    let mut displays: Vec<String> = Vec::new();
    for file in &files_to_remove {
        displays.push(format!("sudo rm -f {file}"));
    }
    if reload_udev {
        displays.push("sudo udevadm control --reload-rules".into());
        displays.push("sudo udevadm trigger".into());
    }
    if reload_networkd {
        displays.push("sudo systemctl reload systemd-networkd".into());
    }
    if reload_nm {
        displays.push("sudo systemctl reload NetworkManager".into());
    }

    if dry_run {
        for cmd in &displays {
            info(&format!("Would run: {cmd}"));
        }
    } else if has_config {
        println!("Remove russignol system configuration:\n");
        for cmd in &displays {
            println!("  {cmd}");
        }

        println!();
        print!("Proceed? (yes/no): ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() != "yes" {
            println!("Purge cancelled.");
            return Ok(());
        }
        println!();
        let tasks: Vec<SpinnerTask<'_>> = displays.iter().map(|d| sudo_task(d)).collect();
        run_with_spinner(tasks, "System configuration removed.");
    }

    if has_keys {
        if has_config {
            println!();
        }
        remove_keys(dry_run, &keys_to_remove, config)?;
    }

    // Verify removal
    if !dry_run {
        println!();
        verify_purge(config);
    }

    Ok(())
}

struct SpinnerTask<'a> {
    display: String,
    run: Box<dyn FnOnce() -> Result<std::process::Output> + 'a>,
    /// Stderr substrings to silently ignore (not real errors)
    ignore_stderr: Vec<&'a str>,
}

fn sudo_task(display: &str) -> SpinnerTask<'static> {
    let parts: Vec<String> = display.split_whitespace().map(String::from).collect();
    SpinnerTask {
        display: display.to_string(),
        run: Box::new(move || {
            let args: Vec<&str> = parts[1..].iter().map(String::as_str).collect();
            run_command(&parts[0], &args)
        }),
        ignore_stderr: Vec::new(),
    }
}

fn run_with_spinner(tasks: Vec<SpinnerTask<'_>>, success_msg: &str) {
    let spinner = create_spinner("");

    for task in tasks {
        spinner.set_message(task.display.clone());

        match (task.run)() {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let trimmed = stderr.trim();
                let ignored = task
                    .ignore_stderr
                    .iter()
                    .any(|pattern| trimmed.contains(pattern));
                if !trimmed.is_empty() && !ignored {
                    spinner.suspend(|| {
                        warning(&format!("{}: {trimmed}", task.display));
                    });
                }
            }
            Err(e) => {
                spinner.suspend(|| {
                    warning(&format!("{}: {e}", task.display));
                });
            }
        }
    }

    spinner.finish_and_clear();
    success(success_msg);
}

fn remove_keys(dry_run: bool, aliases: &[&str], config: &RussignolConfig) -> Result<()> {
    let displays: Vec<String> = aliases
        .iter()
        .map(|a| format!("octez-client forget address {a}"))
        .collect();

    if dry_run {
        for cmd in &displays {
            info(&format!("Would run: {cmd}"));
        }
        return Ok(());
    }

    println!("Remove imported keys from octez-client:\n");
    for cmd in &displays {
        println!("  {cmd}");
    }

    println!();
    print!("Proceed? (yes/no): ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() != "yes" {
        info("Keeping imported keys.");
        return Ok(());
    }
    println!();

    let tasks: Vec<SpinnerTask<'_>> = aliases
        .iter()
        .zip(displays.iter())
        .map(|(alias, display)| SpinnerTask {
            display: display.clone(),
            run: Box::new(|| {
                run_octez_client_command(&["forget", "address", alias, "--force"], config)
            }),
            ignore_stderr: vec!["no public key hash alias named"],
        })
        .collect();
    run_with_spinner(tasks, "Imported keys removed.");

    Ok(())
}

fn verify_purge(config: &RussignolConfig) {
    for file in ALL_CONFIG_FILES {
        if std::path::Path::new(file).exists() {
            warning(&format!("File still exists: {file}"));
        }
    }

    if let Ok(output) = run_octez_client_command(&["list", "known", "addresses"], config) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains(CONSENSUS_KEY_ALIAS) {
            warning(&format!("{CONSENSUS_KEY_ALIAS} key still exists"));
        }
        if stdout.contains(COMPANION_KEY_ALIAS) {
            warning(&format!("{COMPANION_KEY_ALIAS} key still exists"));
        }
    }
}
