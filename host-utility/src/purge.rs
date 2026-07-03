use crate::config::RussignolConfig;
use crate::constants::{
    COMPANION_KEY_ALIAS, CONSENSUS_KEY_ALIAS, NETWORK_CONFIG_PATH, NETWORKMANAGER_CONFIG_PATH,
    NM_CONNECTION_PATH, UDEV_RULE_PATH,
};
use crate::progress::create_spinner;
use crate::utils::{
    ensure_sudo, info, is_service_active, run_command, run_octez_client_command, success, warning,
};
use anyhow::Result;
use std::io::Write;

const ALL_CONFIG_FILES: &[&str] = &[
    UDEV_RULE_PATH,
    NETWORK_CONFIG_PATH,
    NETWORKMANAGER_CONFIG_PATH,
    NM_CONNECTION_PATH,
];

/// Run the purge. Returns `Ok(true)` only when the system is (or was already)
/// fully clean; `Ok(false)` when key state could not be determined, a removal
/// failed, or material survived — the caller maps that to a non-zero exit.
pub fn run_purge(dry_run: bool, config: &RussignolConfig) -> Result<bool> {
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

    // A failed key listing must not read as "no keys": we cannot claim a clean
    // purge if we could not even determine whether key material is present.
    let (known, key_state_known) =
        match run_octez_client_command(&["list", "known", "addresses"], config) {
            Ok(output) if output.status.success() => {
                (String::from_utf8_lossy(&output.stdout).to_string(), true)
            }
            Ok(output) => {
                warning(&format!(
                    "Could not list known keys: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
                (String::new(), false)
            }
            Err(e) => {
                warning(&format!("Could not list known keys: {e:#}"));
                (String::new(), false)
            }
        };
    let keys_to_remove = present_aliases(&known, &[CONSENSUS_KEY_ALIAS, COMPANION_KEY_ALIAS]);

    let has_config = !files_to_remove.is_empty();
    let has_keys = !keys_to_remove.is_empty();

    if !has_config && !has_keys {
        if !key_state_known {
            warning("Could not determine key state; system may not be clean.");
            return Ok(false);
        }
        info("No russignol configuration found. System is clean.");
        return Ok(true);
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
        return Ok(true);
    }

    let mut config_failures = 0usize;
    if has_config {
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
            return Ok(true);
        }
        ensure_sudo()?;
        println!();
        let tasks: Vec<SpinnerTask<'_>> = displays.iter().map(|d| sudo_task(d)).collect();
        config_failures = run_with_spinner(tasks, "System configuration removed.");
    }

    let mut key_failures = 0usize;
    if has_keys {
        if has_config {
            println!();
        }
        key_failures = remove_keys(&keys_to_remove, config)?;
    }

    // Verify removal
    println!();
    let survivors = verify_purge(config);

    Ok(purge_is_clean(
        key_state_known,
        config_failures,
        key_failures,
        survivors,
    ))
}

/// Which of `candidates` appear in `octez-client list known addresses` output.
fn present_aliases<'a>(known: &str, candidates: &[&'a str]) -> Vec<&'a str> {
    candidates
        .iter()
        .copied()
        .filter(|a| known.contains(a))
        .collect()
}

/// A purge is clean only when key state was determinable, nothing failed to
/// remove, and the post-removal verification found no survivors.
fn purge_is_clean(
    key_state_known: bool,
    config_failures: usize,
    key_failures: usize,
    survivors: usize,
) -> bool {
    key_state_known && config_failures == 0 && key_failures == 0 && survivors == 0
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

/// Run each task, warning on any failure. Returns the number of failed tasks
/// so the caller can reflect it in the overall outcome; the success banner is
/// printed only when every task actually succeeded.
fn run_with_spinner(tasks: Vec<SpinnerTask<'_>>, success_msg: &str) -> usize {
    let spinner = create_spinner("");
    let mut failures = 0usize;

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
                if ignored {
                    continue;
                }
                failures += 1;
                let detail = if trimmed.is_empty() {
                    format!("exited with {}", output.status)
                } else {
                    trimmed.to_string()
                };
                spinner.suspend(|| {
                    warning(&format!("{}: {detail}", task.display));
                });
            }
            Err(e) => {
                failures += 1;
                spinner.suspend(|| {
                    warning(&format!("{}: {e}", task.display));
                });
            }
        }
    }

    spinner.finish_and_clear();
    if failures == 0 {
        success(success_msg);
    } else {
        warning(&format!("{success_msg} — {failures} step(s) failed"));
    }
    failures
}

fn remove_keys(aliases: &[&str], config: &RussignolConfig) -> Result<usize> {
    let displays: Vec<String> = aliases
        .iter()
        .map(|a| format!("octez-client forget address {a}"))
        .collect();

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
        return Ok(0);
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
    Ok(run_with_spinner(tasks, "Imported keys removed."))
}

/// Re-check the system after removal. Returns the number of survivors (config
/// files still present, key aliases still known, or a verification that could
/// not run) so the caller never reports a clean purge on unverified state.
fn verify_purge(config: &RussignolConfig) -> usize {
    let mut survivors = 0usize;

    for file in ALL_CONFIG_FILES {
        if std::path::Path::new(file).exists() {
            warning(&format!("File still exists: {file}"));
            survivors += 1;
        }
    }

    match run_octez_client_command(&["list", "known", "addresses"], config) {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for alias in present_aliases(&stdout, &[CONSENSUS_KEY_ALIAS, COMPANION_KEY_ALIAS]) {
                warning(&format!("{alias} key still exists"));
                survivors += 1;
            }
        }
        Ok(output) => {
            warning(&format!(
                "Could not verify key removal: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
            survivors += 1;
        }
        Err(e) => {
            warning(&format!("Could not verify key removal: {e:#}"));
            survivors += 1;
        }
    }

    survivors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn present_aliases_finds_only_listed_ones() {
        let known = "russignol-consensus: tz4abc (tcp sk known)\nother: tz1xyz\n";
        assert_eq!(
            present_aliases(known, &[CONSENSUS_KEY_ALIAS, COMPANION_KEY_ALIAS]),
            vec![CONSENSUS_KEY_ALIAS]
        );
        assert!(present_aliases("", &[CONSENSUS_KEY_ALIAS]).is_empty());
    }

    #[test]
    fn purge_is_clean_only_when_everything_succeeded() {
        assert!(purge_is_clean(true, 0, 0, 0));
        // Key state could not be determined.
        assert!(!purge_is_clean(false, 0, 0, 0));
        // A config removal step failed.
        assert!(!purge_is_clean(true, 1, 0, 0));
        // A key forget failed.
        assert!(!purge_is_clean(true, 0, 1, 0));
        // Material survived (or verification could not run).
        assert!(!purge_is_clean(true, 0, 0, 1));
    }
}
