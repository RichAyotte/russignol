use crate::config::RussignolConfig;
use crate::constants::{COMPANION_KEY_ALIAS, CONSENSUS_KEY_ALIAS, SIGNER_URI};
use crate::utils::run_octez_client_command;
use anyhow::{Context, Result};

pub fn run(dry_run: bool, _verbose: bool, config: &RussignolConfig) -> Result<()> {
    // Silent - progress shown in main

    if dry_run {
        return Ok(());
    }

    // Verify remote signer is still reachable and keys are available
    let output = run_octez_client_command(&["list", "known", "remote", "keys", SIGNER_URI], config)
        .context("Failed to connect to remote signer")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to list remote keys from signer: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut remote_keys = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("tz4") {
            remote_keys.push(line.to_string());
        }
    }

    if remote_keys.len() < 2 {
        anyhow::bail!(
            "Expected at least 2 remote keys but found {}. Signer may not be properly configured.",
            remote_keys.len()
        );
    }

    // Verify our imported keys match the remote keys
    let list_output = run_octez_client_command(&["list", "known", "addresses"], config)
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .context("Failed to list known addresses")?;

    let has_consensus = list_output.contains(CONSENSUS_KEY_ALIAS)
        && (list_output.contains("tcp sk known") || list_output.contains("tcp:sk known"));
    let has_companion = list_output.contains(COMPANION_KEY_ALIAS)
        && (list_output.contains("tcp sk known") || list_output.contains("tcp:sk known"));

    if !has_consensus || !has_companion {
        anyhow::bail!("Imported key aliases not found in octez-client");
    }

    Ok(())
}
