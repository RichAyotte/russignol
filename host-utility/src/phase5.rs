use crate::blockchain;
use crate::config::RussignolConfig;
use crate::constants::{
    COMPANION_KEY_ALIAS, CONSENSUS_KEY_ALIAS, NETWORK_CONFIG, NETWORK_MASK, ORANGE, SIGNER_IP,
};
use colored::Colorize;
use std::path::Path;

pub fn run(
    backup_dir: &Path,
    baker_key: &str,
    dry_run: bool,
    _verbose: bool,
    config: &RussignolConfig,
) {
    print_backup_and_network_status(backup_dir);

    if !dry_run {
        print_key_activation_status(baker_key, config);
        print_baking_rights(baker_key, config);
    }

    print_next_steps(config);
}

fn print_backup_and_network_status(backup_dir: &Path) {
    println!(
        "{} Files have been backed up in {}",
        "✓".green(),
        backup_dir.display()
    );
    println!("{} Network interfaces:", "✓".green());
    println!("  • Host {NETWORK_CONFIG}");
    println!("  • Signer {SIGNER_IP}{NETWORK_MASK}");
}

fn print_key_activation_status(baker_key: &str, config: &RussignolConfig) {
    match blockchain::query_key_activation_status(baker_key, config) {
        Ok(status) => {
            if status.consensus_pending {
                println!(
                    "{} Consensus key activating in cycle {} ({})",
                    "✓".green(),
                    status.consensus_cycle.unwrap(),
                    status.consensus_time_estimate.unwrap()
                );
            } else {
                println!("{} Consensus and companion keys are active", "✓".green());
            }

            if status.companion_pending && !status.consensus_pending {
                println!(
                    "{} Companion key activating in cycle {} ({})",
                    "✓".green(),
                    status.companion_cycle.unwrap(),
                    status.companion_time_estimate.unwrap()
                );
            }
        }
        Err(e) => {
            log::debug!("Failed to query key activation status: {e}");
            println!(
                "{} Could not query key status (RPC unavailable)",
                "⚠".yellow()
            );
        }
    }
}

fn print_baking_rights(baker_key: &str, config: &RussignolConfig) {
    let (baking_result, attesting_result) = std::thread::scope(|s| {
        let config_ref = config;

        let baking_handle =
            s.spawn(move || blockchain::query_next_baking_rights(baker_key, config_ref));
        let attesting_handle =
            s.spawn(move || blockchain::query_next_attesting_rights(baker_key, config_ref));

        (
            baking_handle.join().unwrap(),
            attesting_handle.join().unwrap(),
        )
    });

    match baking_result {
        Ok(Some((level, estimated_time))) => {
            println!(
                "{} Next block to bake: level {} ({})",
                "✓".green(),
                level,
                estimated_time
            );
        }
        Ok(None) => {
            println!(
                "{} No upcoming baking rights found in next 5 cycles",
                "✓".green()
            );
        }
        Err(e) => {
            log::debug!("Failed to query baking rights: {e}");
            println!(
                "{} Could not query baking rights (RPC unavailable)",
                "⚠".yellow()
            );
        }
    }

    match attesting_result {
        Ok(Some((level, estimated_time))) => {
            println!(
                "{} Next attestation: level {} ({})",
                "✓".green(),
                level,
                estimated_time
            );
        }
        Ok(None) => {
            println!(
                "{} No upcoming attesting rights found in next 5 cycles",
                "✓".green()
            );
        }
        Err(e) => {
            log::debug!("Failed to query attesting rights: {e}");
            println!(
                "{} Could not query attesting rights (RPC unavailable)",
                "⚠".yellow()
            );
        }
    }
}

fn print_next_steps(config: &RussignolConfig) {
    let node_dir = config
        .octez_node_dir
        .as_ref()
        .map_or_else(|| "~/.tezos-node".to_string(), |p| p.display().to_string());

    let dal_endpoint = config
        .dal_node_endpoint
        .as_deref()
        .unwrap_or("http://127.0.0.1:10732");

    println!();
    println!("{}", "Next, start your baker:".bold());
    println!("  octez-baker --endpoint {} \\", config.rpc_endpoint);
    println!("    run with local node {node_dir} \\");
    println!("    {CONSENSUS_KEY_ALIAS} {COMPANION_KEY_ALIAS} \\");
    println!("    --dal-node {dal_endpoint} \\");
    println!("    --liquidity-baking-toggle-vote <on|off|pass>");
    println!();
    println!(
        "Run {} to see the latest status",
        "russignol status".truecolor(ORANGE.0, ORANGE.1, ORANGE.2)
    );
}
