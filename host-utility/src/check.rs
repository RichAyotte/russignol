//! `russignol check` — diagnose a signer SD card (and repair fixable issues) or
//! the host environment.

use anyhow::Result;
use clap::Subcommand;
use std::path::PathBuf;

use crate::{config, constants, disk, network, status, utils};

/// `check` subcommands
#[derive(Subcommand, Debug)]
pub enum CheckCommands {
    /// Diagnose a signer SD card and repair fixable issues on confirmation
    Disk {
        /// Target device (e.g. /dev/sdc or /dev/mmcblk0); auto-detected if omitted
        #[arg(long, short)]
        device: Option<PathBuf>,

        /// Tezos node RPC endpoint (default: <http://localhost:8732>)
        #[arg(long)]
        endpoint: Option<String>,

        /// Report issues without applying any repair
        #[arg(long)]
        dry_run: bool,

        /// Apply all fixable repairs without prompting
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Check host, node, key, and hardware health (read-only)
    Host {
        /// Display detailed diagnostic information
        #[arg(long, short)]
        verbose: bool,

        /// Tezos node RPC endpoint (default: <http://localhost:8732>)
        #[arg(long)]
        endpoint: Option<String>,

        /// Remote signer endpoint (e.g., <tcp://192.168.1.100:7732>)
        #[arg(long)]
        signer_endpoint: Option<String>,
    },
}

pub fn run_check_command(command: CheckCommands) -> Result<()> {
    match command {
        CheckCommands::Disk {
            device,
            endpoint,
            dry_run,
            yes,
        } => disk::run_disk_check(device, endpoint.as_deref(), dry_run, yes),
        CheckCommands::Host {
            verbose,
            endpoint,
            signer_endpoint,
        } => run_host_check(verbose, endpoint.as_deref(), signer_endpoint.as_deref()),
    }
}

fn run_host_check(
    verbose: bool,
    endpoint: Option<&str>,
    signer_endpoint: Option<&str>,
) -> Result<()> {
    let log_level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    // Read-only and degrades gracefully: an invalid config surfaces as unknown
    // probes and a non-zero exit, which is more useful than refusing to run, so
    // it keeps the lenient loader.
    let mut config = config::RussignolConfig::load()?;
    config.with_overrides(endpoint, signer_endpoint);
    if endpoint.is_none() && !network::resolve_endpoint_interactively(&mut config, false)? {
        utils::warning(network::NON_INTERACTIVE_HINT.trim_start());
    }
    let healthy = status::run_status(verbose, &config);
    if !healthy {
        std::process::exit(constants::EXIT_UNHEALTHY);
    }
    Ok(())
}
