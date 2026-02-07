use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use colored::Colorize;

use utils::print_title_bar;

mod backup;
mod blockchain;
mod config;
mod confirmation;
mod constants;
mod hardware;
mod image;
mod install;
mod keys;
mod phase2;
mod phase3;
mod phase5;
mod progress;
mod purge;
mod rotate_keys;
mod status;
mod system;
mod upgrade;
mod utils;
mod version;
mod watermark;

/// Automated setup and validation utility for the russignol hardware signer host
#[derive(Parser, Debug)]
#[command(name = "russignol")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the full setup and configuration process
    Setup {
        /// Simulate all operations without making any changes
        #[arg(long)]
        dry_run: bool,

        /// Display detailed diagnostic information for each step
        #[arg(long, short)]
        verbose: bool,

        /// Skip hardware detection (useful for testing or pre-configuration scenarios)
        #[arg(long)]
        skip_hardware_check: bool,

        /// Automatically confirm all prompts without asking
        #[arg(long, short = 'y')]
        yes: bool,

        /// Tezos node RPC endpoint (default: <http://localhost:8732>)
        #[arg(long)]
        endpoint: Option<String>,

        /// Remote signer endpoint (e.g., <tcp://192.168.1.100:7732>)
        /// When specified, skips local USB/network configuration
        #[arg(long)]
        signer_endpoint: Option<String>,

        /// Network backend override (auto-detected by default)
        #[arg(long, value_enum)]
        network_backend: Option<phase2::NetworkBackend>,

        /// Baker key or alias to use (required when using --yes)
        #[arg(long)]
        baker_key: Option<String>,
    },
    /// Display current status without making changes
    Status {
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
    /// Remove all system configuration
    Purge {
        /// Simulate all operations without making any changes
        #[arg(long)]
        dry_run: bool,
    },
    /// Install russignol to ~/.local/bin
    Install {
        /// Force overwrite without confirmation
        #[arg(long, short = 'y')]
        yes: bool,

        /// Create backup of existing installation
        #[arg(long)]
        backup: bool,
    },
    /// Upgrade russignol to the latest version
    Upgrade {
        /// Only check for updates without installing
        #[arg(long)]
        check: bool,

        /// Force upgrade without confirmation
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Manage configuration settings
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Generate and install shell completion scripts
    Completions {
        /// Shell to generate completions for
        shell: Shell,

        /// Print to stdout instead of installing
        #[arg(long)]
        print: bool,
    },
    /// Download and flash SD card images
    Image {
        #[command(subcommand)]
        command: image::ImageCommands,
    },
    /// Manage watermark configuration for first boot
    Watermark {
        #[command(subcommand)]
        command: WatermarkCommands,
    },
    /// Rotate to new consensus and companion keys
    RotateKeys {
        /// Monitor pending key activation without importing new keys
        #[arg(long)]
        monitor: bool,

        /// Replace pending keys with new ones (restart rotation from scratch)
        #[arg(long)]
        replace: bool,

        /// Show what would be done without executing
        #[arg(long)]
        dry_run: bool,

        /// Skip confirmation prompts
        #[arg(short, long)]
        yes: bool,

        /// Show detailed output
        #[arg(short, long)]
        verbose: bool,

        /// Tezos node RPC endpoint (default: <http://localhost:8732>)
        #[arg(long)]
        endpoint: Option<String>,

        /// Remote signer endpoint (e.g., <tcp://192.168.1.100:7732>)
        #[arg(long)]
        signer_endpoint: Option<String>,

        /// Hardware setup mode
        #[arg(long, value_enum)]
        config: Option<rotate_keys::HardwareConfig>,

        /// How to restart the baker daemon
        #[arg(long, value_enum)]
        restart_method: Option<rotate_keys::RestartMethod>,

        /// Systemd service name (for --restart-method=systemd)
        #[arg(long, default_value = "octez-baker")]
        baker_service: String,

        /// Command to stop the baker (for --restart-method=script)
        #[arg(long)]
        stop_command: Option<String>,

        /// Command to start the baker (for --restart-method=script)
        #[arg(long)]
        start_command: Option<String>,
    },
}

/// Watermark subcommands
#[derive(Subcommand, Debug)]
pub enum WatermarkCommands {
    /// Initialize watermarks on an SD card (for manually flashed cards)
    Init {
        /// Target device with boot partition (e.g., /dev/sdc)
        #[arg(long, short)]
        device: Option<std::path::PathBuf>,

        /// Tezos node RPC endpoint (default: <http://localhost:8732>)
        #[arg(long)]
        endpoint: Option<String>,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCommands {
    /// Display current configuration
    Show,
    /// Set a configuration value
    Set {
        /// Configuration key (octez-client-dir, octez-node-dir, rpc-endpoint)
        key: String,
        /// Configuration value
        value: String,
    },
    /// Reset configuration and re-detect
    Reset {
        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Show configuration file path
    Path,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            // No subcommand provided, print help
            Cli::command().print_help()?;
            std::process::exit(0);
        }
        Some(Commands::Setup {
            dry_run,
            verbose,
            skip_hardware_check,
            yes,
            endpoint,
            signer_endpoint,
            network_backend,
            baker_key,
        }) => {
            run_setup(&SetupConfig {
                confirmation: confirmation::ConfirmationConfig {
                    auto_confirm: yes,
                    dry_run,
                    verbose,
                },
                skip_hardware_check,
                baker_key: baker_key.as_deref(),
                endpoint: endpoint.as_deref(),
                signer_endpoint: signer_endpoint.as_deref(),
                network_backend,
            })?;
        }
        Some(Commands::Status {
            verbose,
            endpoint,
            signer_endpoint,
        }) => {
            handle_status_command(verbose, endpoint.as_deref(), signer_endpoint.as_deref())?;
        }
        Some(Commands::Purge { dry_run }) => {
            // Load configuration
            let config = config::RussignolConfig::load()?;
            purge::run_purge(dry_run, &config)?;
        }
        Some(Commands::Install { yes, backup }) => {
            install::run_install(yes, backup)?;
        }
        Some(Commands::Upgrade { check, yes }) => {
            upgrade::run_upgrade(check, yes)?;
        }
        Some(Commands::Config { command }) => {
            config::run_config_command(command)?;
        }
        Some(Commands::Completions { shell, print }) => {
            handle_completions_command(shell, print)?;
        }
        Some(Commands::Image { command }) => {
            image::run_image_command(command)?;
        }
        Some(Commands::Watermark { command }) => {
            handle_watermark_command(command)?;
        }
        Some(Commands::RotateKeys {
            monitor,
            replace,
            dry_run,
            yes,
            verbose,
            endpoint,
            signer_endpoint,
            config: hardware_config,
            restart_method,
            baker_service,
            stop_command,
            start_command,
        }) => {
            let opts = rotate_keys::RotateKeysOptions {
                monitor_only: monitor,
                replace,
                dry_run,
                auto_confirm: yes,
                verbose,
            };
            let restart_config = rotate_keys::RestartConfig {
                method: restart_method,
                service: baker_service,
                stop_command,
                start_command,
            };
            handle_rotate_keys_command(
                &opts,
                hardware_config,
                &restart_config,
                endpoint.as_deref(),
                signer_endpoint.as_deref(),
            )?;
        }
    }

    Ok(())
}

fn install_completions(shell: Shell) -> Result<()> {
    use std::io::Write;

    // Determine the installation directory based on shell type
    let (completions_dir, filename) = match shell {
        Shell::Bash => {
            let data_dir = dirs::data_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine XDG_DATA_HOME"))?;
            (data_dir.join("bash-completion/completions"), "russignol")
        }
        Shell::Zsh => {
            let data_dir = dirs::data_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine XDG_DATA_HOME"))?;
            (data_dir.join("zsh/completions"), "_russignol")
        }
        Shell::Fish => {
            let config_dir = dirs::config_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine XDG_CONFIG_HOME"))?;
            (config_dir.join("fish/completions"), "russignol.fish")
        }
        _ => {
            anyhow::bail!(
                "Auto-install not supported for {shell:?}. Use --print to output to stdout."
            );
        }
    };

    // Create directory if it doesn't exist
    std::fs::create_dir_all(&completions_dir)?;

    // Generate completions to a buffer
    let mut buf = Vec::new();
    clap_complete::generate(shell, &mut Cli::command(), "russignol", &mut buf);

    // Write to file
    let file_path = completions_dir.join(filename);
    let mut file = std::fs::File::create(&file_path)?;
    file.write_all(&buf)?;

    println!(
        "{} Installed {} completions to {}",
        "✓".green(),
        format!("{shell:?}").to_lowercase(),
        file_path.display()
    );
    println!(
        "  {} Restart your shell or run: source {}",
        "→".cyan(),
        file_path.display()
    );

    Ok(())
}

fn handle_watermark_command(command: WatermarkCommands) -> Result<()> {
    let mut config = config::RussignolConfig::load()?;
    match command {
        WatermarkCommands::Init {
            device,
            endpoint,
            yes,
        } => {
            config.with_overrides(endpoint.as_deref(), None);
            watermark::cmd_watermark_init(device, yes, &config)?;
        }
    }
    Ok(())
}

fn handle_status_command(
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

    let mut config = config::RussignolConfig::load()?;
    config.with_overrides(endpoint, signer_endpoint);
    status::run_status(verbose, &config);
    Ok(())
}

fn handle_completions_command(shell: Shell, print: bool) -> Result<()> {
    if print {
        clap_complete::generate(
            shell,
            &mut Cli::command(),
            "russignol",
            &mut std::io::stdout(),
        );
    } else {
        install_completions(shell)?;
    }
    Ok(())
}

fn handle_rotate_keys_command(
    opts: &rotate_keys::RotateKeysOptions,
    hardware_config: Option<rotate_keys::HardwareConfig>,
    restart_config: &rotate_keys::RestartConfig,
    endpoint: Option<&str>,
    signer_endpoint: Option<&str>,
) -> Result<()> {
    let log_level = if opts.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    let mut config = config::RussignolConfig::load()?;
    config.with_overrides(endpoint, signer_endpoint);
    rotate_keys::run(opts, hardware_config, restart_config, &config)
}

/// Configuration for the setup command
struct SetupConfig<'a> {
    confirmation: confirmation::ConfirmationConfig,
    skip_hardware_check: bool,
    baker_key: Option<&'a str>,
    endpoint: Option<&'a str>,
    signer_endpoint: Option<&'a str>,
    network_backend: Option<phase2::NetworkBackend>,
}

fn run_setup(setup_config: &SetupConfig<'_>) -> Result<()> {
    let SetupConfig {
        confirmation,
        skip_hardware_check,
        baker_key,
        endpoint,
        signer_endpoint,
        network_backend,
    } = setup_config;

    let confirmation_config = initialize_setup_environment(confirmation, *baker_key)?;
    let mut config = config::RussignolConfig::load()?;
    config.with_overrides(*endpoint, *signer_endpoint);
    let backup_dir = backup::create_backup_dir()?;

    run_setup_phases(
        &confirmation_config,
        &config,
        &backup_dir,
        *skip_hardware_check,
        *baker_key,
        *network_backend,
    )
}

fn initialize_setup_environment(
    confirmation: &confirmation::ConfirmationConfig,
    baker_key: Option<&str>,
) -> Result<confirmation::ConfirmationConfig> {
    let log_level = if confirmation.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Off
    };
    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    println!();

    if confirmation.dry_run {
        println!(
            "{}",
            "Running in DRY-RUN mode - no changes will be made"
                .yellow()
                .bold()
        );
        println!();
    }

    if confirmation.auto_confirm {
        println!(
            "{}",
            "Auto-confirm mode enabled (--yes) - all prompts will be automatically accepted"
                .yellow()
                .bold()
        );
        println!();
    }

    if confirmation.dry_run && confirmation.auto_confirm {
        utils::info("Both --dry-run and --yes specified. Running in dry-run mode.");
        println!();
    }

    if confirmation.auto_confirm && !confirmation.dry_run && baker_key.is_none() {
        anyhow::bail!(
            "When using --yes, you must provide --baker-key with a baker address or alias"
        );
    }

    confirmation::validate_environment(confirmation)?;

    Ok(confirmation.clone())
}

fn run_setup_phases(
    confirmation_config: &confirmation::ConfirmationConfig,
    config: &config::RussignolConfig,
    backup_dir: &std::path::Path,
    skip_hardware_check: bool,
    baker_key: Option<&str>,
    network_backend: Option<phase2::NetworkBackend>,
) -> Result<()> {
    let dry_run = confirmation_config.dry_run;
    let verbose = confirmation_config.verbose;

    // Phase 0: Hardware detection (inlined)
    if !skip_hardware_check {
        progress::run_step_detail("Detecting hardware", "lsusb", || {
            hardware::detect_hardware_device()?;
            let serial = hardware::get_usb_serial_number()
                .ok()
                .flatten()
                .unwrap_or_default();
            let detail = if serial.is_empty() {
                "Russignol device found".to_string()
            } else {
                format!("Russignol device found (serial: {serial})")
            };
            Ok(((), detail))
        })?;

        if let Ok(Some(power_info)) = hardware::get_usb_power_info()
            && let Some(warning_msg) = hardware::check_power_warning(&power_info)
        {
            println!();
            utils::warning(&warning_msg);
            println!();
        }
    }

    // Phase 1: System validation (inlined)
    progress::run_step(
        "Checking dependencies",
        "which octez-client octez-node ...",
        system::verify_dependencies,
    )?;

    progress::run_step_detail(
        "Checking octez-node",
        &format!(
            "octez-client rpc get /version --endpoint {}",
            config.rpc_endpoint
        ),
        || {
            system::verify_octez_node(config)?;
            let detail = utils::rpc_get_json("/version", config)
                .ok()
                .and_then(|v| {
                    let product = v.get("version")?.get("product")?.as_str()?;
                    Some(product.to_string())
                })
                .unwrap_or_default();
            Ok(((), detail))
        },
    )?;

    progress::run_step(
        "Checking client directory",
        &config.octez_client_dir.display().to_string(),
        || system::verify_octez_client_directory(config),
    )?;

    // Phase 2: Network configuration
    phase2::run(backup_dir, confirmation_config, config, network_backend)?;

    // Phase 3: Key configuration
    let baker_key_result = phase3::run(backup_dir, confirmation_config, baker_key, config)?;

    // Phase 4: Final verification (inlined)
    if !dry_run {
        let signer_uri = config.signer_uri();
        progress::run_step_detail(
            "Verifying signer keys",
            &format!("octez-client list known remote keys {signer_uri}"),
            || {
                let remote_keys = keys::discover_remote_keys(config)
                    .context("Failed to connect to remote signer")?;

                if remote_keys.len() < 2 {
                    anyhow::bail!(
                        "Expected at least 2 remote keys but found {}. Signer may not be properly configured.",
                        remote_keys.len()
                    );
                }
                let detail = format!("{} keys available", remote_keys.len());
                Ok(((), detail))
            },
        )?;

        progress::run_step(
            "Verifying key aliases",
            "octez-client list known addresses",
            || {
                let list_output =
                    utils::run_octez_client_command(&["list", "known", "addresses"], config)
                        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                        .context("Failed to list known addresses")?;

                let has_consensus = list_output.contains(constants::CONSENSUS_KEY_ALIAS)
                    && (list_output.contains("tcp sk known")
                        || list_output.contains("tcp:sk known"));
                let has_companion = list_output.contains(constants::COMPANION_KEY_ALIAS)
                    && (list_output.contains("tcp sk known")
                        || list_output.contains("tcp:sk known"));

                if !has_consensus || !has_companion {
                    anyhow::bail!("Imported key aliases not found in octez-client");
                }
                Ok(())
            },
        )?;
    }

    // Phase 5: Summary
    println!();
    println!();
    print_title_bar("🔐 Russignol Hardware Signer Setup Complete!");
    phase5::run(backup_dir, &baker_key_result, dry_run, verbose, config);

    Ok(())
}
