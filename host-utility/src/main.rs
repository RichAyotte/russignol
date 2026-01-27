use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use colored::Colorize;

use utils::print_title_bar;

mod backup;
mod blockchain;
mod cleanup;
mod config;
mod confirmation;
mod constants;
mod display;
mod hardware;
mod image;
mod install;
mod keys;
mod phase0;
mod phase1;
mod phase2;
mod phase3;
mod phase4;
mod phase5;
mod progress;
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

        /// Baker key or alias to use (required when using --yes)
        #[arg(long)]
        baker_key: Option<String>,
    },
    /// Display current status without making changes
    Status {
        /// Display detailed diagnostic information
        #[arg(long, short)]
        verbose: bool,
    },
    /// Remove all system configuration
    Cleanup {
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
            })?;
        }
        Some(Commands::Status { verbose }) => {
            handle_status_command(verbose)?;
        }
        Some(Commands::Cleanup { dry_run }) => {
            // Load configuration
            let config = config::RussignolConfig::load()?;
            cleanup::run_cleanup(dry_run, &config)?;
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
            let config = config::RussignolConfig::load()?;
            match command {
                WatermarkCommands::Init { device, yes } => {
                    watermark::cmd_watermark_init(device, yes, &config)?;
                }
            }
        }
        Some(Commands::RotateKeys {
            monitor,
            replace,
            dry_run,
            yes,
            verbose,
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
            handle_rotate_keys_command(&opts, hardware_config, &restart_config)?;
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

fn handle_status_command(verbose: bool) -> Result<()> {
    let log_level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    let config = config::RussignolConfig::load()?;
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
) -> Result<()> {
    let log_level = if opts.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    let config = config::RussignolConfig::load()?;
    rotate_keys::run(opts, hardware_config, restart_config, &config)
}

/// Configuration for the setup command
struct SetupConfig<'a> {
    confirmation: confirmation::ConfirmationConfig,
    skip_hardware_check: bool,
    baker_key: Option<&'a str>,
}

fn run_setup(setup_config: &SetupConfig<'_>) -> Result<()> {
    let SetupConfig {
        confirmation,
        skip_hardware_check,
        baker_key,
    } = setup_config;

    let confirmation_config = initialize_setup_environment(confirmation, *baker_key)?;
    let config = config::RussignolConfig::load()?;
    let backup_dir = backup::create_backup_dir()?;

    run_setup_phases(
        &confirmation_config,
        &config,
        &backup_dir,
        *skip_hardware_check,
        *baker_key,
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
) -> Result<()> {
    const TOTAL_STEPS: usize = 6;

    let dry_run = confirmation_config.dry_run;
    let verbose = confirmation_config.verbose;
    let display = display::SetupDisplay::new(TOTAL_STEPS);

    run_phase_with_error_handler(&display, 1, "Detecting hardware...", || {
        phase0::run(skip_hardware_check, dry_run, verbose)
    })?;

    run_phase_with_error_handler(&display, 2, "Validating system...", || {
        phase1::run(dry_run, verbose, config)
    })?;

    run_phase_with_error_handler(&display, 3, "Configuring system...", || {
        display.suspend_for_prompt(|| phase2::run(backup_dir, confirmation_config, config))
    })?;

    display.update(4, "Configuring keys...");
    let baker_key_result = display
        .suspend_for_prompt(|| phase3::run(backup_dir, confirmation_config, baker_key, config))?;

    run_phase_with_error_handler(&display, 5, "Testing connectivity...", || {
        phase4::run(dry_run, verbose, config)
    })?;

    display.update(6, "Finalizing...");
    std::thread::sleep(std::time::Duration::from_millis(300));
    display.finish();

    println!();
    println!();
    print_title_bar("🔐 Russignol Hardware Signer Setup Complete!");
    phase5::run(backup_dir, &baker_key_result, dry_run, verbose, config);

    Ok(())
}

fn run_phase_with_error_handler<F>(
    display: &display::SetupDisplay,
    step: usize,
    message: &str,
    phase_fn: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    display.update(step, message);
    phase_fn()
}
