use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

mod build;
mod changelog;
mod clean;
mod config;
mod image;
mod utils;
mod watermark_test;

use build::build_rpi_signer;
use clean::clean as do_clean;
use image::build_image;
use utils::check_command;

/// Russignol build system - Automated tasks for building, testing, and releasing
#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Russignol build automation", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Target architecture for host utility builds
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Arch {
    /// x86_64-unknown-linux-gnu (AMD64)
    X86_64,
    /// aarch64-unknown-linux-gnu (ARM64)
    Aarch64,
    /// Build for all supported architectures
    All,
}

#[derive(Subcommand)]
enum Commands {
    /// Build `RPi` signer for ARM64
    RpiSigner {
        /// Build in development mode (debug symbols, faster compilation)
        #[arg(long)]
        dev: bool,
    },

    /// Build host utility for all platforms
    HostUtility {
        /// Target architecture: `x86_64`, aarch64, or all
        #[arg(short, long, default_value = "all")]
        arch: Arch,

        /// Build architectures sequentially (default is parallel for multiple targets)
        #[arg(short, long)]
        sequential: bool,

        /// Build in development mode (debug, faster compilation)
        #[arg(long)]
        dev: bool,
    },

    /// Build SD card image via buildroot
    Image {
        /// Use development (non-hardened) configuration
        #[arg(long)]
        dev: bool,

        /// Force clean build (ignore cached state)
        #[arg(long)]
        clean: bool,
    },

    /// Configure buildroot/busybox/kernel
    Config {
        #[command(subcommand)]
        component: ConfigComponent,
    },

    /// Full release: test, build (rpi-signer + host-utility + image), optionally publish to GitHub - always hardened
    Release {
        /// Clean Cargo artifacts before building
        #[arg(long)]
        clean: bool,

        /// Create GitHub release with binaries (requires gh CLI)
        #[arg(long)]
        github: bool,

        /// Publish website to Cloudflare Pages (requires wrangler CLI)
        #[arg(long)]
        website: bool,
    },

    /// Run test suites across workspace
    Test {
        /// Skip proptest fuzzing
        #[arg(long)]
        no_fuzz: bool,
    },

    /// Clean build artifacts
    Clean {
        /// Also clean buildroot output
        #[arg(short, long)]
        buildroot: bool,

        /// Deep clean: remove buildroot downloads and ccache
        #[arg(long)]
        deep: bool,
    },

    /// Validate build environment
    Validate,

    /// Publish website to Cloudflare Pages (requires wrangler CLI)
    Website,

    /// Run watermark protection E2E tests on a physical device
    WatermarkTest {
        /// Device IP address
        #[arg(short, long, default_value = "169.254.1.1")]
        device: String,

        /// Device TCP port
        #[arg(short, long, default_value = "7732")]
        port: u16,

        /// SSH user for device access
        #[arg(short, long, default_value = "russignol")]
        user: String,

        /// Run only tests matching this category (basic, multi, chain, edge)
        #[arg(short, long)]
        category: Option<String>,

        /// Clear watermarks before testing
        #[arg(long)]
        clean: bool,

        /// Restart device service before testing
        #[arg(long)]
        restart: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
enum ConfigComponent {
    /// Configure buildroot
    Buildroot {
        #[command(subcommand)]
        action: BuildrootAction,

        /// Use development (non-hardened) configuration
        #[arg(long)]
        dev: bool,
    },

    /// Configure busybox
    Busybox {
        #[command(subcommand)]
        action: BusyboxAction,

        /// Use development (non-hardened) configuration
        #[arg(long)]
        dev: bool,
    },

    /// Configure Linux kernel
    Kernel {
        #[command(subcommand)]
        action: KernelAction,

        /// Use development (non-hardened) configuration
        #[arg(long)]
        dev: bool,
    },
}

#[derive(Subcommand)]
enum BuildrootAction {
    /// Open ncurses configuration menu
    Nconfig,
    /// Open classic menu configuration
    Menuconfig,
    /// Load defconfig
    Load,
    /// Save current config back to defconfig
    Update,
}

#[derive(Subcommand)]
enum BusyboxAction {
    /// Open busybox configuration menu
    Menuconfig,
    /// Save current config back to external tree
    Update,
}

#[derive(Subcommand)]
enum KernelAction {
    /// Open kernel configuration menu
    Nconfig,
    /// Save current config back to defconfig
    Update,
}

// Build targets for host utility
const HOST_TARGETS: &[&str] = &["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"];

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    let cli = Cli::parse();

    // Ensure we're in the project root
    let project_root = project_root()?;
    env::set_current_dir(&project_root).context("Failed to change to project root directory")?;

    match cli.command {
        Commands::RpiSigner { dev } => build_rpi_signer(dev),
        Commands::HostUtility {
            arch,
            sequential,
            dev,
        } => cmd_host_utility(arch, sequential, dev),
        Commands::Image { dev, clean } => build_image(dev, clean),
        Commands::Config { component } => match component {
            ConfigComponent::Buildroot { action, dev } => match action {
                BuildrootAction::Nconfig => config::config_buildroot_nconfig(dev),
                BuildrootAction::Menuconfig => config::config_buildroot_menuconfig(dev),
                BuildrootAction::Load => config::config_buildroot_load(dev),
                BuildrootAction::Update => config::config_buildroot_update(dev),
            },
            ConfigComponent::Busybox { action, dev } => match action {
                BusyboxAction::Menuconfig => config::config_busybox_menuconfig(dev),
                BusyboxAction::Update => config::config_busybox_update(dev),
            },
            ConfigComponent::Kernel { action, dev } => match action {
                KernelAction::Nconfig => config::config_kernel_nconfig(dev),
                KernelAction::Update => config::config_kernel_update(dev),
            },
        },
        Commands::Release {
            clean,
            github,
            website,
        } => cmd_release(clean, github, website),
        Commands::Test { no_fuzz } => cmd_test(!no_fuzz),
        Commands::Clean { buildroot, deep } => do_clean(buildroot, deep),
        Commands::Validate => cmd_validate(),
        Commands::Website => cmd_website(),
        Commands::WatermarkTest {
            device,
            port,
            user,
            category,
            clean,
            restart,
            verbose,
        } => {
            let config = watermark_test::WatermarkTestConfig {
                device_ip: device,
                device_port: port,
                ssh_user: user,
                category,
                clean,
                restart,
                verbose,
            };
            watermark_test::run_watermark_test(&config)
        }
    }
}

fn cmd_host_utility(arch: Arch, sequential: bool, dev: bool) -> Result<()> {
    let profile = if dev { "debug" } else { "release" };
    let mode_desc = if dev { "DEBUG" } else { "RELEASE" };

    // Resolve architectures to build
    let targets = resolve_targets(arch);

    // Validate targets are installed before starting
    let mut valid_targets = Vec::new();
    for target in &targets {
        if is_target_installed(target)? {
            valid_targets.push(*target);
        } else {
            println!(
                "  {} Target {} not installed. Install with: {}",
                "⚠".yellow(),
                target,
                format!("rustup target add {target}").cyan()
            );
        }
    }

    if valid_targets.is_empty() {
        bail!("No valid targets available. Install required targets with rustup.");
    }

    // Build: parallel by default for multiple targets, sequential if requested
    let use_parallel = !sequential && valid_targets.len() > 1;

    if use_parallel {
        println!(
            "{}",
            format!(
                "Building host utility for {} targets in parallel ({})...",
                valid_targets.len(),
                mode_desc
            )
            .cyan()
        );
        build_parallel(&valid_targets, dev)?;
    } else {
        println!(
            "{}",
            format!(
                "Building host utility for {} target(s) ({})...",
                valid_targets.len(),
                mode_desc
            )
            .cyan()
        );
        build_sequential(&valid_targets, dev)?;
    }

    println!(
        "{}",
        format!("✓ Host utility builds complete ({profile})").green()
    );
    Ok(())
}

fn resolve_targets(arch: Arch) -> Vec<&'static str> {
    match arch {
        Arch::All => HOST_TARGETS.to_vec(),
        Arch::X86_64 => vec!["x86_64-unknown-linux-gnu"],
        Arch::Aarch64 => vec!["aarch64-unknown-linux-gnu"],
    }
}

fn build_sequential(targets: &[&str], dev: bool) -> Result<()> {
    for target in targets {
        println!("  Building for {}...", target.yellow());
        build_for_target(target, dev)?;
    }
    Ok(())
}

fn build_for_target(target: &str, dev: bool) -> Result<()> {
    let mut args = vec!["build", "--package", "russignol-setup", "--target", target];
    if !dev {
        args.push("--release");
    }
    run_cargo(&args, &format!("Build failed for {target}"))
}

fn build_parallel(targets: &[&str], dev: bool) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let had_error = AtomicBool::new(false);
    let profile = if dev { "debug" } else { "release" };

    // Use separate target directories per-arch to avoid Cargo lock contention
    std::thread::scope(|s| {
        let handles: Vec<_> = targets
            .iter()
            .map(|target| {
                let had_error = &had_error;
                // Each target gets its own build directory
                let target_dir = format!("target-{}", target.split('-').next().unwrap_or(target));
                s.spawn(move || {
                    println!("  {} Building for {}...", "→".cyan(), target);
                    if let Err(e) = build_for_target_with_dir(target, dev, &target_dir) {
                        eprintln!("  {} {} failed: {}", "✗".red(), target, e);
                        had_error.store(true, Ordering::SeqCst);
                    } else {
                        println!("  {} {}", "✓".green(), target);
                    }
                })
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }
    });

    if had_error.load(Ordering::SeqCst) {
        bail!("One or more parallel builds failed");
    }

    // Copy binaries from parallel target dirs to standard locations
    for target in targets {
        let arch = target.split('-').next().unwrap_or(target);
        let src = format!("target-{arch}/{target}/{profile}/russignol");
        let dst_dir = format!("target/{target}/{profile}");
        let dst = format!("{dst_dir}/russignol");

        std::fs::create_dir_all(&dst_dir).with_context(|| format!("Failed to create {dst_dir}"))?;
        std::fs::copy(&src, &dst).with_context(|| format!("Failed to copy {src} to {dst}"))?;
    }

    Ok(())
}

fn build_for_target_with_dir(target: &str, dev: bool, target_dir: &str) -> Result<()> {
    let mut args = vec![
        "build",
        "--package",
        "russignol-setup",
        "--target",
        target,
        "--target-dir",
        target_dir,
    ];
    if !dev {
        args.push("--release");
    }

    // Disable cargo's progress bar to avoid interleaved output in parallel builds
    let status = Command::new("cargo")
        .args(&args)
        .env("CARGO_TERM_PROGRESS_WHEN", "never")
        .status()
        .with_context(|| format!("Failed to execute: cargo {}", args.join(" ")))?;

    if !status.success() {
        bail!("Build failed for {target}");
    }
    Ok(())
}

/// Compute SHA256 hash of a file
fn compute_sha256(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut file =
        File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    std::io::copy(&mut file, &mut hasher)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Move release assets to target/ with canonical names and generate checksums
fn copy_release_assets() -> Result<Vec<String>> {
    let mut assets: Vec<String> = Vec::new();

    // Move host utility binaries
    for target in HOST_TARGETS {
        let binary = format!("target/{target}/release/russignol");
        if Path::new(&binary).exists() {
            let output_name = match *target {
                "x86_64-unknown-linux-gnu" => "russignol-amd64",
                "aarch64-unknown-linux-gnu" => "russignol-aarch64",
                _ => continue,
            };
            let release_path = format!("target/{output_name}");
            std::fs::rename(&binary, &release_path)
                .with_context(|| format!("Failed to move binary for {target}"))?;
            assets.push(release_path);
            println!("    {} {}", "✓".green(), output_name);
        } else {
            println!(
                "    {} Skipping {} (binary not found)",
                "⚠".yellow(),
                target
            );
        }
    }

    // Move SD card image
    let image_path = Path::new("buildroot/output/images/sdcard.img.xz");
    if image_path.exists() {
        let release_image = "target/russignol-pi-zero.img.xz";
        std::fs::rename(image_path, release_image).context("Failed to move SD card image")?;
        assets.push(release_image.to_string());
        println!("    {} russignol-pi-zero.img.xz", "✓".green());
    } else {
        println!(
            "    {} Skipping SD card image (not found at {})",
            "⚠".yellow(),
            image_path.display()
        );
    }

    // Generate checksums.txt for all assets
    if !assets.is_empty() {
        println!("  Computing checksums...");
        let checksums_path = "target/checksums.txt";
        let file = File::create(checksums_path).context("Failed to create checksums.txt")?;
        let mut writer = BufWriter::new(file);

        for asset_path in &assets {
            let path = Path::new(asset_path);
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .context("Invalid asset filename")?;
            let hash = compute_sha256(path)?;
            // sha256sum format: two spaces between hash and filename
            writeln!(writer, "{hash}  {filename}").context("Failed to write checksum")?;
        }

        writer.flush().context("Failed to flush checksums.txt")?;
        assets.push(checksums_path.to_string());
        println!("    {} checksums.txt", "✓".green());
    }

    Ok(assets)
}

fn cmd_website() -> Result<()> {
    check_command("wrangler", "Install with: bun add -g wrangler")?;
    cmd_website_publish()
}

fn cmd_website_publish() -> Result<()> {
    println!(
        "{}",
        "Publishing website to Cloudflare Pages...".cyan().bold()
    );

    run_cmd(
        "wrangler",
        &["pages", "deploy", "website", "--project-name=russignol"],
        "Failed to publish website to Cloudflare Pages",
    )?;

    println!(
        "\n{}",
        "✓ Website published to Cloudflare Pages!".green().bold()
    );
    println!("  View at: https://russignol.com");

    Ok(())
}

fn cmd_github_release() -> Result<()> {
    let version = get_cargo_version()?;

    println!(
        "{}",
        format!("Creating GitHub release v{version}...")
            .cyan()
            .bold()
    );

    check_command("gh", "Install with: https://cli.github.com/")?;

    // Collect existing release assets
    let mut assets: Vec<String> = Vec::new();
    for name in [
        "russignol-amd64",
        "russignol-aarch64",
        "russignol-pi-zero.img.xz",
        "checksums.txt",
    ] {
        let path = format!("target/{name}");
        if Path::new(&path).exists() {
            assets.push(path);
        }
    }

    if assets.is_empty() {
        bail!("No release assets found. Build first with: cargo xtask release");
    }

    // Generate changelog from conventional commits
    println!("  Generating changelog...");
    let changelog_path = changelog::create_changelog_file(&version)?;

    // Create GitHub release with assets
    println!("  Creating release on GitHub...");
    let tag = format!("v{version}");
    let title = format!("Russignol v{version}");

    let mut args = vec![
        "release",
        "create",
        &tag,
        "--title",
        &title,
        "--notes-file",
        &changelog_path,
    ];

    for asset in &assets {
        args.push(asset);
    }

    run_cmd("gh", &args, "Failed to create GitHub release")?;

    println!(
        "\n{}",
        format!("✓ GitHub release v{version} created!")
            .green()
            .bold()
    );
    println!("  View at: https://github.com/RichAyotte/russignol/releases/tag/{tag}");

    Ok(())
}

fn cmd_release(clean: bool, github: bool, website: bool) -> Result<()> {
    let version = get_cargo_version()?;

    println!(
        "{}",
        format!("Building full release {version} (HARDENED)...")
            .cyan()
            .bold()
    );

    // Validate wrangler early if --website is used
    if website {
        check_command("wrangler", "Install with: bun add -g wrangler")?;
    }

    let mut step = 1;

    // 1. Clean (optional) - includes buildroot output
    if clean {
        println!("\n{}", format!("Step {step}: Clean").cyan().bold());
        do_clean(true, false)?;
        step += 1;
    }

    // 2. Test (includes proptest fuzzing)
    println!("\n{}", format!("Step {step}: Test").cyan().bold());
    cmd_test(true)?;
    step += 1;

    // 3. Build RPi signer (hardened)
    println!(
        "\n{}",
        format!("Step {step}: Build RPi Signer").cyan().bold()
    );
    build_rpi_signer(false)?;
    step += 1;

    // 4. Build host utility (all targets, sequential, release)
    println!(
        "\n{}",
        format!("Step {step}: Build Host Utility").cyan().bold()
    );
    cmd_host_utility(Arch::All, false, false)?;
    step += 1;

    // 5. Build image (hardened)
    println!(
        "\n{}",
        format!("Step {step}: Build SD Card Image").cyan().bold()
    );
    build_image(false, false)?;
    step += 1;

    // 6. Move release assets to target/
    println!(
        "\n{}",
        format!("Step {step}: Move Release Assets").cyan().bold()
    );
    copy_release_assets()?;

    // 7. Create GitHub release (optional)
    if github {
        step += 1;
        println!(
            "\n{}",
            format!("Step {step}: Create GitHub Release").cyan().bold()
        );
        cmd_github_release()?;
    }

    // 8. Publish website (optional)
    if website {
        step += 1;
        println!(
            "\n{}",
            format!("Step {step}: Publish Website").cyan().bold()
        );
        cmd_website_publish()?;
    }

    println!(
        "\n{} {}",
        "✓ Release".green().bold(),
        format!("{version} complete!").green().bold()
    );
    println!("  - Binaries: target/russignol-amd64, target/russignol-aarch64");
    println!("  - SD image: target/russignol-pi-zero.img.xz");
    if github {
        println!("  - GitHub: https://github.com/RichAyotte/russignol/releases");
    }
    if website {
        println!("  - Website: https://russignol.com");
    }

    Ok(())
}

fn cmd_test(fuzz: bool) -> Result<()> {
    println!("{}", "Running tests...".cyan());
    run_cargo(&["test", "--workspace"], "Tests failed")?;
    println!("{}", "✓ All tests passed".green());

    // Run proptest fuzzing if requested
    if fuzz {
        println!("\n{}", "Running proptest fuzzing...".cyan());
        run_cargo(
            &[
                "test",
                "--package",
                "russignol-signer-lib",
                "--test",
                "proptest_protocol",
            ],
            "Proptest fuzzing failed",
        )?;
        println!("{}", "✓ Proptest fuzzing complete".green());
    }

    Ok(())
}

fn cmd_validate() -> Result<()> {
    println!("{}", "Validating build environment...".cyan().bold());

    // Check Rust toolchain
    println!("  Checking Rust toolchain...");
    check_command("cargo", "Install Rust from https://rustup.rs")?;
    check_command("rustup", "Install Rust from https://rustup.rs")?;

    // Check required targets
    println!("  Checking Rust targets...");
    let all_targets = &["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"];
    for target in all_targets {
        if is_target_installed(target)? {
            println!("    {} {}", "✓".green(), target);
        } else {
            println!(
                "    {} {} - install with: {}",
                "✗".red(),
                target,
                format!("rustup target add {target}").cyan()
            );
        }
    }

    // Check cross-compiler
    println!("  Checking cross-compiler...");
    match check_command("aarch64-linux-gnu-gcc", "") {
        Ok(()) => println!("    {} aarch64-linux-gnu-gcc", "✓".green()),
        Err(_) => println!(
            "    {} aarch64-linux-gnu-gcc - install with: {}",
            "✗".red(),
            "sudo apt install gcc-aarch64-linux-gnu".cyan()
        ),
    }

    // Check buildroot
    println!("  Checking buildroot...");
    if Path::new("buildroot").exists() {
        println!("    {} buildroot directory found", "✓".green());
    } else {
        println!(
            "    {} buildroot not found - clone with: {}",
            "✗".red(),
            "git clone https://gitlab.com/buildroot.org/buildroot.git".cyan()
        );
    }

    println!("\n{}", "Environment validation complete".green().bold());
    Ok(())
}

// Utility functions

fn project_root() -> Result<PathBuf> {
    let dir = env::current_dir().context("Failed to get current directory")?;
    let mut path = dir.as_path();

    // Look for Cargo.toml with [workspace]
    loop {
        let cargo_toml = path.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = std::fs::read_to_string(&cargo_toml)?;
            if content.contains("[workspace]") {
                return Ok(path.to_path_buf());
            }
        }

        path = path
            .parent()
            .context("Reached filesystem root without finding project")?;
    }
}

fn run_cargo(args: &[&str], error_msg: &str) -> Result<()> {
    run_cmd("cargo", args, error_msg)
}

fn run_cmd(cmd: &str, args: &[&str], error_msg: &str) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("Failed to execute: {} {}", cmd, args.join(" ")))?;

    if !status.success() {
        bail!("{error_msg}");
    }

    Ok(())
}

fn is_target_installed(target: &str) -> Result<bool> {
    let output = Command::new("rustup")
        .args(["target", "list"])
        .stdout(Stdio::piped())
        .output()
        .context("Failed to run rustup")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .any(|line| line.contains(target) && line.contains("installed")))
}

fn get_cargo_version() -> Result<String> {
    let cargo_toml_path = Path::new("host-utility/Cargo.toml");
    let cargo_toml_content = std::fs::read_to_string(cargo_toml_path)
        .context("Failed to read host-utility/Cargo.toml")?;

    // Parse version from Cargo.toml
    for line in cargo_toml_content.lines() {
        if line.trim().starts_with("version")
            && let Some(version) = line.split('=').nth(1)
        {
            let version = version.trim().trim_matches('"').to_string();
            return Ok(version);
        }
    }

    bail!("Could not find version in host-utility/Cargo.toml")
}
