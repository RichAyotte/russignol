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

/// Component to release in monorepo-style releases
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ReleaseComponent {
    /// `RPi` signer application (rpi-signer/Cargo.toml)
    Signer,
    /// Host utility application (host-utility/Cargo.toml)
    HostUtility,
    /// Signer library (libs/signer/Cargo.toml)
    SignerLib,
    /// UI library (libs/ui/Cargo.toml)
    Ui,
    /// Crypto library (libs/crypto/Cargo.toml)
    Crypto,
    /// EPD display library (libs/epd-2in13-v4/Cargo.toml)
    EpdDisplay,
    /// Full release - all components (current behavior)
    All,
}

/// Options for the release command
#[allow(clippy::struct_excessive_bools)]
struct ReleaseOptions {
    component: ReleaseComponent,
    no_bump: bool,
    clean: bool,
    github: bool,
    website: bool,
}

impl ReleaseComponent {
    /// Get the Cargo.toml path for this component
    fn cargo_toml_path(self) -> &'static str {
        match self {
            Self::Signer | Self::All => "rpi-signer/Cargo.toml",
            Self::HostUtility => "host-utility/Cargo.toml",
            Self::SignerLib => "libs/signer/Cargo.toml",
            Self::Ui => "libs/ui/Cargo.toml",
            Self::Crypto => "libs/crypto/Cargo.toml",
            Self::EpdDisplay => "libs/epd-2in13-v4/Cargo.toml",
        }
    }

    /// Get the tag prefix for this component
    fn tag_prefix(self) -> &'static str {
        match self {
            Self::Signer => "signer",
            Self::HostUtility => "host-utility",
            Self::SignerLib => "signer-lib",
            Self::Ui => "ui",
            Self::Crypto => "crypto",
            Self::EpdDisplay => "epd-display",
            Self::All => "", // No prefix for full releases (uses "v{version}")
        }
    }

    /// Get the display name for this component
    fn display_name(self) -> &'static str {
        match self {
            Self::Signer => "Signer",
            Self::HostUtility => "Host Utility",
            Self::SignerLib => "Signer Library",
            Self::Ui => "UI Library",
            Self::Crypto => "Crypto Library",
            Self::EpdDisplay => "EPD Display Library",
            Self::All => "Full Release",
        }
    }

    /// Get the commit scope used for filtering changelog
    fn commit_scope(self) -> Option<&'static str> {
        match self {
            Self::Signer => Some("signer"),
            Self::HostUtility => Some("host-utility"),
            Self::SignerLib => Some("signer-lib"),
            Self::Ui => Some("ui"),
            Self::Crypto => Some("crypto"),
            Self::EpdDisplay => Some("epd-display"),
            Self::All => None, // Include all commits for full release
        }
    }
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
        /// Component to release (default: all for full release)
        #[arg(short, long, default_value = "all")]
        component: ReleaseComponent,

        /// Skip auto-bump of version (by default, version is bumped based on conventional commits)
        #[arg(long)]
        no_bump: bool,

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

    /// Publish to GitHub and/or Cloudflare Pages without rebuilding
    Publish {
        /// Component to publish (default: all for full release)
        #[arg(short, long, default_value = "all")]
        component: ReleaseComponent,

        /// Publish to GitHub releases (requires gh CLI)
        #[arg(long)]
        github: bool,

        /// Publish website to Cloudflare Pages (requires wrangler CLI)
        #[arg(long)]
        website: bool,
    },

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
            component,
            no_bump,
            clean,
            github,
            website,
        } => cmd_release(&ReleaseOptions {
            component,
            no_bump,
            clean,
            github,
            website,
        }),
        Commands::Test { no_fuzz } => cmd_test(!no_fuzz),
        Commands::Clean { buildroot, deep } => do_clean(buildroot, deep),
        Commands::Validate => cmd_validate(),
        Commands::Publish {
            component,
            github,
            website,
        } => cmd_publish(component, github, website),
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

fn cmd_publish(component: ReleaseComponent, github: bool, website: bool) -> Result<()> {
    if !github && !website {
        bail!("Specify --github and/or --website to publish");
    }

    if github {
        cmd_github_release(component)?;
    }

    if website {
        if component == ReleaseComponent::All {
            cmd_website_publish()?;
        } else {
            println!(
                "  {} --website is only supported for full releases, ignoring",
                "⚠".yellow()
            );
        }
    }

    Ok(())
}

fn cmd_website_publish() -> Result<()> {
    check_command("wrangler", "Install with: bun add -g wrangler")?;
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

fn cmd_github_release(component: ReleaseComponent) -> Result<()> {
    let version = get_component_version(component)?;

    let (tag, title) = if component == ReleaseComponent::All {
        (format!("v{version}"), format!("Russignol v{version}"))
    } else {
        let prefix = component.tag_prefix();
        (
            format!("{prefix}-v{version}"),
            format!("Russignol {} v{version}", component.display_name()),
        )
    };

    println!(
        "{}",
        format!("Creating GitHub release {tag}...").cyan().bold()
    );

    check_command("gh", "Install with: https://cli.github.com/")?;

    // Collect release assets based on component
    let assets = collect_release_assets(component);

    // Libraries don't have binary assets - that's fine
    let has_assets = !assets.is_empty();

    // Generate changelog from conventional commits
    println!("  Generating changelog...");
    let changelog_path = if component == ReleaseComponent::All {
        changelog::create_changelog_file(&version)?
    } else {
        let prefix = component.tag_prefix();
        let scope = component.commit_scope();
        changelog::create_changelog_file_for_component(&version, Some(prefix), scope)?
    };

    // Create GitHub release with assets
    println!("  Creating release on GitHub...");

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
        format!("✓ GitHub release {tag} created!").green().bold()
    );
    println!("  View at: https://github.com/RichAyotte/russignol/releases/tag/{tag}");

    if !has_assets {
        println!("  {}", "(No binary assets for this component)".yellow());
    }

    Ok(())
}

/// Collect release assets based on the component being released
fn collect_release_assets(component: ReleaseComponent) -> Vec<String> {
    let asset_names: &[&str] = match component {
        ReleaseComponent::All => &[
            "russignol-amd64",
            "russignol-aarch64",
            "russignol-pi-zero.img.xz",
            "checksums.txt",
        ],
        ReleaseComponent::Signer => &["russignol-pi-zero.img.xz", "checksums.txt"],
        ReleaseComponent::HostUtility => &["russignol-amd64", "russignol-aarch64", "checksums.txt"],
        // Libraries don't have binary assets
        ReleaseComponent::SignerLib
        | ReleaseComponent::Ui
        | ReleaseComponent::Crypto
        | ReleaseComponent::EpdDisplay => &[],
    };

    asset_names
        .iter()
        .map(|name| format!("target/{name}"))
        .filter(|path| Path::new(path).exists())
        .collect()
}

fn cmd_release(opts: &ReleaseOptions) -> Result<()> {
    let ReleaseOptions {
        component,
        no_bump,
        clean,
        github,
        website,
    } = *opts;

    let mut step = 1;

    // 1. Version bump (default) - must happen first before we read version
    let version = if no_bump {
        get_component_version(component)?
    } else {
        println!("\n{}", format!("Step {step}: Bump Version").cyan().bold());
        let new_version = bump_component_version(component)?;
        step += 1;
        new_version
    };

    let release_desc = if component == ReleaseComponent::All {
        format!("full release {version} (HARDENED)")
    } else {
        format!("{} release {version}", component.display_name())
    };

    println!("{}", format!("Building {release_desc}...").cyan().bold());

    // Website publishing only makes sense for full releases
    if website && component != ReleaseComponent::All {
        println!(
            "  {} --website is only supported for full releases, ignoring",
            "⚠".yellow()
        );
    }

    // Validate wrangler early if --website is used for full release
    if website && component == ReleaseComponent::All {
        check_command("wrangler", "Install with: bun add -g wrangler")?;
    }

    // 2. Clean (optional) - includes buildroot output for full/signer releases
    if clean {
        println!("\n{}", format!("Step {step}: Clean").cyan().bold());
        let clean_buildroot = matches!(component, ReleaseComponent::All | ReleaseComponent::Signer);
        do_clean(clean_buildroot, false)?;
        step += 1;
    }

    // 3. Test - always run tests
    println!("\n{}", format!("Step {step}: Test").cyan().bold());
    cmd_test(true)?;
    step += 1;

    // 4. Component-specific build steps
    step = build_component_artifacts(component, step)?;

    // Create GitHub release (optional)
    if github {
        println!(
            "\n{}",
            format!("Step {step}: Create GitHub Release").cyan().bold()
        );
        cmd_github_release(component)?;
        step += 1;
    }

    // Publish website (optional, only for full releases)
    if website && component == ReleaseComponent::All {
        println!(
            "\n{}",
            format!("Step {step}: Publish Website").cyan().bold()
        );
        cmd_website_publish()?;
    }

    // Print completion summary
    print_release_summary(component, &version, github, website);

    Ok(())
}

/// Bump the version for a component based on conventional commits
fn bump_component_version(component: ReleaseComponent) -> Result<String> {
    let prefix = if component == ReleaseComponent::All {
        None
    } else {
        Some(component.tag_prefix())
    };
    let scope = component.commit_scope();

    // Determine bump type from commits
    let bump_type = changelog::get_bump_type_for_component(prefix, scope)?;
    println!("  Detected {bump_type} bump from commits");

    // Get current version and calculate new version
    let current_version = get_component_version(component)?;
    let new_version = changelog::bump_version(&current_version, bump_type)?;
    println!("  {} → {}", current_version, new_version.green());

    // Update Cargo.toml(s)
    if component == ReleaseComponent::All {
        // Full release: update both signer and host-utility versions
        update_cargo_version("rpi-signer/Cargo.toml", &new_version)?;
        update_cargo_version("host-utility/Cargo.toml", &new_version)?;
    } else {
        let cargo_toml_path = component.cargo_toml_path();
        update_cargo_version(cargo_toml_path, &new_version)?;
    }

    // Commit the change
    commit_version_bump(component, &new_version)?;

    Ok(new_version)
}

/// Update the version in a Cargo.toml file
fn update_cargo_version(cargo_toml_path: &str, new_version: &str) -> Result<()> {
    let content = std::fs::read_to_string(cargo_toml_path)
        .with_context(|| format!("Failed to read {cargo_toml_path}"))?;

    // Find and replace the version line in the [package] section
    let mut in_package = false;
    let mut updated = false;
    let new_content: String = content
        .lines()
        .map(|line| {
            if line.trim() == "[package]" {
                in_package = true;
                return line.to_string();
            }
            if line.trim().starts_with('[') && line.trim() != "[package]" {
                in_package = false;
            }
            if in_package && line.trim().starts_with("version") && !updated {
                updated = true;
                return format!("version = \"{new_version}\"");
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Preserve trailing newline if original had one
    let new_content = if content.ends_with('\n') {
        format!("{new_content}\n")
    } else {
        new_content
    };

    std::fs::write(cargo_toml_path, new_content)
        .with_context(|| format!("Failed to write {cargo_toml_path}"))?;

    println!("  Updated {}", cargo_toml_path.cyan());

    Ok(())
}

/// Commit the version bump with a conventional commit message
fn commit_version_bump(component: ReleaseComponent, version: &str) -> Result<()> {
    // Update Cargo.lock to reflect the version changes
    let status = Command::new("cargo")
        .args(["update", "--workspace"])
        .status()
        .context("Failed to run cargo update")?;
    if !status.success() {
        bail!("Failed to update Cargo.lock");
    }

    // Stage the Cargo.toml file(s) and Cargo.lock
    if component == ReleaseComponent::All {
        // Full release: stage both signer and host-utility
        for path in [
            "rpi-signer/Cargo.toml",
            "host-utility/Cargo.toml",
            "Cargo.lock",
        ] {
            let status = Command::new("git")
                .args(["add", path])
                .status()
                .context("Failed to run git add")?;
            if !status.success() {
                bail!("Failed to stage {path}");
            }
        }
    } else {
        let cargo_toml_path = component.cargo_toml_path();
        for path in [cargo_toml_path, "Cargo.lock"] {
            let status = Command::new("git")
                .args(["add", path])
                .status()
                .context("Failed to run git add")?;
            if !status.success() {
                bail!("Failed to stage {path}");
            }
        }
    }

    // Create commit message
    let (scope, tag) = if component == ReleaseComponent::All {
        ("release".to_string(), format!("v{version}"))
    } else {
        let prefix = component.tag_prefix();
        (prefix.to_string(), format!("{prefix}-v{version}"))
    };

    let commit_msg = format!("chore({scope}): release {tag}");

    // Commit
    let status = Command::new("git")
        .args(["commit", "-m", &commit_msg])
        .status()
        .context("Failed to run git commit")?;

    if !status.success() {
        bail!("Failed to commit version bump");
    }

    println!("  Committed: {}", commit_msg.cyan());

    // Create local git tag to prevent duplicate releases
    let status = Command::new("git")
        .args(["tag", &tag])
        .status()
        .context("Failed to run git tag")?;

    if !status.success() {
        bail!("Failed to create tag {tag}");
    }

    println!("  Tagged: {}", tag.cyan());

    Ok(())
}

/// Build artifacts for a specific component, returning the next step number
fn build_component_artifacts(component: ReleaseComponent, mut step: usize) -> Result<usize> {
    match component {
        ReleaseComponent::All => {
            println!(
                "\n{}",
                format!("Step {step}: Build RPi Signer").cyan().bold()
            );
            build_rpi_signer(false)?;
            step += 1;

            println!(
                "\n{}",
                format!("Step {step}: Build Host Utility").cyan().bold()
            );
            cmd_host_utility(Arch::All, false, false)?;
            step += 1;

            println!(
                "\n{}",
                format!("Step {step}: Build SD Card Image").cyan().bold()
            );
            build_image(false, false)?;
            step += 1;

            println!(
                "\n{}",
                format!("Step {step}: Move Release Assets").cyan().bold()
            );
            copy_release_assets()?;
            step += 1;
        }
        ReleaseComponent::Signer => {
            println!(
                "\n{}",
                format!("Step {step}: Build RPi Signer").cyan().bold()
            );
            build_rpi_signer(false)?;
            step += 1;

            println!(
                "\n{}",
                format!("Step {step}: Build SD Card Image").cyan().bold()
            );
            build_image(false, false)?;
            step += 1;

            println!(
                "\n{}",
                format!("Step {step}: Move Release Assets").cyan().bold()
            );
            copy_signer_release_assets()?;
            step += 1;
        }
        ReleaseComponent::HostUtility => {
            println!(
                "\n{}",
                format!("Step {step}: Build Host Utility").cyan().bold()
            );
            cmd_host_utility(Arch::All, false, false)?;
            step += 1;

            println!(
                "\n{}",
                format!("Step {step}: Move Release Assets").cyan().bold()
            );
            copy_host_utility_release_assets()?;
            step += 1;
        }
        ReleaseComponent::SignerLib
        | ReleaseComponent::Ui
        | ReleaseComponent::Crypto
        | ReleaseComponent::EpdDisplay => {
            println!(
                "  {}",
                "Library release - no binary artifacts to build".cyan()
            );
        }
    }
    Ok(step)
}

/// Copy only signer-related release assets
fn copy_signer_release_assets() -> Result<Vec<String>> {
    let mut assets: Vec<String> = Vec::new();

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

    // Generate checksums
    if !assets.is_empty() {
        generate_checksums(&assets)?;
        assets.push("target/checksums.txt".to_string());
    }

    Ok(assets)
}

/// Copy only host-utility release assets
fn copy_host_utility_release_assets() -> Result<Vec<String>> {
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

    // Generate checksums
    if !assets.is_empty() {
        generate_checksums(&assets)?;
        assets.push("target/checksums.txt".to_string());
    }

    Ok(assets)
}

/// Generate checksums.txt for the given assets
fn generate_checksums(assets: &[String]) -> Result<()> {
    println!("  Computing checksums...");
    let checksums_path = "target/checksums.txt";
    let file = File::create(checksums_path).context("Failed to create checksums.txt")?;
    let mut writer = BufWriter::new(file);

    for asset_path in assets {
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
    println!("    {} checksums.txt", "✓".green());

    Ok(())
}

/// Print release completion summary
fn print_release_summary(component: ReleaseComponent, version: &str, github: bool, website: bool) {
    println!(
        "\n{} {}",
        "✓ Release".green().bold(),
        format!("{version} complete!").green().bold()
    );

    match component {
        ReleaseComponent::All => {
            println!("  - Binaries: target/russignol-amd64, target/russignol-aarch64");
            println!("  - SD image: target/russignol-pi-zero.img.xz");
        }
        ReleaseComponent::Signer => {
            println!("  - SD image: target/russignol-pi-zero.img.xz");
        }
        ReleaseComponent::HostUtility => {
            println!("  - Binaries: target/russignol-amd64, target/russignol-aarch64");
        }
        ReleaseComponent::SignerLib
        | ReleaseComponent::Ui
        | ReleaseComponent::Crypto
        | ReleaseComponent::EpdDisplay => {
            println!("  - Library release (tag only, no binary artifacts)");
        }
    }

    if github {
        let tag = if component == ReleaseComponent::All {
            format!("v{version}")
        } else {
            format!("{}-v{version}", component.tag_prefix())
        };
        println!("  - GitHub: https://github.com/RichAyotte/russignol/releases/tag/{tag}");
    }

    if website && component == ReleaseComponent::All {
        println!("  - Website: https://russignol.com");
    }
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

/// Get the version for a specific component from its Cargo.toml
fn get_component_version(component: ReleaseComponent) -> Result<String> {
    let cargo_toml_path = Path::new(component.cargo_toml_path());
    let cargo_toml_content = std::fs::read_to_string(cargo_toml_path)
        .with_context(|| format!("Failed to read {}", component.cargo_toml_path()))?;

    // Parse version from Cargo.toml
    for line in cargo_toml_content.lines() {
        if line.trim().starts_with("version")
            && let Some(version) = line.split('=').nth(1)
        {
            let version = version.trim().trim_matches('"').to_string();
            return Ok(version);
        }
    }

    bail!("Could not find version in {}", component.cargo_toml_path())
}
