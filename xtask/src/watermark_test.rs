//! Watermark E2E Testing Command
//!
//! Orchestrates watermark protection testing on a physical Russignol device.

use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::io::Write;
use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::deploy::{DEVICE_PASS, RESTART_SIGNER_CMD};

/// Default device address (link-local USB network)
const DEFAULT_DEVICE_IP: &str = "169.254.1.1";
const DEFAULT_DEVICE_PORT: u16 = 7732;

/// On-device watermark storage, the `SignerConfig::watermark_dir` default in
/// `rpi-signer/src/signer_server.rs`. Clearing it drops every key to
/// uninitialized so the next unlock reloads a clean slate.
const WATERMARK_DIR: &str = "/data/watermarks";

/// Watermark test configuration
pub struct WatermarkTestConfig {
    /// Device IP address
    pub device_ip: String,
    /// Device TCP port
    pub device_port: u16,
    /// SSH user for device access
    pub ssh_user: String,
    /// Test category filter (None = all)
    pub category: Option<String>,
    /// Clear watermarks before testing
    pub clean: bool,
    /// Restart device before testing
    pub restart: bool,
    /// Verbose output
    pub verbose: bool,
}

impl Default for WatermarkTestConfig {
    fn default() -> Self {
        Self {
            device_ip: DEFAULT_DEVICE_IP.to_string(),
            device_port: DEFAULT_DEVICE_PORT,
            ssh_user: "russignol".to_string(),
            category: None,
            clean: false,
            restart: false,
            verbose: false,
        }
    }
}

/// Run watermark E2E tests
pub fn run_watermark_test(config: &WatermarkTestConfig) -> Result<()> {
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "           RUSSIGNOL WATERMARK TEST ORCHESTRATOR"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!();

    let device_addr = format!("{}:{}", config.device_ip, config.device_port);
    println!("  Device:     {}", device_addr.yellow());
    println!("  SSH User:   {}", config.ssh_user.yellow());
    println!(
        "  Category:   {}",
        config.category.as_deref().unwrap_or("all").yellow()
    );
    println!();

    // Step 1: Check device connectivity
    println!("{}", "Step 1: Checking device connectivity...".cyan());
    check_device_connectivity(&config.device_ip, config.device_port)?;
    println!("  {} Device is reachable", "✓".green());

    // Step 2: Optionally clear watermarks
    if config.clean {
        println!("\n{}", "Step 2: Clearing existing watermarks...".cyan());
        clear_watermarks(&config.device_ip, &config.ssh_user)?;
        println!("  {} Watermarks cleared", "✓".green());
    } else {
        println!(
            "\n{}",
            "Step 2: Skipping watermark clear (use --clean to reset)".dimmed()
        );
    }

    // Step 3: Optionally restart device
    if config.restart {
        println!("\n{}", "Step 3: Restarting Russignol service...".cyan());
        restart_device(&config.device_ip, &config.ssh_user)?;
        println!(
            "  {} Service restarted; the device is back at PIN entry",
            "✓".green()
        );

        // The signer only binds its port after unlock, so the operator must
        // re-enter the PIN before the harness can reconnect.
        check_device_connectivity(&config.device_ip, config.device_port)?;
        println!("  {} Device responding after restart", "✓".green());
    } else {
        println!(
            "\n{}",
            "Step 3: Skipping restart (use --restart to restart device)".dimmed()
        );
    }

    // Step 4: Run the test harness
    println!("\n{}", "Step 4: Running watermark E2E tests...".cyan());
    println!();

    run_test_harness(&device_addr, config.category.as_deref(), config.verbose)?;

    println!(
        "\n{}",
        "═══════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "              WATERMARK TESTING COMPLETE".green().bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );

    Ok(())
}

/// Check if the device is reachable via TCP, prompting for PIN if locked
fn check_device_connectivity(ip: &str, port: u16) -> Result<()> {
    let addr = format!("{ip}:{port}");
    let socket_addr: std::net::SocketAddr = addr
        .parse()
        .with_context(|| format!("Invalid address: {addr}"))?;

    // First attempt to connect
    if TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)).is_ok() {
        Ok(())
    } else {
        // Device is likely locked - prompt user for PIN entry
        println!("  {} Device not ready (likely locked)", "!".yellow());
        println!();
        println!(
            "{}",
            "══════════════════════════════════════════════════════════".yellow()
        );
        println!(
            "{}",
            "  Device is locked. Enter your PIN on the device.        "
                .yellow()
                .bold()
        );
        println!(
            "{}",
            "══════════════════════════════════════════════════════════".yellow()
        );
        println!();
        print!("Press ENTER when the device is unlocked... ");
        std::io::stdout().flush().ok();

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("Failed to read user input")?;

        // Poll for the port rather than a single retry: the operator may press
        // ENTER a moment before the signer finishes binding after unlock.
        print!("  Reconnecting... ");
        std::io::stdout().flush().ok();

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)).is_ok() {
                println!("{}", "connected".green());
                return Ok(());
            }
            if Instant::now() >= deadline {
                println!("{}", "failed".red());
                bail!("Still cannot connect to device at {addr} after unlock");
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

/// Run a command on the device over SSH as the unprivileged `russignol` user.
/// Dev images authenticate with a fixed password; hardened images have no SSH.
fn device_ssh(user: &str, ip: &str, cmd: &str) -> Result<()> {
    let output = Command::new("sshpass")
        .args([
            "-p",
            DEVICE_PASS,
            "ssh",
            "-x",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
            &format!("{user}@{ip}"),
            cmd,
        ])
        .output()
        .context("Failed to execute sshpass ssh (is sshpass installed?)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("SSH command failed: {stderr}");
    }
    Ok(())
}

/// Run a command on the device as root via `su`; root has no SSH login, so the
/// unprivileged user escalates with the dev-image password. `cmd` must not
/// contain double quotes.
fn device_ssh_su(user: &str, ip: &str, cmd: &str) -> Result<()> {
    device_ssh(user, ip, &format!("echo {DEVICE_PASS} | su -c \"{cmd}\""))
}

/// Clear the device's stored watermarks, dropping every key to uninitialized so
/// the next unlock reloads a clean slate.
fn clear_watermarks(ip: &str, user: &str) -> Result<()> {
    device_ssh(user, ip, &format!("rm -rf {WATERMARK_DIR}/*"))
}

/// Restart the signer as root. The service comes back at PIN entry, so the
/// caller must wait for the operator to unlock before the port reopens.
fn restart_device(ip: &str, user: &str) -> Result<()> {
    device_ssh_su(user, ip, RESTART_SIGNER_CMD)
}

/// Run the watermark E2E test harness
fn run_test_harness(device_addr: &str, category: Option<&str>, verbose: bool) -> Result<()> {
    let mut args = vec![
        "run",
        "--release",
        "--example",
        "watermark_e2e_test",
        "--package",
        "russignol-signer-lib",
        "--",
        "--device",
        device_addr,
    ];

    if let Some(cat) = category {
        args.push("--category");
        args.push(cat);
    }

    if verbose {
        args.push("--verbose");
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .context("Failed to run test harness")?;

    if !status.success() {
        bail!("Test harness exited with non-zero status");
    }

    Ok(())
}
