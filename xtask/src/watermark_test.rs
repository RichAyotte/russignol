//! Watermark E2E Testing Command
//!
//! Orchestrates watermark protection testing on a physical Russignol device.

use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::io::Write;
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

/// Default device address (link-local USB network)
const DEFAULT_DEVICE_IP: &str = "169.254.1.1";
const DEFAULT_DEVICE_PORT: u16 = 7732;

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
        println!("  {} Service restarted", "✓".green());

        // Wait for service to come back up
        println!("  Waiting for service to start...");
        std::thread::sleep(Duration::from_secs(5));

        // Verify connectivity after restart
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

        // Try to connect again
        print!("  Reconnecting... ");
        std::io::stdout().flush().ok();

        match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)) {
            Ok(_) => {
                println!("{}", "connected".green());
                Ok(())
            }
            Err(e) => {
                println!("{}", "failed".red());
                bail!("Still cannot connect to device at {addr}: {e}")
            }
        }
    }
}

/// Clear watermark files on the device via SSH
fn clear_watermarks(ip: &str, user: &str) -> Result<()> {
    let ssh_target = format!("{user}@{ip}");

    let output = Command::new("ssh")
        .args([
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=accept-new",
            &ssh_target,
            "rm -f /home/russignol/.tezos-signer/*_high_watermark",
        ])
        .output()
        .context("Failed to execute SSH command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to clear watermarks: {stderr}");
    }

    Ok(())
}

/// Restart the Russignol service on the device
fn restart_device(ip: &str, user: &str) -> Result<()> {
    let ssh_target = format!("{user}@{ip}");

    let output = Command::new("ssh")
        .args([
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=accept-new",
            &ssh_target,
            "sudo systemctl restart russignol",
        ])
        .output()
        .context("Failed to execute SSH command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to restart service: {stderr}");
    }

    Ok(())
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
