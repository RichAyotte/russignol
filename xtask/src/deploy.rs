use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::process::Command;

use crate::build::{build_rpi_signer, get_signer_binary_path};
use crate::utils::check_command;

const DEVICE_USER: &str = "russignol";
const DEVICE_PASS: &str = "russignol";
const DEVICE_HOST: &str = "169.254.1.1";
const REMOTE_BINARY: &str = "/data/russignol-signer";

pub fn deploy(skip_build: bool, dev: bool) -> Result<()> {
    check_command("sshpass", "Install with: sudo apt-get install sshpass")?;

    if !skip_build {
        let mode = if dev { "development" } else { "release" };
        println!("{}", format!("Building {mode} binary...").cyan());
        build_rpi_signer(dev)?;
    }

    let binary_path = get_signer_binary_path(dev)?;

    println!("{}", "Stopping signer on device...".cyan());
    // Character class [r] prevents pkill from matching its own command line
    ssh_run("pkill -f '[r]ussignol-signer' 2>/dev/null; true")?;

    println!(
        "{}",
        format!("Copying {} to device...", binary_path.display()).cyan()
    );
    scp(&binary_path, REMOTE_BINARY)?;

    println!("{}", "Starting signer on device...".cyan());
    ssh_run(&format!("chmod +x {REMOTE_BINARY}"))?;
    // Start in background; nohup + redirect so ssh can disconnect
    ssh_run(&format!("nohup {REMOTE_BINARY} >/dev/null 2>&1 &"))?;

    println!("{}", "✓ Device updated".green());
    Ok(())
}

fn ssh_run(cmd: &str) -> Result<()> {
    let status = Command::new("sshpass")
        .args([
            "-p",
            DEVICE_PASS,
            "ssh",
            "-x",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=5",
            &format!("{DEVICE_USER}@{DEVICE_HOST}"),
            cmd,
        ])
        .status()
        .context("Failed to execute sshpass ssh")?;

    if !status.success() {
        bail!("SSH command failed: {cmd}");
    }
    Ok(())
}

fn scp(local: &std::path::Path, remote: &str) -> Result<()> {
    let status = Command::new("sshpass")
        .args([
            "-p",
            DEVICE_PASS,
            "scp",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ForwardX11=no",
        ])
        .arg(local)
        .arg(format!("{DEVICE_USER}@{DEVICE_HOST}:{remote}"))
        .status()
        .context("Failed to execute sshpass scp")?;

    if !status.success() {
        bail!("SCP failed: {} -> {remote}", local.display());
    }
    Ok(())
}
