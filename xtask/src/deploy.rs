use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::process::Command;

use crate::build::{build_rpi_signer, get_signer_binary_path};
use crate::utils::check_command;

const DEVICE_USER: &str = "russignol";
/// Fixed dev-image login (buildroot `users.txt`); hardened images have no SSH.
pub(crate) const DEVICE_PASS: &str = "russignol";
const DEVICE_HOST: &str = "169.254.1.1";
/// Staging path on the device tmpfs (large enough for debug builds); the SSH
/// user can write here, root moves it into place.
const REMOTE_STAGING: &str = "/tmp/russignol-signer.next";
/// The binary the init scripts run on every boot — installing here (rather
/// than a side location the init never consults) makes the deploy survive
/// reboots.
const REMOTE_BINARY: &str = "/bin/russignol-signer";

/// Reliably restart the signer as root. The init pidfile tracks the `/bin/sh`
/// wrapper, not the signer, so it goes stale and `stop` kills a dead PID while
/// the real process keeps the display GPIO — a second signer then crashes on
/// EBUSY. Kill by name instead, wait for the GPIO to release, then start
/// through the init script (the sole authority on how the signer starts). The
/// `[r]` class stops pkill/pgrep from matching their own command lines.
pub(crate) const RESTART_SIGNER_CMD: &str = "pkill -f '[r]ussignol-signer'; \
     for i in 1 2 3 4 5; do pgrep -f '[r]ussignol-signer' >/dev/null || break; sleep 1; done; \
     /etc/init.d/S20russignol start";

pub fn deploy(skip_build: bool, dev: bool) -> Result<()> {
    check_command("sshpass", "Install with: sudo apt-get install sshpass")?;

    if !skip_build {
        let mode = if dev { "development" } else { "release" };
        println!("{}", format!("Building {mode} binary...").cyan());
        build_rpi_signer(dev)?;
    }

    let binary_path = get_signer_binary_path(dev)?;

    println!(
        "{}",
        format!("Copying {} to device...", binary_path.display()).cyan()
    );
    scp(&binary_path, REMOTE_STAGING)?;

    // Everything below runs as root: privileged boots (first boot, migration,
    // watermark recovery) run the signer as root, which the unprivileged SSH
    // user can neither kill nor replace.
    println!("{}", "Installing binary...".cyan());
    // rm-then-cp: overwriting the running binary in place fails with ETXTBSY
    ssh_su(&format!(
        "rm -f {REMOTE_BINARY} && cp {REMOTE_STAGING} {REMOTE_BINARY} \
         && chmod 755 {REMOTE_BINARY} && rm -f {REMOTE_STAGING} && sync"
    ))?;

    println!("{}", "Restarting signer...".cyan());
    ssh_su(RESTART_SIGNER_CMD)?;

    // A dead-on-arrival signer must fail the deploy, not print success. Also
    // require it to still be alive a few seconds after startup so an
    // immediate crash-and-exit does not read as running.
    ssh_run(
        "for i in 1 2 3 4 5 6 7 8 9 10; do pgrep -f '/bin/[r]ussignol-signer' >/dev/null && break; sleep 1; done; \
         sleep 3; pgrep -f '/bin/[r]ussignol-signer' >/dev/null",
    )
    .context("Signer is not running after deploy")?;

    println!("{}", "✓ Device updated".green());
    Ok(())
}

/// Run a command on the device as root via `su` (dev images only; the root
/// account has no SSH login). The command must not contain double quotes.
fn ssh_su(cmd: &str) -> Result<()> {
    ssh_run(&format!("echo {DEVICE_PASS} | su -c \"{cmd}\""))
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
