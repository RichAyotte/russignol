//! SSH access to the signer device (dev images only; hardened images have no
//! SSH server).

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

pub(crate) const DEVICE_USER: &str = "russignol";
/// Fixed dev-image login (buildroot `users.txt`).
const DEVICE_PASS: &str = "russignol";
/// Link-local USB network address.
pub(crate) const DEVICE_HOST: &str = "169.254.1.1";

/// Reliably restart the signer as root. The init pidfile tracks the `/bin/sh`
/// wrapper, not the signer, so it goes stale and `stop` kills a dead PID while
/// the real process keeps the display GPIO — a second signer then crashes on
/// EBUSY. Kill by name instead, wait for the GPIO to release, then start
/// through the init script (the sole authority on how the signer starts). The
/// `[r]` class stops pkill/pgrep from matching their own command lines.
pub(crate) const RESTART_SIGNER_CMD: &str = "pkill -f '[r]ussignol-signer'; \
     for i in 1 2 3 4 5; do pgrep -f '[r]ussignol-signer' >/dev/null || break; sleep 1; done; \
     /etc/init.d/S20russignol start";

/// Run a command on the device over SSH as the unprivileged dev user.
pub(crate) fn ssh_run(user: &str, host: &str, cmd: &str) -> Result<()> {
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
            &format!("{user}@{host}"),
            cmd,
        ])
        .status()
        .context("Failed to execute sshpass ssh")?;

    if !status.success() {
        bail!("SSH command failed: {cmd}");
    }
    Ok(())
}

/// Run a command on the device as root via `su`; the root account has no SSH
/// login, so the unprivileged user escalates with the dev-image password. The
/// command must not contain double quotes.
pub(crate) fn ssh_su(user: &str, host: &str, cmd: &str) -> Result<()> {
    ssh_run(user, host, &format!("echo {DEVICE_PASS} | su -c \"{cmd}\""))
}

pub(crate) fn scp(user: &str, host: &str, local: &Path, remote: &str) -> Result<()> {
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
        .arg(format!("{user}@{host}:{remote}"))
        .status()
        .context("Failed to execute sshpass scp")?;

    if !status.success() {
        bail!("SCP failed: {} -> {remote}", local.display());
    }
    Ok(())
}
