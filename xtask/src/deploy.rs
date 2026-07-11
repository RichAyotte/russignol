use anyhow::{Context, Result};
use colored::Colorize;

use crate::build::{build_rpi_signer, get_signer_binary_path};
use crate::device::{DEVICE_HOST, DEVICE_USER, RESTART_SIGNER_CMD, scp, ssh_run, ssh_su};
use crate::utils::check_command;

/// Staging path on the device tmpfs (large enough for debug builds); the SSH
/// user can write here, root moves it into place.
const REMOTE_STAGING: &str = "/tmp/russignol-signer.next";
/// The binary the init scripts run on every boot — installing here (rather
/// than a side location the init never consults) makes the deploy survive
/// reboots.
const REMOTE_BINARY: &str = "/bin/russignol-signer";

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
    scp(DEVICE_USER, DEVICE_HOST, &binary_path, REMOTE_STAGING)?;

    // Everything below runs as root: privileged boots (first boot, migration,
    // watermark recovery) run the signer as root, which the unprivileged SSH
    // user can neither kill nor replace.
    println!("{}", "Installing binary...".cyan());
    // rm-then-cp: overwriting the running binary in place fails with ETXTBSY
    ssh_su(
        DEVICE_USER,
        DEVICE_HOST,
        &format!(
            "rm -f {REMOTE_BINARY} && cp {REMOTE_STAGING} {REMOTE_BINARY} \
             && chmod 755 {REMOTE_BINARY} && rm -f {REMOTE_STAGING} && sync"
        ),
    )?;

    println!("{}", "Restarting signer...".cyan());
    ssh_su(DEVICE_USER, DEVICE_HOST, RESTART_SIGNER_CMD)?;

    // A dead-on-arrival signer must fail the deploy, not print success. Also
    // require it to still be alive a few seconds after startup so an
    // immediate crash-and-exit does not read as running.
    ssh_run(
        DEVICE_USER,
        DEVICE_HOST,
        "for i in 1 2 3 4 5 6 7 8 9 10; do pgrep -f '/bin/[r]ussignol-signer' >/dev/null && break; sleep 1; done; \
         sleep 3; pgrep -f '/bin/[r]ussignol-signer' >/dev/null",
    )
    .context("Signer is not running after deploy")?;

    println!("{}", "✓ Device updated".green());
    Ok(())
}
