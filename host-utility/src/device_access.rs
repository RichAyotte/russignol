//! Write-access probing for SD-card target devices.
//!
//! Access is verified by opening the actual device node, not by group
//! membership: udev uaccess ACLs can grant access without the `disk` group,
//! and a session started before a `usermod` lacks the group even though the
//! group database has it. Diagnosis distinguishes those cases so the user is
//! never told to join a group they already belong to.

use std::path::{Path, PathBuf};

/// How raw device writes (dd, sfdisk, mkfs) should be executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashPrivilege {
    Direct,
    Sudo,
}

/// Facts gathered about the device node and the current user when a write
/// open was denied.
#[derive(Debug, Clone)]
pub struct AccessFacts {
    pub device: PathBuf,
    /// Permission bits of the device node (file-type bits may be present).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Name of the node's owning group; `None` when the gid has no name in
    /// the group database.
    pub group_name: Option<String>,
    /// Supplementary groups of the running process (session credentials).
    pub process_gids: Vec<u32>,
    /// Groups the user belongs to per the group database; `None` when the
    /// lookup itself failed (membership unknown, not absent).
    pub db_gids: Option<Vec<u32>>,
    pub user_name: String,
}

/// Why the write open was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeniedCause {
    /// User is a member per the group database, but the session credentials
    /// predate the membership.
    MembershipNotActive { group: String },
    /// User is verifiably not a member of the node's owning group.
    NotInGroup { group: String },
    /// The group database could not be read; membership is unverifiable.
    MembershipUnknown { group: String },
    /// The owning group is active in the session yet the open was denied
    /// anyway (e.g. an ACL mask or MAC policy); membership fixes can't help.
    DeniedDespiteGroup { group: String },
    /// No group grants write access to the node (e.g. root:root 0600).
    NoGroupPath,
}

fn group_label(facts: &AccessFacts) -> String {
    facts
        .group_name
        .clone()
        .unwrap_or_else(|| format!("gid {}", facts.gid))
}

pub fn diagnose_denied(facts: &AccessFacts) -> DeniedCause {
    let group_writable = facts.mode & 0o020 != 0;
    if !group_writable {
        return DeniedCause::NoGroupPath;
    }
    let group = group_label(facts);
    // The kernel checks the process's credentials, not the group database:
    // a denial with the group already active is not a membership problem.
    if facts.process_gids.contains(&facts.gid) {
        return DeniedCause::DeniedDespiteGroup { group };
    }
    match &facts.db_gids {
        None => DeniedCause::MembershipUnknown { group },
        Some(db_gids) if db_gids.contains(&facts.gid) => DeniedCause::MembershipNotActive { group },
        Some(_) => DeniedCause::NotInGroup { group },
    }
}

pub fn render_denied_message(
    cause: &DeniedCause,
    facts: &AccessFacts,
    interactive: bool,
) -> String {
    let dev = facts.device.display();
    let mode = facts.mode & 0o7777;
    let user = &facts.user_name;
    let header = format!("Cannot write to {dev}: permission denied.");
    let body = match cause {
        DeniedCause::MembershipNotActive { group } => format!(
            "{dev} is writable by group '{group}' and user '{user}' is already a member \
             of '{group}', but this login session started before the membership was added, \
             so it is not active here.\n\
             \x20 • Permanent fix: log out completely (or reboot), then log back in.\n\
             \x20 • Right now, without root: sg {group} -c \"russignol ...\""
        ),
        DeniedCause::NotInGroup { group } => format!(
            "{dev} is writable by group '{group}', but user '{user}' is not a member of '{group}'.\n\
             \x20 • Permanent fix: sudo usermod -aG {group} {user}, then log out completely \
             (or reboot) and log back in.\n\
             \x20 • Once added, continue immediately without re-login: sg {group} -c \"russignol ...\""
        ),
        DeniedCause::MembershipUnknown { group } => format!(
            "{dev} is writable by group '{group}', but membership of user '{user}' in \
             '{group}' could not be verified (group database lookup failed).\n\
             \x20 • Check yourself with: groups {user}"
        ),
        DeniedCause::DeniedDespiteGroup { group } => format!(
            "{dev} is writable by group '{group}' and '{group}' is active in this session, \
             but the write was still denied — an ACL or security policy (e.g. SELinux, \
             AppArmor) may be restricting access.\n\
             \x20 • The write can run with sudo."
        ),
        DeniedCause::NoGroupPath => format!(
            "{dev} is owned by uid {uid}, group '{group}', mode {mode:03o} — no group grants \
             write access to your user.\n\
             \x20 • Removable media is normally made accessible by a udev rule or uaccess ACL; \
             alternatively the write can run with sudo.",
            uid = facts.uid,
            group = group_label(facts),
        ),
    };
    let footer = if interactive {
        "Choose how to continue below."
    } else {
        "Re-run interactively (without --yes, with a terminal) for guided recovery options."
    };
    format!("{header}\n{body}\n{footer}")
}

/// Gather the facts needed to explain a denied write open.
#[cfg(target_os = "linux")]
pub fn gather_access_facts(device: &Path) -> anyhow::Result<AccessFacts> {
    use std::ffi::CString;
    use std::os::unix::fs::MetadataExt;

    use anyhow::Context;
    use nix::unistd::{Gid, Group, User, getegid, geteuid, getgrouplist, getgroups};

    let meta = std::fs::metadata(device)
        .with_context(|| format!("Cannot stat device {}", device.display()))?;
    let gid = meta.gid();
    let group_name = Group::from_gid(Gid::from_raw(gid))
        .ok()
        .flatten()
        .map(|g| g.name);
    let mut process_gids: Vec<u32> = getgroups()
        .map(|gids| gids.iter().map(|g| g.as_raw()).collect())
        .unwrap_or_default();
    process_gids.push(getegid().as_raw());
    let user = User::from_uid(geteuid()).ok().flatten();
    let (user_name, primary_gid) = match user {
        Some(u) => (u.name, u.gid),
        None => (
            std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()),
            getegid(),
        ),
    };
    let db_gids = CString::new(user_name.clone())
        .ok()
        .and_then(|name| getgrouplist(&name, primary_gid).ok())
        .map(|gids| gids.iter().map(|g| g.as_raw()).collect());
    Ok(AccessFacts {
        device: device.to_path_buf(),
        mode: meta.mode(),
        uid: meta.uid(),
        gid,
        group_name,
        process_gids,
        db_gids,
        user_name,
    })
}

/// Verify write access by opening the device node itself.
///
/// On permission denial, diagnose the cause and (interactively) offer
/// recovery: re-exec through `sg` when group membership already exists,
/// consented `usermod` + `sg` when it doesn't, or sudo for the raw writes.
/// `reexec_device_arg` is appended as `--device` on re-exec so an
/// interactively selected device survives; pass `None` when the current
/// argv would not accept it.
#[cfg(target_os = "linux")]
pub fn probe_write_access(
    device: &Path,
    reexec_device_arg: Option<&Path>,
    yes: bool,
) -> anyhow::Result<FlashPrivilege> {
    use anyhow::{Context, bail};

    match std::fs::OpenOptions::new().write(true).open(device) {
        Ok(_) => Ok(FlashPrivilege::Direct),
        // The kernel checks permissions before rejecting a busy device
        // (e.g. automounted partitions), so EBUSY proves the node is
        // writable; mounts are removed at flash time.
        Err(e) if e.kind() == std::io::ErrorKind::ResourceBusy => Ok(FlashPrivilege::Direct),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let interactive = !yes && !crate::confirmation::is_non_interactive();
            let facts = gather_access_facts(device)?;
            let cause = diagnose_denied(&facts);
            let message = render_denied_message(&cause, &facts, interactive);
            if !interactive {
                bail!("{message}");
            }
            println!();
            crate::utils::warning(&message);
            println!();
            recovery_menu(&cause, &facts, reexec_device_arg, &message)
        }
        Err(e) => {
            Err(e).with_context(|| format!("Cannot open device {} for writing", device.display()))
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn probe_write_access(
    _device: &Path,
    _reexec_device_arg: Option<&Path>,
    _yes: bool,
) -> anyhow::Result<FlashPrivilege> {
    Ok(FlashPrivilege::Direct)
}

#[cfg(target_os = "linux")]
enum Recovery {
    UseExistingMembership(String),
    AddToGroupAndContinue(String),
    SudoWrites,
    Quit,
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for Recovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Recovery::UseExistingMembership(group) => write!(
                f,
                "Continue with your existing '{group}' membership (re-runs via sg, no password)"
            ),
            Recovery::AddToGroupAndContinue(group) => {
                write!(f, "Add me to '{group}' now (sudo usermod) and continue")
            }
            Recovery::SudoWrites => write!(f, "Run the SD-card write steps with sudo"),
            Recovery::Quit => write!(f, "Quit"),
        }
    }
}

#[cfg(target_os = "linux")]
fn recovery_menu(
    cause: &DeniedCause,
    facts: &AccessFacts,
    reexec_device_arg: Option<&std::path::Path>,
    message: &str,
) -> anyhow::Result<FlashPrivilege> {
    use anyhow::bail;

    let sg = crate::utils::resolve_tool("sg").filter(|_| facts.group_name.is_some());
    let sudo_available = crate::utils::command_exists("sudo");
    let mut options = Vec::new();
    match cause {
        DeniedCause::MembershipNotActive { group } if sg.is_some() => {
            options.push(Recovery::UseExistingMembership(group.clone()));
        }
        DeniedCause::NotInGroup { group } if sg.is_some() && sudo_available => {
            options.push(Recovery::AddToGroupAndContinue(group.clone()));
        }
        _ => {}
    }
    if sudo_available {
        options.push(Recovery::SudoWrites);
    }
    options.push(Recovery::Quit);

    let choice = inquire::Select::new("How would you like to proceed?", options)
        .with_render_config(crate::utils::create_orange_theme())
        .prompt();
    match choice {
        Ok(Recovery::UseExistingMembership(group)) => {
            exec_via_sg(&sg.expect("gated above"), &group, reexec_device_arg)
        }
        Ok(Recovery::AddToGroupAndContinue(group)) => {
            let output = crate::utils::sudo_command("usermod", &["-aG", &group, &facts.user_name])?;
            if !output.status.success() {
                bail!(
                    "usermod failed: {}\n{message}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            crate::utils::success(&format!("Added '{}' to group '{group}'", facts.user_name));
            exec_via_sg(&sg.expect("gated above"), &group, reexec_device_arg)
        }
        Ok(Recovery::SudoWrites) => Ok(FlashPrivilege::Sudo),
        Ok(Recovery::Quit) | Err(_) => bail!("{message}"),
    }
}

/// Replace this process with the same invocation run under `sg <group>`,
/// picking up the group membership the current session is missing.
#[cfg(target_os = "linux")]
fn exec_via_sg(
    sg: &std::path::Path,
    group: &str,
    reexec_device_arg: Option<&std::path::Path>,
) -> anyhow::Result<FlashPrivilege> {
    use std::os::unix::process::CommandExt;

    use anyhow::Context;

    let exe = std::env::current_exe().context("Cannot determine current executable path")?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = sg_reexec_command(&exe, &args, reexec_device_arg);
    crate::utils::info(&format!("Re-running: sg {group} -c \"{command}\""));
    let err = std::process::Command::new(sg)
        .arg(group)
        .arg("-c")
        .arg(&command)
        .exec();
    Err(err).context("Failed to re-exec via sg")
}

/// Quote a string for POSIX sh (the shell `sg -c` uses).
pub fn shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@".contains(c));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Rebuild the current invocation as a single sh command for `sg <group> -c`.
///
/// `--device` is appended when the original arguments carry none, so an
/// interactively selected device survives the re-exec without re-prompting.
pub fn sg_reexec_command(
    exe_path: &Path,
    args: &[String],
    selected_device: Option<&Path>,
) -> String {
    let mut parts = vec![shell_quote(&exe_path.display().to_string())];
    parts.extend(args.iter().map(|a| shell_quote(a)));
    let has_device = args
        .iter()
        .any(|a| a == "--device" || a.starts_with("--device="));
    if let Some(device) = selected_device
        && !has_device
    {
        parts.push("--device".to_string());
        parts.push(shell_quote(&device.display().to_string()));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(
        mode: u32,
        gid: u32,
        group_name: Option<&str>,
        process_gids: &[u32],
        db_gids: Option<&[u32]>,
    ) -> AccessFacts {
        AccessFacts {
            device: PathBuf::from("/dev/sdz"),
            mode,
            uid: 0,
            gid,
            group_name: group_name.map(str::to_string),
            process_gids: process_gids.to_vec(),
            db_gids: db_gids.map(<[u32]>::to_vec),
            user_name: "alice".to_string(),
        }
    }

    fn all_causes() -> Vec<(DeniedCause, AccessFacts)> {
        vec![
            (
                DeniedCause::MembershipNotActive {
                    group: "disk".into(),
                },
                facts(0o660, 6, Some("disk"), &[100], Some(&[100, 6])),
            ),
            (
                DeniedCause::NotInGroup {
                    group: "disk".into(),
                },
                facts(0o660, 6, Some("disk"), &[100], Some(&[100])),
            ),
            (
                DeniedCause::MembershipUnknown {
                    group: "disk".into(),
                },
                facts(0o660, 6, Some("disk"), &[100], None),
            ),
            (
                DeniedCause::NoGroupPath,
                facts(0o600, 0, Some("root"), &[100], Some(&[100])),
            ),
            (
                DeniedCause::DeniedDespiteGroup {
                    group: "disk".into(),
                },
                facts(0o660, 6, Some("disk"), &[100, 6], Some(&[100, 6])),
            ),
        ]
    }

    #[test]
    fn diagnose_membership_not_active_when_db_has_group_but_session_lacks_it() {
        let f = facts(0o660, 6, Some("disk"), &[100, 24], Some(&[100, 24, 6]));
        assert_eq!(
            diagnose_denied(&f),
            DeniedCause::MembershipNotActive {
                group: "disk".into()
            }
        );
    }

    #[test]
    fn diagnose_not_in_group_when_db_verifiably_lacks_group() {
        let f = facts(0o660, 6, Some("disk"), &[100], Some(&[100, 24]));
        assert_eq!(
            diagnose_denied(&f),
            DeniedCause::NotInGroup {
                group: "disk".into()
            }
        );
    }

    #[test]
    fn diagnose_membership_unknown_when_db_lookup_failed() {
        let f = facts(0o660, 6, Some("disk"), &[100], None);
        assert_eq!(
            diagnose_denied(&f),
            DeniedCause::MembershipUnknown {
                group: "disk".into()
            }
        );
    }

    #[test]
    fn diagnose_no_group_path_for_root_owned_0600() {
        let f = facts(0o600, 0, Some("root"), &[100], Some(&[100]));
        assert_eq!(diagnose_denied(&f), DeniedCause::NoGroupPath);
    }

    #[test]
    fn diagnose_active_group_denial_as_non_membership_problem() {
        let f = facts(0o660, 6, Some("disk"), &[100, 6], Some(&[100, 6]));
        assert_eq!(
            diagnose_denied(&f),
            DeniedCause::DeniedDespiteGroup {
                group: "disk".into()
            }
        );
    }

    #[test]
    fn diagnose_by_session_credentials_even_when_db_disagrees() {
        // The kernel checks process credentials, not the group database.
        let f = facts(0o660, 6, Some("disk"), &[100, 6], Some(&[100]));
        assert_eq!(
            diagnose_denied(&f),
            DeniedCause::DeniedDespiteGroup {
                group: "disk".into()
            }
        );
    }

    #[test]
    fn denied_despite_group_message_offers_sudo_not_sg() {
        let f = facts(0o660, 6, Some("disk"), &[100, 6], Some(&[100, 6]));
        let cause = DeniedCause::DeniedDespiteGroup {
            group: "disk".into(),
        };
        for interactive in [true, false] {
            let msg = render_denied_message(&cause, &f, interactive);
            assert!(msg.contains("sudo"), "should offer sudo: {msg}");
            assert!(
                !msg.contains("sg "),
                "sg cannot help when the group is already active: {msg}"
            );
        }
    }

    #[test]
    fn message_names_actual_group_not_disk() {
        let f = facts(0o660, 24, Some("cdrom"), &[100], Some(&[100, 24]));
        let cause = diagnose_denied(&f);
        let msg = render_denied_message(&cause, &f, true);
        assert!(msg.contains("cdrom"), "message should name cdrom: {msg}");
        assert!(
            !msg.contains("'disk'"),
            "message must not claim 'disk': {msg}"
        );
    }

    #[test]
    fn message_uses_numeric_gid_when_group_name_lookup_failed() {
        let f = facts(0o660, 977, None, &[100], Some(&[100, 977]));
        let cause = diagnose_denied(&f);
        let msg = render_denied_message(&cause, &f, true);
        assert!(msg.contains("977"), "message should show the gid: {msg}");
        assert!(!msg.contains("disk"), "no invented group name: {msg}");
    }

    #[test]
    fn messages_never_suggest_other_flash_tools() {
        for (cause, f) in all_causes() {
            for interactive in [true, false] {
                let msg = render_denied_message(&cause, &f, interactive);
                for forbidden in ["Raspberry Pi Imager", "another tool", "Imager"] {
                    assert!(
                        !msg.contains(forbidden),
                        "{cause:?} message must not mention {forbidden:?}: {msg}"
                    );
                }
            }
        }
    }

    #[test]
    fn membership_not_active_message_offers_sg_and_relogin_only() {
        let f = facts(0o660, 6, Some("disk"), &[100], Some(&[100, 6]));
        let cause = DeniedCause::MembershipNotActive {
            group: "disk".into(),
        };
        let msg = render_denied_message(&cause, &f, false);
        assert!(msg.contains("sg "), "should offer sg: {msg}");
        assert!(
            msg.contains("log out") || msg.contains("reboot"),
            "should mention full re-login/reboot: {msg}"
        );
        assert!(
            msg.contains("already a member"),
            "must state membership exists: {msg}"
        );
    }

    #[test]
    fn not_in_group_message_suggests_usermod() {
        let f = facts(0o660, 6, Some("disk"), &[100], Some(&[100]));
        let cause = DeniedCause::NotInGroup {
            group: "disk".into(),
        };
        let msg = render_denied_message(&cause, &f, false);
        assert!(
            msg.contains("usermod -aG disk alice"),
            "should suggest usermod with real user: {msg}"
        );
    }

    #[test]
    fn only_verified_non_members_are_told_to_join_a_group() {
        for (cause, f) in all_causes() {
            let expects_usermod = matches!(cause, DeniedCause::NotInGroup { .. });
            for interactive in [true, false] {
                let msg = render_denied_message(&cause, &f, interactive);
                assert_eq!(
                    msg.contains("usermod"),
                    expects_usermod,
                    "{cause:?} usermod suggestion wrong (interactive={interactive}): {msg}"
                );
            }
        }
    }

    #[test]
    fn membership_unknown_message_says_unverified_and_mentions_groups_command() {
        let f = facts(0o660, 6, Some("disk"), &[100], None);
        let cause = DeniedCause::MembershipUnknown {
            group: "disk".into(),
        };
        let msg = render_denied_message(&cause, &f, false);
        assert!(
            msg.contains("could not") && msg.contains("verif"),
            "must admit membership is unverified: {msg}"
        );
        assert!(
            msg.contains("groups"),
            "should point at the groups command: {msg}"
        );
    }

    #[test]
    fn shell_quote_handles_spaces_and_single_quotes() {
        assert_eq!(shell_quote("plain-arg_1.img"), "plain-arg_1.img");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn sg_reexec_appends_selected_device_when_absent() {
        let cmd = sg_reexec_command(
            Path::new("/usr/local/bin/russignol"),
            &["image".into(), "flash".into(), "my image.xz".into()],
            Some(Path::new("/dev/sdc")),
        );
        assert_eq!(
            cmd,
            "/usr/local/bin/russignol image flash 'my image.xz' --device /dev/sdc"
        );
    }

    #[test]
    fn sg_reexec_does_not_duplicate_existing_device_arg() {
        let cmd = sg_reexec_command(
            Path::new("/usr/local/bin/russignol"),
            &[
                "image".into(),
                "flash".into(),
                "--device".into(),
                "/dev/sdc".into(),
            ],
            Some(Path::new("/dev/sdc")),
        );
        assert_eq!(
            cmd,
            "/usr/local/bin/russignol image flash --device /dev/sdc"
        );
        let with_eq = sg_reexec_command(
            Path::new("/usr/local/bin/russignol"),
            &["image".into(), "flash".into(), "--device=/dev/sdc".into()],
            Some(Path::new("/dev/sdc")),
        );
        assert_eq!(
            with_eq,
            "/usr/local/bin/russignol image flash --device=/dev/sdc"
        );
    }
}
