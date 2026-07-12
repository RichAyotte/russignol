use std::process::Command;

/// Embed the source commit the signer was built from, so the device can show
/// the exact provenance of a locally built image that carries no release
/// version. `unknown` when built outside a git tree (e.g. from a tarball).
fn main() {
    let hash = git_short_hash().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=RUSSIGNOL_GIT_HASH={hash}");

    // Re-run when HEAD moves or the index changes, so the embedded hash and the
    // dirty suffix track the working tree rather than sticking at first build.
    if let Some(git_dir) = git_dir() {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        println!("cargo:rerun-if-changed={git_dir}/index");
    }
}

fn git_short_hash() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let hash = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if hash.is_empty() {
        return None;
    }
    Some(if git_is_dirty() {
        format!("{hash}-dirty")
    } else {
        hash
    })
}

fn git_is_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .is_ok_and(|o| !o.stdout.is_empty())
}

fn git_dir() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let dir = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!dir.is_empty()).then_some(dir)
}
