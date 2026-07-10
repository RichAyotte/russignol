//! Maintainer signing-key tooling: generate a key, protect its seed at rest
//! behind a passphrase, and sign release images with it.
//!
//! The seed rides through `russignol-crypto`'s string API as hex, matching how
//! the device stores its own secrets, so no new cipher is introduced here. The
//! sign/verify contract lives in `russignol-release-signature`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use russignol_crypto::{decrypt, encrypt};
use russignol_release_signature::{generate_seed, public_key};
use zeroize::Zeroizing;

/// Default location of the sealed maintainer seed, under the XDG config dir.
///
/// # Errors
///
/// Returns an error if the config directory cannot be determined.
pub fn default_key_path() -> Result<PathBuf> {
    let config_dir = dirs::config_dir()
        .context("could not determine config directory (XDG_CONFIG_HOME or ~/.config)")?;
    Ok(config_dir.join("russignol").join("maintainer-key"))
}

/// The maintainer key location: `explicit` when given, else [`default_key_path`].
fn resolve_key_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    match explicit {
        Some(path) => Ok(path),
        None => default_key_path(),
    }
}

/// Generate a maintainer signing key, seal its seed behind a freshly prompted
/// passphrase, write it to `output` (or [`default_key_path`]), and print the
/// public key as a literal ready to paste into `MAINTAINER_PUBKEY`.
///
/// # Errors
///
/// Returns an error if a key already exists at the target path, the passphrase
/// prompt fails or is not confirmed, the OS random source is unavailable, or
/// the sealed seed cannot be written.
pub fn cmd_maintainer_keygen(output: Option<PathBuf>) -> Result<()> {
    let key_path = resolve_key_path(output)?;

    if key_path.exists() {
        bail!(
            "refusing to overwrite an existing maintainer key at {}; \
             remove it explicitly if you really mean to replace it",
            key_path.display()
        );
    }

    let passphrase = prompt_new_passphrase()?;
    let pubkey = generate_and_write_sealed_key(&key_path, passphrase.as_bytes())?;

    println!(
        "{} Sealed maintainer key written to {}",
        "✓".green(),
        key_path.display()
    );
    println!("{}", format_pubkey_literal(&pubkey));
    Ok(())
}

/// Generate a fresh seed, seal it under `passphrase`, write it owner-only to
/// `key_path` (failing if the file already exists), and return the public key.
fn generate_and_write_sealed_key(key_path: &Path, passphrase: &[u8]) -> Result<[u8; 32]> {
    let seed = generate_seed().context("failed to read the OS random source")?;
    let pubkey = public_key(&seed);
    let blob = seal_seed(passphrase, &seed).context("failed to seal the seed")?;

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    write_private(key_path, &blob)
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    Ok(pubkey)
}

/// Prompt twice for a new passphrase, returning it only if both entries match.
fn prompt_new_passphrase() -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(
        rpassword::prompt_password("New maintainer key passphrase: ")
            .context("failed to read passphrase")?,
    );
    if first.is_empty() {
        bail!("passphrase must not be empty");
    }
    let confirm = Zeroizing::new(
        rpassword::prompt_password("Confirm passphrase: ").context("failed to read passphrase")?,
    );
    if first.as_str() != confirm.as_str() {
        bail!("passphrases did not match");
    }
    Ok(first)
}

/// Write `bytes` to `path`, creating it owner-only and failing if it exists.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

/// Render the public key as hex plus a ready-to-paste `MAINTAINER_PUBKEY`
/// literal for `host-utility/src/release_signature.rs`.
fn format_pubkey_literal(pubkey: &[u8; 32]) -> String {
    use std::fmt::Write;

    let mut out = format!("\nPublic key (hex): {}\n", hex::encode(pubkey));
    out.push_str("\nPaste into host-utility/src/release_signature.rs:\n\n");
    out.push_str("pub const MAINTAINER_PUBKEY: Option<[u8; 32]> = Some([\n");
    for row in pubkey.chunks(8) {
        let bytes: Vec<String> = row.iter().map(|b| format!("0x{b:02x}")).collect();
        writeln!(out, "    {},", bytes.join(", ")).expect("writing to a String cannot fail");
    }
    out.push_str("]);");
    out
}

/// Seal a 32-byte signing seed under `passphrase` for at-rest storage.
///
/// # Errors
///
/// Propagates any error from the underlying authenticated encryption.
pub fn seal_seed(passphrase: &[u8], seed: &[u8; 32]) -> io::Result<Vec<u8>> {
    let seed_hex = Zeroizing::new(hex::encode(seed));
    encrypt(passphrase, seed_hex.as_str())
}

/// Unseal a 32-byte signing seed previously sealed by [`seal_seed`]. The
/// decrypted hex is zeroized as it is decoded straight into the returned buffer,
/// so the raw seed never lands in an unzeroized copy.
///
/// # Errors
///
/// Returns an error if decryption fails (wrong passphrase or tampered blob) or
/// the recovered plaintext is not exactly 32 bytes of hex.
pub fn unseal_seed(passphrase: &[u8], blob: &[u8]) -> io::Result<Zeroizing<[u8; 32]>> {
    let seed_hex = decrypt(passphrase, blob)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(seed_hex.as_str(), seed.as_mut())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(seed)
}

/// Prompt once for the maintainer key passphrase.
fn prompt_passphrase() -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        rpassword::prompt_password("Maintainer key passphrase: ")
            .context("failed to read passphrase")?,
    ))
}

/// Sign the image at `image` with the sealed key at `key_path`, prompting once
/// for its passphrase, and write the detached signature sidecar where the
/// flash-time verifier looks for it.
///
/// # Errors
///
/// Returns an error if the image or key is missing, the passphrase cannot be
/// read, the key cannot be unsealed, or the sidecar cannot be written.
pub fn cmd_maintainer_sign(image: &Path, key: Option<PathBuf>) -> Result<()> {
    let key_path = resolve_key_path(key)?;
    let sidecar = sign_image_with_prompt(image, &key_path)?;
    println!(
        "{} Detached signature written to {}",
        "✓".green(),
        sidecar.display()
    );
    Ok(())
}

/// [`sign_image`] with the passphrase prompted from the terminal.
///
/// # Errors
///
/// Propagates [`sign_image`] errors, plus a failed passphrase read.
pub fn sign_image_with_prompt(image: &Path, key_path: &Path) -> Result<PathBuf> {
    sign_image(image, key_path, prompt_passphrase)
}

/// A signing input that was absent. Typed so callers can apply their own
/// missing-input policy: `maintainer-sign` fails, a release build skips the
/// unbuilt image or warns and ships unsigned.
#[derive(Debug)]
pub enum MissingSigningInput {
    /// No image at the given path.
    Image(PathBuf),
    /// No sealed maintainer key at the given path.
    Key(PathBuf),
}

impl std::fmt::Display for MissingSigningInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Image(path) => write!(f, "image not found: {}", path.display()),
            Self::Key(path) => write!(
                f,
                "no maintainer key at {}; generate one with `cargo xtask maintainer-keygen`",
                path.display()
            ),
        }
    }
}

impl std::error::Error for MissingSigningInput {}

/// Digest `image`, sign it with the sealed key at `key_path`, and write the
/// signature (hex plus a trailing newline) to the image's sidecar path,
/// returning that path. Any sidecar already present is removed up front —
/// whatever it signed, it was not produced by this run — so a `.sig` exists
/// only when this run signed the image beside it. `passphrase` is invoked only
/// after the image and key are known to exist, so a prompting supplier never
/// wastes an entry on an invocation that cannot sign.
///
/// # Errors
///
/// Returns [`MissingSigningInput`] if the image or key does not exist, and an
/// opaque error if a stale sidecar cannot be removed, an existence check
/// fails, the passphrase supplier fails, unsealing fails (wrong passphrase or
/// tampered file), or the sidecar cannot be written.
fn sign_image(
    image: &Path,
    key_path: &Path,
    passphrase: impl FnOnce() -> Result<Zeroizing<String>>,
) -> Result<PathBuf> {
    let sidecar = russignol_release_signature::sidecar_path(image);
    if let Err(err) = fs::remove_file(&sidecar)
        && err.kind() != io::ErrorKind::NotFound
    {
        return Err(err).with_context(|| format!("failed to remove stale {}", sidecar.display()));
    }
    if !image
        .try_exists()
        .with_context(|| format!("failed to check for image {}", image.display()))?
    {
        return Err(MissingSigningInput::Image(image.to_path_buf()).into());
    }
    if !key_path
        .try_exists()
        .with_context(|| format!("failed to check for key {}", key_path.display()))?
    {
        return Err(MissingSigningInput::Key(key_path.to_path_buf()).into());
    }
    let digest = crate::compute_sha256(image)?;
    let signature = sign_digest(key_path, passphrase()?.as_bytes(), &digest)?;
    std::fs::write(&sidecar, format!("{signature}\n"))
        .with_context(|| format!("failed to write {}", sidecar.display()))?;
    Ok(sidecar)
}

/// Read the sealed key at `key_path`, unseal it under `passphrase`, and sign
/// `digest_hex`.
fn sign_digest(key_path: &Path, passphrase: &[u8], digest_hex: &str) -> Result<String> {
    let blob =
        fs::read(key_path).with_context(|| format!("failed to read {}", key_path.display()))?;
    let seed = unseal_seed(passphrase, &blob)
        .context("failed to unseal the maintainer key (wrong passphrase?)")?;
    russignol_release_signature::sign(&seed, digest_hex).context("failed to sign the image digest")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x11; 32];
    const PASS: &[u8] = b"correct horse battery staple";

    /// The test passphrase in the form [`sign_image`]'s supplier yields it.
    fn test_passphrase() -> Zeroizing<String> {
        Zeroizing::new(String::from_utf8(PASS.to_vec()).expect("test passphrase is UTF-8"))
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let blob = seal_seed(PASS, &SEED).unwrap();
        let recovered = unseal_seed(PASS, &blob).unwrap();
        assert_eq!(*recovered, SEED);
    }

    #[test]
    fn unseal_wrong_passphrase_fails() {
        let blob = seal_seed(PASS, &SEED).unwrap();
        assert!(unseal_seed(b"wrong passphrase", &blob).is_err());
    }

    #[test]
    fn unseal_tampered_blob_fails() {
        let mut blob = seal_seed(PASS, &SEED).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(unseal_seed(PASS, &blob).is_err());
    }

    #[test]
    fn keygen_writes_owner_only_recoverable_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("maintainer-key");

        let pubkey = generate_and_write_sealed_key(&key_path, PASS).unwrap();

        // The file on disk unseals to a seed whose public key is the one we
        // reported to the operator — the paste-in key really matches the seed.
        let blob = std::fs::read(&key_path).unwrap();
        let seed = unseal_seed(PASS, &blob).unwrap();
        assert_eq!(public_key(&seed), pubkey);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn keygen_refuses_to_clobber_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("maintainer-key");

        generate_and_write_sealed_key(&key_path, PASS).unwrap();
        assert!(generate_and_write_sealed_key(&key_path, PASS).is_err());
    }

    #[test]
    fn sealed_key_signs_verifiably() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("maintainer-key");
        let pubkey = generate_and_write_sealed_key(&key_path, PASS).unwrap();

        let digest = hex::encode([0xcd_u8; 32]);
        let sig = sign_digest(&key_path, PASS, &digest).unwrap();

        // The release signature verifies under the reported public key — the
        // full sign-side pipeline agrees with the host verifier.
        assert_eq!(
            russignol_release_signature::verify(&pubkey, &digest, &sig),
            Ok(())
        );
    }

    #[test]
    fn sign_image_writes_a_verifiable_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("maintainer-key");
        let pubkey = generate_and_write_sealed_key(&key_path, PASS).unwrap();
        let image = dir.path().join("image.img.xz");
        std::fs::write(&image, b"image bytes").unwrap();

        let sidecar = sign_image(&image, &key_path, || Ok(test_passphrase())).unwrap();

        assert_eq!(sidecar, russignol_release_signature::sidecar_path(&image));
        let content = std::fs::read_to_string(&sidecar).unwrap();
        assert!(
            content.ends_with('\n'),
            "the sidecar is a single hex line with a trailing newline"
        );
        let digest = crate::compute_sha256(&image).unwrap();
        assert_eq!(
            russignol_release_signature::verify(&pubkey, &digest, content.trim()),
            Ok(())
        );
    }

    #[test]
    fn failed_signing_removes_a_stale_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("maintainer-key");
        generate_and_write_sealed_key(&key_path, PASS).unwrap();
        let image = dir.path().join("image.img.xz");
        std::fs::write(&image, b"fresh image bytes").unwrap();
        let sidecar = russignol_release_signature::sidecar_path(&image);
        std::fs::write(&sidecar, "stale signature\n").unwrap();

        let result = sign_image(&image, &key_path, || bail!("prompt aborted"));

        assert!(result.is_err());
        assert!(
            !sidecar.exists(),
            "a signature from an earlier signing must not survive a failed run"
        );
    }

    #[test]
    fn sign_image_missing_image_errors_without_prompting() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("maintainer-key");
        generate_and_write_sealed_key(&key_path, PASS).unwrap();

        let err = sign_image(&dir.path().join("no-such-image.img.xz"), &key_path, || {
            panic!("the passphrase must not be requested for a missing image")
        })
        .unwrap_err();

        assert!(matches!(
            err.downcast_ref::<MissingSigningInput>(),
            Some(MissingSigningInput::Image(_))
        ));
    }

    #[test]
    fn sign_image_missing_key_errors_without_prompting() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("image.img.xz");
        std::fs::write(&image, b"image bytes").unwrap();

        let err = sign_image(&image, &dir.path().join("no-such-key"), || {
            panic!("the passphrase must not be requested for a missing key")
        })
        .unwrap_err();

        assert!(matches!(
            err.downcast_ref::<MissingSigningInput>(),
            Some(MissingSigningInput::Key(_))
        ));
    }

    #[test]
    fn sign_digest_rejects_wrong_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("maintainer-key");
        generate_and_write_sealed_key(&key_path, PASS).unwrap();

        let digest = hex::encode([0xcd_u8; 32]);
        assert!(sign_digest(&key_path, b"wrong", &digest).is_err());
    }

    #[test]
    fn pubkey_literal_encodes_the_key() {
        let pubkey = public_key(&SEED);
        let literal = format_pubkey_literal(&pubkey);
        assert!(literal.contains(&hex::encode(pubkey)));

        // The byte literals in the pasted array decode back to the public key.
        let start = literal.find("Some([").unwrap() + "Some([".len();
        let end = literal[start..].find("])").unwrap() + start;
        let bytes: Vec<u8> = literal[start..end]
            .split(',')
            .filter_map(|tok| tok.trim().strip_prefix("0x"))
            .map(|hex| u8::from_str_radix(hex, 16).unwrap())
            .collect();
        assert_eq!(bytes, pubkey);
    }
}
