# Threat model

Every path below is relative to the repository root, which is `/src` in the scanner's image.

## What this project does and where untrusted input enters

Russignol is a hardware signer for Tezos bakers. It runs on a Raspberry Pi Zero 2W, holds BLS (tz4) and XMSS (tz6) secret keys encrypted under a PIN typed on its touchscreen, and signs blocks and attestations for a baker over USB gadget Ethernet. `docs/SECURITY_AUDIT.md` describes the design.

- **The signing protocol** (`libs/signer/src/protocol.rs`, `server.rs`, `magic_bytes.rs`, `high_watermark.rs`): a TCP server on `169.254.1.1:7732` (`rpi-signer/src/signer_server.rs`). It authenticates no client: `handle_authorized_keys` in `libs/signer/src/server.rs` tells every client that no key is authorized, and `docs/SECURITY_AUDIT.md` §6.1 records that the USB link being the only path to the port is what stands in for authentication. So every byte it reads is untrusted.
- **Files the device reads from the card at boot**: `watermark-config.json` (`rpi-signer/src/watermark_setup.rs`), the flash manifest (`libs/flash-manifest`, `rpi-signer/src/image_info.rs`), the encrypted key store (`libs/crypto`) and the staged provisioning request (`rpi-signer/src/provision.rs`). Anyone holding the card can rewrite them.
- **The host utility** (`host-utility/`, binary `russignol`): downloads release images and verifies their signatures (`libs/release-signature`, `host-utility/src/release_signature.rs`), reads Tezos node RPC responses (`host-utility/src/blockchain.rs`), and reads and writes SD cards. Downloaded images and RPC responses are untrusted.

## Components that matter most / least

- **Most**: the signing protocol and the high watermark that stops the signer from signing twice at one level and round; XMSS signing (`libs/xmss`) and the epoch counter that hands out each one-time epoch (`claim_epoch` in `libs/signer/src/high_watermark.rs`), since signing two messages at one epoch discloses the key; key-store encryption and PIN handling (`libs/crypto`); release-signature verification before a card is flashed.
- **Less**: the e-paper display driver and UI (`libs/epd-2in13-v4`, `libs/ui`); host-utility status and diagnostics output.
- **Out of scope**: `xtask/` (maintainer build and release tooling), `website/`, `buildroot/` and `rpi-linux/` (upstream submodules that build the SD card image, not checked out in this image), and `vendors/leanVM-b` except where russignol's use of it is wrong.

## How to exercise it

- `runuser -u builder -- cargo test --workspace` runs every unit and integration test on x86-64. Run them as `builder`, as the image does: as root, the tests that make a directory read-only to force a write to fail see the write succeed.
- `target/x86_64-unknown-linux-gnu/debug/russignol-signer-lib launch socket` runs the same signing server on the host, so a client can drive the protocol over localhost. `--help` lists its options.
- `rpi-signer` (binary `russignol-signer`) builds and tests on x86-64, but its display, touch and partition code expects the device.

## How you rate severity

- **Critical**: anything that makes the signer sign two different blocks or attestations at one level and round, reuse an XMSS epoch, or reveal a secret key; remote code execution through the signing port.
- **High**: memory corruption or a panic reachable from the signing port; the host flashing an image whose release signature does not verify; getting around the PIN attempt limit on the device.
- **Medium**: a denial of service from the USB link that makes the baker miss a slot; a watermark or key-store write that can leave the card unable to sign after a power loss.
- **Low**: anything that needs root on the baker's host, or physical access to the card together with its PIN.

## Anything to leave alone

- The signing port has no authentication, by design. Do not report that alone. Do report a way to reach it from anywhere but the USB link.
- Timing, power and electromagnetic side channels in BLST.
