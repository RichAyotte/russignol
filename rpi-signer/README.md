# Russignol RPi Signer

This directory contains the core signer application and the build configuration for the Raspberry Pi Zero 2 W firmware.

## Overview

The signer application (`src/`) is a Rust binary that runs on the device. It handles:
- Drawing the UI on the e-ink display (via `epd-2in13-v4` crate).
- Managing cryptographic keys (generation, storage, signing).
- Listening for signing requests over TCP (port 7732).
- Preventing double-baking via high-watermark enforcement.

The firmware is built using **Buildroot**, which creates a minimal Linux system image customized for the Pi Zero 2 W.

## Build Modes

### 1. Hardened Production Image (Default)
**Default build.** Minimal attack surface for production use.
- **SSH Server**: REMOVED.
- **Tools**: REMOVED (`htop`, `inotify-tools`, etc.).
- **BusyBox**: Stripped down (no telnet, netcat, wget, editors, user management).
- **Root Account**: Locked (password hash removed).
- **Console**: Login services removed.
- **Access**: Only via Touch UI or the specific signer TCP port (7732).

**Build Command:**
```bash
cargo xtask image
```

### 2. Development Image
**Development build.** Includes tools helpful for debugging and development.
- **SSH Server**: Enabled (login as `root` or `russignol`).
- **Tools**: `htop`, `inotify-tools`, `strace`, full BusyBox suite (telnet, netcat, etc.).
- **Root Password**: Disabled (no password required for console login).
- **Console**: HDMI/Serial console enabled.

**Build Command:**
```bash
cargo xtask image --dev
```

## Configuration Files

The buildroot configuration is managed via an external tree structure in `buildroot-external/`.

### Standard Configs
- **Defconfig**: `buildroot-external/configs/russignol_defconfig`
- **BusyBox**: `buildroot-external/package/busybox/busybox.config`
- **Users**: `buildroot-external/board/russignol/users.txt`

### Hardened Configs
- **Defconfig**: `buildroot-external/configs/russignol_hardened_defconfig`
- **BusyBox**: `buildroot-external/package/busybox/busybox_hardened.config`
- **Users**: `buildroot-external/board/russignol/users_hardened.txt` (Locked password)

## Configuration

Use `cargo xtask config` to modify buildroot, kernel, and BusyBox configurations:

```bash
cargo xtask config buildroot nconfig   # Configure buildroot
cargo xtask config kernel nconfig      # Configure kernel
cargo xtask config busybox menuconfig  # Configure BusyBox
cargo xtask config <target> update     # Save changes

# Use --dev flag for development configuration
cargo xtask config buildroot --dev nconfig
```

## Building and Flashing

```bash
cargo xtask image           # Build hardened image
cargo xtask image --dev     # Build development image
```

See the main [README.md](../README.md) for flashing instructions.
