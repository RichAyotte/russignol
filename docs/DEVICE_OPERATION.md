# Device Operation

Day-to-day usage of the Russignol signer after installation.

## Display & Interface

The device uses a 2.13" e-ink touchscreen for all interaction. After unlocking with your PIN, it displays a main menu with six pages:

- **System** — baker status, CPU temperature, uptime, and signature count since boot
- **Activity** — recent signing activity
- **Blockchain** — chain name, chain ID, and key addresses
- **Watermarks** — per-key watermark levels, both in-memory and persisted to disk
- **About** — version information
- **Shutdown** — safe shutdown (see below)

After 1 minute of inactivity the display enters screensaver mode. Touch the screen once to wake it. The screensaver only puts the display to sleep — signing continues, and no PIN re-entry is required.

## PIN Entry & Lockout

The device requires PIN entry on every boot before it starts signing. The PIN stays unlocked until the device reboots or loses power.

After 5 failed PIN attempts the device shows a **LOCKED** screen and the signer stops. Power cycle the device to retry.

## Watermark Gap Confirmation

If a signing request arrives at a level far above the stored watermark (more than about 4 cycles — for example, after the device was offline for an extended period), the signer rejects the request and shows a **"Stale watermark"** confirmation listing the current level, the requested level, and the gap. Tap the update button to advance the watermark to the requested level; subsequent signing requests then succeed. Tap **Cancel** to leave the watermark unchanged.

## Shutting Down

From the main menu, tap **Shutdown**. The device displays a "Shutdown the device?" confirmation with two buttons:

- **Shutdown** — proceeds with shutdown
- **Cancel** — returns to the menu

### What shutdown does

1. Syncs filesystem buffers
2. Clears the display (blank white screen)
3. Puts the display to sleep and halts the signer

Once the screen is blank, it is safe to remove power.

## Why a Shutdown Button?

The Raspberry Pi Zero 2W has no physical power button. The shutdown button provides a clean halt: filesystem buffers are flushed and the e-ink display is cleared and put into deep sleep before power is removed. Signing safety does not depend on a clean shutdown — high watermark data is committed to stable storage before each signature is returned — but a clean halt flushes buffered log data and leaves the display blank rather than showing stale content while powered off.
