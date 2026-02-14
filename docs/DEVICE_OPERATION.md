# Device Operation

Day-to-day usage of the Russignol signer after installation.

## Display & Interface

The device uses a 2.13" e-ink touchscreen for all interaction. After unlocking with your PIN, it displays live signing activity.

After 3 minutes of inactivity the display enters screensaver mode. Touch the screen once to wake it.

## Shutting Down

Tap the touchscreen 5 times in rapid succession to trigger a safe shutdown. Each tap must be within 300ms of the previous one.

### Behavior by screen state

- **Screensaver** — all taps count toward the shutdown sequence; reaching 5 wakes the display and shows the confirmation dialog
- **Normal pages** — taps count toward shutdown; intermediate taps are suppressed so page buttons aren't accidentally activated
- **Modal dialogs** — taps are handled normally by the dialog buttons; the shutdown counter is disabled so button presses always work

### Confirmation dialog

After 5 rapid taps the device displays a "Shutdown the device?" confirmation with two buttons:

- **Shutdown** — proceeds with shutdown
- **Cancel** — returns to the previous screen

### What shutdown does

1. Flushes high watermark data to disk
2. Syncs filesystem buffers
3. Clears the display (blank white screen)
4. Puts the device to sleep

## Why Tap-to-Shutdown?

The Raspberry Pi Zero 2W has no physical power button. Without a shutdown mechanism, the only way to power off is pulling the USB cable — risking high watermark data loss if writes haven't been flushed to disk. Tap-to-shutdown provides a safe way to halt the device while preserving signing state.
