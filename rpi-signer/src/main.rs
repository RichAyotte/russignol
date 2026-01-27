mod chain_info;
mod constants;
mod events;
mod fonts;
mod network_status;
mod pages;
mod setup;
mod signer_server;
mod storage;
mod tezos_encrypt;
mod tezos_signer;
mod util;
mod watermark_setup;
mod widgets;

use russignol_signer_lib::{
    ChainId,
    bls::PublicKeyHash,
    signing_activity,
    wallet::{KeyManager, OcamlKeyEntry, StoredKey},
};

use embedded_graphics::geometry::Dimensions;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::{DrawTarget, Point};
use epd_2in13_v4::display::Display;
use epd_2in13_v4::{Device, DeviceConfig};
use events::AppEvent;
use pages::{
    GreetingPage, Page, PinMode, confirmation::ConfirmationPage, dialog::DialogPage, pin::PinPage,
    screensaver::ScreensaverPage, signatures::SignaturesPage, status::StatusPage,
};
use russignol_ui::pages::{ErrorPage, ProgressPage};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use constants::KEYS_DIR;

/// Maximum failed PIN attempts before lockout
const MAX_FAILED_ATTEMPTS: u32 = 5;
/// Lockout duration after max failed attempts (5 minutes)
const LOCKOUT_DURATION: Duration = Duration::from_secs(300);

/// Show a fatal error on the display and exit (never returns)
fn fatal_error(device: &mut Device, title: &str, message: &str) -> ! {
    log::error!("FATAL: {title} - {message}");
    let mut error_page = ErrorPage::new(title, message);
    let _ = error_page.show(&mut device.display);
    let _ = device.display.update();
    std::process::exit(1)
}

fn main() -> epd_2in13_v4::EpdResult<()> {
    env_logger::init();

    // Shared signing activity tracker
    let signing_activity = Arc::new(Mutex::new(signing_activity::SigningActivity::default()));

    // Create app event channel
    let (app_tx, app_rx) = crossbeam_channel::unbounded();

    // Create channel to pass decrypted secret keys to signer (in memory, never written to disk)
    let (start_signer_tx, start_signer_rx) = crossbeam_channel::bounded::<String>(1);

    // Watermark will be created after PIN entry and encryption unlock
    let watermark: Arc<
        std::sync::RwLock<Option<Arc<std::sync::RwLock<russignol_signer_lib::HighWatermark>>>>,
    > = Arc::new(std::sync::RwLock::new(None));

    // Create watermark error callback
    let tx_for_callback = app_tx.clone();
    let watermark_error_callback: signer_server::WatermarkErrorCallback =
        Arc::new(move |pkh, chain_id, error| {
            use russignol_signer_lib::WatermarkError;

            // Extract structured error info for LevelTooLow variant
            let (current_level, requested_level) = match error {
                WatermarkError::LevelTooLow { current, requested } => {
                    (Some(*current), Some(*requested))
                }
                _ => (None, None),
            };

            let _ = tx_for_callback.send(AppEvent::WatermarkError {
                pkh: pkh.to_b58check(),
                chain_id,
                error_message: error.to_string(),
                current_level,
                requested_level,
            });
        });

    // Create signing notify callback - triggers display refresh when a signature is completed
    let tx_for_signing = app_tx.clone();
    let signing_notify_callback: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        let _ = tx_for_signing.send(AppEvent::DirtyDisplay);
    });

    // Create large level gap callback - triggers when watermark gap exceeds 4 cycles
    let tx_for_large_gap = app_tx.clone();
    let large_gap_callback: Arc<dyn Fn(PublicKeyHash, ChainId, u32, u32) + Send + Sync> =
        Arc::new(move |pkh, chain_id, current_level, requested_level| {
            let _ = tx_for_large_gap.send(AppEvent::LargeWatermarkGap {
                pkh: pkh.to_b58check(),
                chain_id,
                current_level,
                requested_level,
            });
        });

    // Set up signal handler - send shutdown event directly to UI loop
    let tx_for_signal = app_tx.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        log::info!("Received Ctrl+C, shutting down...");
        let _ = tx_for_signal.send(AppEvent::Shutdown);
    }) {
        log::error!("Failed to set Ctrl-C handler: {e}");
        // Continue anyway - Ctrl-C won't work but the app can still function
    }

    // Spawn task that waits for keys to be ready before starting signer
    let signing_activity_clone = signing_activity.clone();
    let watermark_for_signer = watermark.clone();
    let watermark_callback_for_signer = Some(watermark_error_callback);
    let signing_callback_for_signer = Some(signing_notify_callback);
    let large_gap_callback_for_signer = Some(large_gap_callback);
    let tx_for_signer = app_tx.clone();

    let signer_handle = std::thread::spawn(move || {
        // Wait for decrypted secret keys (passed in memory, never written to disk)
        if let Ok(secret_keys_json) = start_signer_rx.recv() {
            log::info!("Secret keys received, starting signer server...");
            let config = signer_server::SignerConfig::default();

            // Read the watermark that was created after PIN entry
            let watermark = match watermark_for_signer.read() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => {
                    log::error!("Watermark lock poisoned in signer thread, recovering");
                    let _ = tx_for_signer.send(AppEvent::FatalError {
                        title: "LOCK POISONED".to_string(),
                        message: "Watermark lock poisoned in signer".to_string(),
                    });
                    poisoned.into_inner().clone()
                }
            };

            // Read blocks_per_cycle from chain_info for level gap detection
            let blocks_per_cycle = chain_info::read_chain_info()
                .ok()
                .and_then(|info| info.blocks_per_cycle);
            if let Some(bpc) = blocks_per_cycle {
                log::info!("Level gap detection enabled: threshold = 4 × {bpc} blocks");
            }

            let callbacks = signer_server::SignerCallbacks {
                watermark_error: watermark_callback_for_signer,
                signing: signing_callback_for_signer,
                large_gap: large_gap_callback_for_signer,
            };

            if let Err(e) = signer_server::start_integrated_signer(
                &config,
                &secret_keys_json,
                &signing_activity_clone,
                watermark.as_ref(),
                &callbacks,
                blocks_per_cycle,
            ) {
                log::error!("Signer server error: {e}");
            }
        }
    });

    // Run the UI loop in the main thread
    let result = run_ui_loop(
        &signing_activity,
        &start_signer_tx,
        &app_tx,
        &app_rx,
        &watermark,
    );

    // Signer thread will naturally terminate when the server returns
    // No abort needed - threads clean up on drop
    drop(signer_handle);
    log::info!("Shutdown complete");

    result
}

#[expect(
    clippy::too_many_lines,
    reason = "UI event loop with multiple page handlers"
)]
fn run_ui_loop(
    signing_activity: &Arc<Mutex<signing_activity::SigningActivity>>,
    start_signer_tx: &crossbeam_channel::Sender<String>,
    tx: &crossbeam_channel::Sender<AppEvent>,
    rx: &crossbeam_channel::Receiver<AppEvent>,
    watermark: &Arc<
        std::sync::RwLock<Option<Arc<std::sync::RwLock<russignol_signer_lib::HighWatermark>>>>,
    >,
) -> epd_2in13_v4::EpdResult<()> {
    const SCREENSAVER_TIMEOUT: Duration = Duration::from_secs(180);

    let (mut device, touch_events) = Device::new(DeviceConfig {
        ..Default::default()
    })?;

    let tx_touch = tx.clone();

    std::thread::spawn(move || {
        for touch in touch_events {
            if tx_touch
                .send(AppEvent::Touch(Point::new(touch.x, touch.y)))
                .is_err()
            {
                break;
            }
        }
    });

    // Detect first boot vs normal operation
    let is_first_boot = setup::is_first_boot();

    // CRITICAL: Check for error conditions BEFORE showing any UI
    // If keys exist but marker is missing, show error immediately
    if is_first_boot && let Err(e) = setup::verify_partitions_early() {
        fatal_error(&mut device, "SETUP ERROR", &e);
    }

    // First boot: show greeting page to start setup flow
    // Normal boot: show PIN page to decrypt existing keys
    let mut current_page: Box<dyn Page<Display>> = if is_first_boot {
        log::info!("First boot detected - starting setup flow");
        Box::new(GreetingPage::new(tx.clone()))
    } else {
        log::info!("Normal boot - showing PIN verification");
        Box::new(PinPage::new(tx.clone(), "Enter\n PIN", PinMode::Verify))
    };
    current_page.show(&mut device.display)?;
    device.display.update()?;

    // Setup state (only used during first boot)
    let mut first_pin: Option<Vec<u8>> = None;

    // Screensaver state
    let mut screensaver_active = false;
    let mut saved_page: Option<Box<dyn Page<Display>>> = None;

    // PIN rate limiting state
    let mut failed_pin_attempts: u32 = 0;
    let mut lockout_until: Option<Instant> = None;

    // Animation state - true when current page is ProgressPage and needs periodic redraws
    let mut needs_animation = false;
    let mut animation_interval = Duration::from_secs(1); // Default, updated per ProgressPage

    // Inactivity tracking for screensaver (None until after PIN verification)
    let mut last_activity: Option<Instant> = None;

    loop {
        // Use recv_timeout to drive animation when ProgressPage is active
        let event = match rx.recv_timeout(animation_interval) {
            Ok(event) => event,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // Check for inactivity timeout (screensaver)
                if let Some(activity_time) = last_activity
                    && !screensaver_active
                    && !current_page.is_modal()
                    && activity_time.elapsed() >= SCREENSAVER_TIMEOUT
                {
                    log::debug!("Inactivity timer expired, activating screensaver");
                    let _ = tx.send(AppEvent::ActivateScreensaver);
                }
                // Animation tick - only redraw if animation is needed
                if needs_animation && !screensaver_active {
                    current_page.show(&mut device.display)?;
                    device.display.update()?;
                }
                continue;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                log::info!("Event channel disconnected, exiting event loop");
                break;
            }
        };

        match event {
            AppEvent::Touch(touch_point) => {
                if screensaver_active {
                    log::debug!("Touch detected while screensaver active, waking up");
                    // Wake from screensaver on any touch
                    let _ = tx.send(AppEvent::DeactivateScreensaver);
                } else {
                    // Normal touch handling
                    current_page.handle_touch(touch_point);
                    // Reset inactivity timer
                    log::debug!("Touch detected, resetting inactivity timer");
                    last_activity = Some(Instant::now());
                }
            }

            // === First-boot setup events ===
            AppEvent::StartSetup => {
                log::info!("User tapped Begin, starting setup...");

                // Check if storage partitions need to be created
                if setup::needs_storage_setup() {
                    log::info!("Storage setup needed - creating partitions...");

                    // Show progress page for storage setup
                    let mut progress = ProgressPage::new("Preparing storage...");
                    progress.show(&mut device.display)?;
                    device.display.update()?;

                    // Run storage setup in background thread with progress updates
                    let tx_clone = tx.clone();
                    std::thread::spawn(move || {
                        let result = storage::setup_storage(|msg, pct| {
                            tx_clone
                                .send(AppEvent::StorageProgress {
                                    message: msg.to_string(),
                                    percent: pct,
                                })
                                .map_err(|e| e.to_string())
                        });
                        match result {
                            Ok(()) => {
                                let _ = tx_clone.send(AppEvent::StorageSetupComplete);
                            }
                            Err(e) => {
                                let _ = tx_clone.send(AppEvent::StorageSetupFailed(e));
                            }
                        }
                    });

                    // Keep current page as progress page, wait for completion event
                    current_page = Box::new(progress);
                    needs_animation = false;
                } else {
                    // Partitions already exist, proceed directly to verification
                    let _ = tx.send(AppEvent::StorageSetupComplete);
                }
            }
            AppEvent::StorageProgress { message, percent } => {
                // Update progress page with current status
                let mut progress = ProgressPage::new(&message);
                progress.set_progress(&message, percent);
                progress.show(&mut device.display)?;
                device.display.update()?;
                current_page = Box::new(progress);
            }
            AppEvent::StorageSetupComplete => {
                log::info!("Storage setup complete, verifying partitions...");

                // Verify partitions and create directories
                if let Err(e) = setup::verify_partitions() {
                    fatal_error(&mut device, "SETUP FAILED", &e);
                }

                if let Err(e) = setup::create_directories() {
                    fatal_error(&mut device, "SETUP FAILED", &e);
                }

                // Note: Still running as root here. Privileges will be dropped
                // after key generation, once /keys is remounted read-only.

                // Show PIN creation page
                current_page =
                    Box::new(PinPage::new(tx.clone(), "Create\nnew PIN", PinMode::Create));
                needs_animation = false;
                current_page.show(&mut device.display)?;
                device.display.update()?;
            }
            AppEvent::StorageSetupFailed(e) => {
                fatal_error(&mut device, "STORAGE FAILED", &e);
            }
            AppEvent::FirstPinEntered(pin) => {
                log::info!("First PIN entered, asking for confirmation");
                first_pin = Some(pin);

                // Show confirmation PIN page
                current_page = Box::new(PinPage::new(tx.clone(), "Confirm\nPIN", PinMode::Confirm));
                needs_animation = false;
                current_page.show(&mut device.display)?;
                device.display.update()?;
            }
            AppEvent::PinMismatch => {
                log::warn!("PINs don't match, restarting PIN entry");
                first_pin = None;

                // Show error dialog briefly, then restart
                let mut error_page =
                    ErrorPage::new("PIN MISMATCH", "PINs don't match. Please try again.");
                let _ = error_page.show(&mut device.display);
                let _ = device.display.update();
                std::thread::sleep(Duration::from_secs(2));

                // Restart with create PIN page
                current_page =
                    Box::new(PinPage::new(tx.clone(), "Create\nnew PIN", PinMode::Create));
                needs_animation = false;
                current_page.show(&mut device.display)?;
                device.display.update()?;
            }
            AppEvent::KeyGenSuccess(secret_keys_json) => {
                log::info!("Keys generated and encrypted successfully");

                // Process watermark configuration from boot partition
                // (creates chain_info.json on /keys)
                match watermark_setup::process_watermark_config() {
                    watermark_setup::WatermarkResult::Configured { chain_name, level } => {
                        log::info!("Watermarks configured: {chain_name} at level {level}");
                    }
                    watermark_setup::WatermarkResult::NotFound => {
                        log::info!(
                            "No watermark config found - signer will reject signing until watermarks are set"
                        );
                    }
                    watermark_setup::WatermarkResult::Error(e) => {
                        log::error!("Watermark config error: {e}");
                        fatal_error(&mut device, "WATERMARK ERROR", &e);
                    }
                }

                // Write setup marker
                if let Err(e) = setup::write_setup_marker() {
                    log::error!("Failed to write setup marker: {e}");
                }

                // Set proper permissions on ALL key files (after chain_info.json is written)
                if let Err(e) = tezos_encrypt::set_key_permissions() {
                    log::error!("Failed to set key permissions: {e}");
                }

                // Sync filesystem before remounting
                setup::sync_disk();

                // Remount keys partition as read-only (requires root)
                if let Err(e) = storage::remount_keys_readonly() {
                    fatal_error(&mut device, "SECURITY ERROR", &e);
                }

                // Drop root privileges now that setup is complete
                // Keys partition is read-only, all future operations run as russignol
                if let Err(e) = storage::drop_privileges() {
                    fatal_error(&mut device, "SECURITY ERROR", &e);
                }

                log::info!("Setup complete! Transitioning to signing mode...");

                // Transition directly to signing mode with keys already decrypted
                // No need for user to re-enter PIN!
                let _ = tx.send(AppEvent::KeysDecrypted(secret_keys_json));
            }
            AppEvent::KeyGenFailed(e) => {
                log::error!("Key generation failed: {e}");
                fatal_error(&mut device, "KEY GEN FAILED", &e);
            }

            // === Normal operation events ===
            AppEvent::EnterPin => {
                // Re-show PIN verification page
                current_page = Box::new(PinPage::new(tx.clone(), "Enter\nPIN", PinMode::Verify));
                needs_animation = false;
                current_page.show(&mut device.display)?;
                device.display.update()?;
            }
            AppEvent::InvalidPinEntered => {
                log::info!(">>> InvalidPinEntered event received, showing dialog");

                // Increment failed attempts
                failed_pin_attempts += 1;
                log::warn!("Failed PIN attempt {failed_pin_attempts} of {MAX_FAILED_ATTEMPTS}");

                // Check if we should lock the device
                if failed_pin_attempts >= MAX_FAILED_ATTEMPTS {
                    lockout_until = Some(Instant::now() + LOCKOUT_DURATION);
                    log::error!(
                        "Maximum PIN attempts exceeded, device locked for {} seconds",
                        LOCKOUT_DURATION.as_secs()
                    );
                    let _ = tx.send(AppEvent::DeviceLocked);
                    continue;
                }

                let message: &'static str = {
                    let remaining = MAX_FAILED_ATTEMPTS - failed_pin_attempts;
                    match remaining {
                        1 => "Invalid PIN\n1 attempt left",
                        2 => "Invalid PIN\n2 attempts left",
                        _ => "Invalid PIN",
                    }
                };
                current_page = Box::new(DialogPage::new(tx.clone(), message, AppEvent::EnterPin));
                needs_animation = false;
                current_page.show(&mut device.display)?;
                device.display.update()?;
                log::info!(">>> InvalidPinEntered dialog displayed: {message}");
            }
            AppEvent::DeviceLocked => {
                log::error!("Device locked due to too many failed PIN attempts");

                // Draw locked message directly (no button, no way out)
                device.display.clear(BinaryColor::On)?;
                let font = u8g2_fonts::FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
                let display_center = device.display.bounding_box().center();
                let _ = font.render_aligned(
                    "LOCKED\nPower cycle to retry",
                    display_center,
                    u8g2_fonts::types::VerticalPosition::Center,
                    u8g2_fonts::types::HorizontalAlignment::Center,
                    u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
                    &mut device.display,
                ); // Ignore font error in locked state
                device.display.update()?;

                // E-ink display retains image after process exits
                log::error!("Entering locked state - power cycle required");
                std::process::exit(1);
            }
            AppEvent::PinEntered(pin) => {
                // Check if we're in setup mode (PIN confirmation) or normal mode (PIN verification)
                if let Some(ref stored_first_pin) = first_pin {
                    // === SETUP MODE: Confirm PIN and generate keys ===
                    if stored_first_pin == &pin {
                        log::info!("PINs match, generating keys...");
                        first_pin = None; // Clear stored PIN

                        // Show progress page
                        let progress =
                            ProgressPage::new_timed("Generating keys...", Duration::from_secs(8))
                                .with_modal(true);
                        animation_interval = progress.animation_interval();
                        current_page = Box::new(progress);
                        needs_animation = true;
                        current_page.show(&mut device.display)?;
                        device.display.update()?;

                        // Spawn key generation in background thread
                        let tx_clone = tx.clone();
                        std::thread::spawn(move || match generate_and_encrypt_keys(&pin) {
                            Ok(secret_keys_json) => {
                                let _ = tx_clone.send(AppEvent::KeyGenSuccess(secret_keys_json));
                            }
                            Err(e) => {
                                let _ = tx_clone.send(AppEvent::KeyGenFailed(e));
                            }
                        });
                    } else {
                        // PINs don't match
                        let _ = tx.send(AppEvent::PinMismatch);
                    }
                } else {
                    // === NORMAL MODE: Verify PIN and decrypt keys ===
                    // Check if device is locked out
                    if let Some(lockout_time) = lockout_until {
                        if Instant::now() < lockout_time {
                            log::warn!("Device still locked, ignoring PIN entry");
                            let _ = tx.send(AppEvent::DeviceLocked);
                            continue;
                        }
                        // Lockout expired, reset state
                        log::info!("Lockout expired, allowing PIN entry");
                        lockout_until = None;
                        failed_pin_attempts = 0;
                    }

                    // Verify PIN by decrypting secret keys in background thread
                    let progress =
                        ProgressPage::new_timed("Verifying PIN...", Duration::from_secs(8))
                            .with_modal(true);
                    animation_interval = progress.animation_interval();
                    current_page = Box::new(progress);
                    needs_animation = true;
                    current_page.show(&mut device.display)?;
                    device.display.update()?;

                    let tx_clone = tx.clone();
                    std::thread::spawn(move || {
                        let decrypt_start = std::time::Instant::now();
                        // Try to decrypt secret_keys.enc - if it succeeds, PIN is correct
                        match tezos_encrypt::decrypt_secret_keys(&pin) {
                            Ok(secret_keys_json) => {
                                log::info!("Decrypting time: {:?}", decrypt_start.elapsed());
                                // PIN verified - send the decrypted secret keys JSON
                                let _ = tx_clone.send(AppEvent::PinVerified(secret_keys_json));
                            }
                            Err(e) => {
                                log::error!("PIN verification failed: {e}");
                                log::info!("Decrypting time: {:?}", decrypt_start.elapsed());
                                let _ = tx_clone.send(AppEvent::PinVerificationFailed);
                            }
                        }
                    });
                }
            }
            AppEvent::PinVerified(secret_keys_json) => {
                // PIN verified successfully, reset failed attempts
                failed_pin_attempts = 0;
                log::info!(">>> PIN verified successfully, secret keys decrypted");
                log::debug!(
                    ">>> Secret keys JSON length: {} bytes",
                    secret_keys_json.len()
                );

                // Create watermark (on /data partition)
                log::info!("Creating high watermark tracker...");
                let config = signer_server::SignerConfig::default();
                let hwm = signer_server::create_high_watermark(&config).map_err(|e| {
                    std::io::Error::other(format!("Failed to create watermark: {e}"))
                })?;

                // Store watermark for signer and reset task
                {
                    let Ok(mut wm_lock) = watermark.write() else {
                        fatal_error(
                            &mut device,
                            "LOCK POISONED",
                            "Watermark lock poisoned during PIN entry",
                        );
                    };
                    *wm_lock = hwm;
                }

                // Pass secret keys in memory to signer (never written to disk)
                log::info!(">>> PIN verified, proceeding to home");
                let _ = tx.send(AppEvent::KeysDecrypted(secret_keys_json));
            }
            AppEvent::PinVerificationFailed => {
                // Delegate to InvalidPinEntered which handles attempt counting and lockout
                log::info!(">>> PinVerificationFailed, delegating to InvalidPinEntered");
                let _ = tx.send(AppEvent::InvalidPinEntered);
            }
            AppEvent::KeysDecrypted(secret_keys_json) => {
                log::info!(">>> KeysDecrypted event received, showing status page");
                log::debug!(">>> Secret keys JSON: {} bytes", secret_keys_json.len());

                // Send secret keys to signer (in memory, never written to disk)
                let _ = start_signer_tx.send(secret_keys_json);

                // Show status page first - user can tap to see signatures
                current_page = Box::new(StatusPage::new(tx.clone(), signing_activity.clone()));
                needs_animation = false;
                current_page.show(&mut device.display)?;
                device.display.update()?;
                // Start inactivity timer for screensaver
                log::debug!("Starting inactivity timer after KeysDecrypted");
                last_activity = Some(Instant::now());
            }
            AppEvent::DirtyDisplay => {
                // Skip redraws when screensaver is active
                if !screensaver_active {
                    current_page.show(&mut device.display)?;
                    device.display.update()?;
                }
            }
            AppEvent::ActivateScreensaver => {
                log::debug!(
                    "ActivateScreensaver event received (screensaver_active={screensaver_active})"
                );
                // Don't activate screensaver when a modal dialog is showing
                if current_page.is_modal() {
                    log::debug!("Screensaver activation skipped - modal dialog showing");
                    continue;
                }
                if screensaver_active {
                    log::debug!("Screensaver activation skipped (already active)");
                } else {
                    log::info!("Activating screensaver");
                    // Save current page
                    saved_page = Some(current_page);
                    // Show screensaver
                    current_page = Box::new(ScreensaverPage::new());
                    current_page.show(&mut device.display)?;
                    device.display.update()?;
                    // Put display to sleep (touch stays active)
                    device.display_sleep()?;
                    screensaver_active = true;
                    log::info!("Screensaver activated successfully");
                }
            }
            AppEvent::DeactivateScreensaver => {
                log::debug!(
                    "DeactivateScreensaver event received (screensaver_active={screensaver_active})"
                );
                if screensaver_active {
                    log::info!("Deactivating screensaver");
                    // Wake display
                    device.display_wake()?;
                    // Restore previous page
                    if let Some(page) = saved_page.take() {
                        current_page = page;
                    }
                    current_page.show(&mut device.display)?;
                    device.display.update()?;
                    screensaver_active = false;
                    log::info!("Screensaver deactivated successfully");
                    // Restart inactivity timer
                    log::debug!("Restarting inactivity timer after screensaver deactivation");
                    last_activity = Some(Instant::now());
                } else {
                    log::debug!("Screensaver deactivation skipped (not active)");
                }
            }
            AppEvent::Shutdown => {
                log::info!("Shutting down UI...");

                // Flush watermarks to disk before shutdown to prevent data loss
                if let Ok(guard) = watermark.read()
                    && let Some(ref wm) = *guard
                    && let Ok(wm_guard) = wm.read()
                {
                    if let Err(e) = wm_guard.flush_all() {
                        log::error!("Failed to flush watermarks on shutdown: {e}");
                    } else {
                        log::info!("Watermarks flushed to disk");
                    }
                }

                // If screensaver is active, wake display first
                if screensaver_active {
                    log::debug!("Waking display from screensaver before shutdown");
                    device.display_wake()?;
                }
                // Clear the display (white screen)
                device.display.clear(BinaryColor::On)?;
                device.display.update()?;
                // Put device to sleep
                device.sleep()?;
                break;
            }
            AppEvent::WatermarkError {
                pkh,
                chain_id,
                error_message,
                current_level,
                requested_level,
            } => {
                // Don't replace modal pages (dialogs) - they require user interaction first
                if current_page.is_modal() {
                    log::debug!("Ignoring WatermarkError - modal dialog already showing");
                    continue;
                }

                // Check if it's a "level too low" error (has current_level and requested_level)
                if let (Some(current), Some(requested)) = (current_level, requested_level) {
                    log::warn!("Watermark error detected: {error_message}");

                    let chain_id_str = chain_id.to_b58check();
                    // Truncate chain ID to fit on screen (show first 12 chars)
                    let chain_short = if chain_id_str.len() > 12 {
                        format!("{}...", &chain_id_str[..12])
                    } else {
                        chain_id_str.clone()
                    };

                    let message = format!(
                        "Watermark test failed.\nChain: {chain_short}\nCurrent level: {current}"
                    );

                    let button_text = format!("Set level to {requested}");

                    log::info!("Creating watermark update dialog: {message}");

                    // Show confirmation dialog with warning icon
                    current_page = Box::new(ConfirmationPage::new(
                        tx.clone(),
                        &message,
                        AppEvent::UpdateWatermarkToLevel {
                            pkh: pkh.clone(),
                            chain_id,
                            new_level: requested,
                        },
                        AppEvent::DialogDismissed,
                        true, // Show warning icon
                        &button_text,
                    ));
                    needs_animation = false;
                    current_page.show(&mut device.display)?;
                    device.display.update()?;
                } else {
                    // For non-destructive errors (e.g., "Round too low"), just log and continue.
                    // The signer already returned an error to the client - no UI interruption needed.
                    log::info!("Non-destructive watermark error (no dialog): {error_message}");
                }
            }
            AppEvent::WatermarkUpdateSuccess => {
                log::info!("Watermark update complete, returning to signatures page");
                current_page = Box::new(SignaturesPage::new(tx.clone(), signing_activity.clone()));
                needs_animation = false;
                current_page.show(&mut device.display)?;
                device.display.update()?;
            }
            AppEvent::LargeWatermarkGap {
                pkh,
                chain_id,
                current_level,
                requested_level,
            } => {
                // Don't replace modal pages (dialogs) - they require user interaction first
                if current_page.is_modal() {
                    log::debug!("Ignoring LargeWatermarkGap - modal dialog already showing");
                    continue;
                }

                let gap = requested_level.saturating_sub(current_level);
                log::warn!(
                    "Large level gap detected: {gap} blocks (current: {current_level}, requested: {requested_level})"
                );

                let title = "Stale watermark.";
                let pairs = vec![
                    ("Current:".to_string(), current_level.to_string()),
                    ("Requested:".to_string(), requested_level.to_string()),
                    ("Gap:".to_string(), format!("{gap} blocks")),
                ];
                let confirm_button_text = format!("Update to {requested_level}");

                // Show confirmation dialog with warning icon and aligned key-value pairs
                current_page = Box::new(ConfirmationPage::new_with_pairs(
                    tx.clone(),
                    title,
                    pairs,
                    AppEvent::UpdateWatermarkToLevel {
                        pkh: pkh.clone(),
                        chain_id,
                        new_level: requested_level,
                    },
                    AppEvent::DialogDismissed,
                    true, // Show warning icon
                    &confirm_button_text,
                ));
                needs_animation = false;
                current_page.show(&mut device.display)?;
                device.display.update()?;
            }
            AppEvent::UpdateWatermarkToLevel {
                pkh,
                chain_id,
                new_level,
            } => {
                // Update watermark to the new level
                log::info!(
                    "Updating watermark for {pkh} on chain {chain_id:?} to level {new_level}"
                );
                let wm_opt = match watermark.read() {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        log::warn!("Watermark lock poisoned in update handler, recovering");
                        poisoned.into_inner()
                    }
                };
                if let Some(wm_lock) = wm_opt.as_ref() {
                    if let Ok(pkh_parsed) = PublicKeyHash::from_b58check(&pkh) {
                        let wm = match wm_lock.write() {
                            Ok(guard) => guard,
                            Err(poisoned) => {
                                log::warn!(
                                    "Watermark inner lock poisoned in update handler, recovering"
                                );
                                poisoned.into_inner()
                            }
                        };
                        if let Err(e) = wm.update_to_level(chain_id, &pkh_parsed, new_level) {
                            log::error!("Failed to update watermark: {e}");
                            current_page = Box::new(DialogPage::new(
                                tx.clone(),
                                &format!("Update failed:\n{e}"),
                                AppEvent::DialogDismissed,
                            ));
                            current_page.show(&mut device.display)?;
                            device.display.update()?;
                        } else {
                            log::info!("Watermark updated to level {new_level} for {pkh}");
                            let _ = tx.send(AppEvent::WatermarkUpdateSuccess);
                        }
                    } else {
                        log::error!("Invalid PKH for watermark update: {pkh}");
                        current_page = Box::new(DialogPage::new(
                            tx.clone(),
                            "Update failed:\nInvalid key hash",
                            AppEvent::DialogDismissed,
                        ));
                        current_page.show(&mut device.display)?;
                        device.display.update()?;
                    }
                } else {
                    log::warn!("Watermark not initialized yet");
                    current_page = Box::new(DialogPage::new(
                        tx.clone(),
                        "Update failed:\nWatermark not ready",
                        AppEvent::DialogDismissed,
                    ));
                    current_page.show(&mut device.display)?;
                    device.display.update()?;
                }
            }
            AppEvent::DialogDismissed => {
                log::info!("Dialog dismissed, returning to signatures page");
                current_page = Box::new(SignaturesPage::new(tx.clone(), signing_activity.clone()));
                needs_animation = false;
                current_page.show(&mut device.display)?;
                device.display.update()?;
            }
            AppEvent::ShowStatus => {
                log::info!("Showing status page");
                current_page = Box::new(StatusPage::new(tx.clone(), signing_activity.clone()));
                needs_animation = false;
                current_page.show(&mut device.display)?;
                device.display.update()?;
            }
            AppEvent::ShowSignatures => {
                log::info!("Showing signatures page");
                current_page = Box::new(SignaturesPage::new(tx.clone(), signing_activity.clone()));
                needs_animation = false;
                current_page.show(&mut device.display)?;
                device.display.update()?;
            }
            AppEvent::FatalError { title, message } => {
                fatal_error(&mut device, &title, &message);
            }
        }
    }

    Ok(())
}

/// Generate keys and encrypt them with the PIN
///
/// **SECURITY**: Keys are generated in memory and ONLY the encrypted form
/// is written to disk. Plaintext secret keys NEVER touch the filesystem.
///
/// Returns the secret keys JSON (for immediate use in signing mode).
fn generate_and_encrypt_keys(pin: &[u8]) -> Result<String, String> {
    let key_manager = KeyManager::new(Some(PathBuf::from(KEYS_DIR)));

    // Generate keys IN MEMORY ONLY - no disk writes yet
    log::info!("Generating consensus key (in memory)...");
    let consensus_key = key_manager
        .gen_keys_in_memory("consensus", false)
        .map_err(|e| format!("Failed to generate consensus key: {e}"))?;
    log::info!("Consensus key generated");

    log::info!("Generating companion key (in memory)...");
    let companion_key = key_manager
        .gen_keys_in_memory("companion", false)
        .map_err(|e| format!("Failed to generate companion key: {e}"))?;
    log::info!("Companion key generated");

    let keys = [&consensus_key, &companion_key];

    // Build secret_keys JSON in memory (OCaml-compatible format)
    let secret_keys_json = build_secret_keys_json(&keys)?;

    // Encrypt secret keys and write ONLY the encrypted form to disk
    log::info!("Encrypting secret keys...");
    tezos_encrypt::encrypt_secret_keys(pin, &secret_keys_json)
        .map_err(|e| format!("Failed to encrypt keys: {e}"))?;
    log::info!("Encrypted secret keys written to disk");

    // Save ONLY public keys to disk (secret keys stay encrypted)
    log::info!("Saving public keys...");
    key_manager
        .save_public_keys_only(&[consensus_key, companion_key])
        .map_err(|e| format!("Failed to save public keys: {e}"))?;
    log::info!("Public keys saved");

    Ok(secret_keys_json)
}

/// Build OCaml-compatible `secret_keys` JSON from in-memory keys
fn build_secret_keys_json(keys: &[&StoredKey]) -> Result<String, String> {
    let entries: Vec<OcamlKeyEntry<String>> = keys
        .iter()
        .filter_map(|key| {
            key.secret_key.as_ref().map(|sk| OcamlKeyEntry {
                name: key.alias.clone(),
                value: format!("unencrypted:{sk}"),
            })
        })
        .collect();

    serde_json::to_string_pretty(&entries)
        .map_err(|e| format!("Failed to serialize secret_keys: {e}"))
}
