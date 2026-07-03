mod app;
mod chain_info;
mod constants;
mod cpu_freq;
mod events;
mod fonts;
mod led;
mod log_writer;
mod network_status;
mod pages;
mod secret;
mod setup;
mod signer_server;
mod storage;
mod tezos_encrypt;
mod tezos_signer;
mod util;
mod watermark_setup;
mod widgets;

use app::{App, Effect, LoopAction, PageSpec};
use crossbeam_channel::Sender;
use russignol_signer_lib::{
    ChainId, HighWatermark,
    bls::PublicKeyHash,
    signing_activity,
    wallet::{KeyManager, StoredKey},
};
use std::sync::RwLock;

use embedded_graphics::geometry::Dimensions;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::{DrawTarget, Point};
use epd_2in13_v4::display::Display;
use epd_2in13_v4::{Device, device};
use events::AppEvent;
use pages::{
    Page, about, blockchain, confirmation, dialog, greeting, menu, notice, pin, screensaver,
    signatures, status, watermarks,
};
use russignol_ui::pages::{error, progress};
use secret::Secret;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use constants::{KEYS_DIR, LOG_DIR, LOG_FILE};

/// Show a fatal error on the display and exit (never returns)
fn fatal_error(device: &mut Device, title: &str, message: &str) -> ! {
    log::error!("FATAL: {title} - {message}");
    let mut error_page = error::Page::new(title, message);
    let _ = error_page.show(&mut device.display);
    let _ = device.display.update();
    std::process::exit(1)
}

fn init_logging() {
    if std::path::Path::new(LOG_DIR).exists() {
        // Normal boot: route logs through a size-capped rotating writer
        if let Ok(writer) = log_writer::RotatingWriter::new(std::path::Path::new(LOG_FILE)) {
            env_logger::Builder::from_default_env()
                .target(env_logger::Target::Pipe(Box::new(writer)))
                .init();
        } else {
            // Fall back to stderr if we can't open the log file
            env_logger::init();
        }
    } else {
        // First boot: /data/logs doesn't exist yet, use stderr
        env_logger::init();
    }
}

fn main() -> epd_2in13_v4::EpdResult<()> {
    init_logging();

    // Shared signing activity tracker
    let signing_activity = Arc::new(Mutex::new(signing_activity::SigningActivity::default()));

    // Create app event channel
    let (app_tx, app_rx) = crossbeam_channel::unbounded();

    // Create channel to pass decrypted secret keys to signer (in memory, never written to disk)
    let (start_signer_tx, start_signer_rx) = crossbeam_channel::bounded::<Secret<String>>(1);

    // Watermark will be created after PIN entry and encryption unlock
    let watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>> = Arc::new(RwLock::new(None));

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

    setup_signal_handler(&app_tx);

    // Spawn task that waits for keys to be ready before starting signer
    let signing_activity_clone = signing_activity.clone();
    let watermark_for_signer = watermark.clone();
    let watermark_callback_for_signer = Some(watermark_error_callback);
    let signing_callback_for_signer = Some(signing_notify_callback);
    let large_gap_callback_for_signer = Some(large_gap_callback);
    let tx_for_signer = app_tx.clone();

    let cpu_boost = init_cpu_freq_control();
    let led = init_led_control();
    let (pre_sign_callback, post_sign_callback) =
        connection_callbacks(cpu_boost.as_ref(), led.as_ref());

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
                pre_sign: pre_sign_callback,
                post_sign: post_sign_callback,
            };

            if let Err(e) = signer_server::start_integrated_signer(
                &config,
                &secret_keys_json,
                &signing_activity_clone,
                watermark.as_ref(),
                &callbacks,
                blocks_per_cycle,
            ) {
                report_signer_failure(&tx_for_signer, e);
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
        cpu_boost.as_ref(),
    );

    // Signer thread will naturally terminate when the server returns
    // No abort needed - threads clean up on drop
    drop(signer_handle);
    log::info!("Shutdown complete");

    result
}

/// Surface a signer failure on the display: a deterministic startup failure
/// (e.g. a stored key that no longer parses) ends the signer thread for
/// good, and without a display error the operator only learns when the
/// baker stops attesting.
fn report_signer_failure(tx: &crossbeam_channel::Sender<AppEvent>, error: String) {
    log::error!("Signer server error: {error}");
    let _ = tx.send(AppEvent::FatalError {
        title: "SIGNER FAILED".to_string(),
        message: error,
    });
}

fn run_ui_loop(
    signing_activity: &Arc<Mutex<signing_activity::SigningActivity>>,
    start_signer_tx: &crossbeam_channel::Sender<Secret<String>>,
    tx: &crossbeam_channel::Sender<AppEvent>,
    rx: &crossbeam_channel::Receiver<AppEvent>,
    watermark: &Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    cpu_boost: Option<&cpu_freq::CpuBoost>,
) -> epd_2in13_v4::EpdResult<()> {
    const SCREENSAVER_TIMEOUT: Duration = Duration::from_mins(1);

    let (screensaver_reset_tx, screensaver_reset_rx) = crossbeam_channel::unbounded::<()>();
    let tx_screensaver = tx.clone();
    std::thread::spawn(move || {
        screensaver_timer(&screensaver_reset_rx, &tx_screensaver, SCREENSAVER_TIMEOUT);
    });

    let (mut device, touch_events) = Device::new(device::Config {
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

    let is_first_boot = setup::is_first_boot();

    // CRITICAL: Check for error conditions BEFORE showing any UI
    if is_first_boot && let Err(e) = setup::verify_partitions_early() {
        fatal_error(&mut device, "SETUP ERROR", &e);
    }

    let mut app = App::new(
        is_first_boot,
        tx.clone(),
        signing_activity.clone(),
        start_signer_tx.clone(),
        watermark.clone(),
    );

    let mut current_page: Box<dyn Page<Display>> = if is_first_boot {
        log::info!("First boot detected - starting setup flow");
        Box::new(greeting::Page::new(tx.clone()))
    } else {
        log::info!("Normal boot - showing PIN verification");
        Box::new(pin::Page::new(tx.clone(), "Enter\n PIN", pin::Mode::Verify))
    };
    current_page.show(&mut device.display)?;
    device.display.update()?;

    loop {
        let timeout = app.recv_timeout();

        let event = match rx.recv_timeout(timeout) {
            Ok(event) => event,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                handle_timeout(&mut app, &mut device, &mut current_page)?;
                continue;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                log::info!("Event channel disconnected, exiting event loop");
                break;
            }
        };

        // Handle Touch and DirtyDisplay directly in the runtime
        match event {
            AppEvent::Touch(touch_point) => {
                handle_touch(
                    &mut app,
                    &mut current_page,
                    touch_point,
                    &screensaver_reset_tx,
                );
                continue;
            }
            AppEvent::DirtyDisplay => {
                if !app.is_screensaver_active() {
                    current_page.show(&mut device.display)?;
                    device.display.update()?;
                }
                continue;
            }
            _ => {}
        }

        // Delegate all other events to App
        let (action, effects) = app.handle_event(event);

        if action != LoopAction::Continue {
            // A failed effect otherwise unwinds to `main` and exits with the
            // last frame still on the bistable panel — a crash that reads as a
            // hang. Render it instead (fatal_error diverges).
            if let Err(e) = apply_effects(
                &mut app,
                effects,
                &mut device,
                &mut current_page,
                cpu_boost,
                &screensaver_reset_tx,
            ) {
                fatal_error(&mut device, "SYSTEM ERROR", &e.to_string());
            }
            if action == LoopAction::Break {
                break;
            }
        }
    }

    Ok(())
}

fn handle_timeout(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
) -> epd_2in13_v4::EpdResult<()> {
    if app.needs_animation && !app.is_screensaver_active() {
        current_page.show(&mut device.display)?;
        device.display.update()?;
    }
    Ok(())
}

/// Block for `duration`, redrawing the current page each
/// `app.animation_interval` if it's animated. Without this the progress
/// bar shown before a migration reboot would freeze at 0% for the entire
/// countdown — `std::thread::sleep` blocks the event loop, so the
/// timed-progress page never gets a chance to refresh from `handle_timeout`.
fn sleep_with_animation(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
    duration: Duration,
) -> epd_2in13_v4::EpdResult<()> {
    let deadline = std::time::Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        if app.needs_animation && !app.is_screensaver_active() {
            if let Err(e) = current_page.show(&mut device.display) {
                log::warn!("display update during sleep: {e}");
            }
            if let Err(e) = device.display.update() {
                log::warn!("display update during sleep: {e}");
            }
            std::thread::sleep(app.animation_interval.min(remaining));
        } else {
            std::thread::sleep(remaining);
        }
    }
}

fn handle_touch(
    app: &mut App,
    current_page: &mut Box<dyn Page<Display>>,
    touch_point: Point,
    screensaver_reset_tx: &Sender<()>,
) {
    if app.is_screensaver_active() {
        let _ = app.tx.send(AppEvent::DeactivateScreensaver);
    } else {
        current_page.handle_touch(touch_point);
        let _ = screensaver_reset_tx.send(());
    }
}

fn screensaver_timer(
    reset_rx: &crossbeam_channel::Receiver<()>,
    event_tx: &Sender<AppEvent>,
    timeout: Duration,
) {
    loop {
        match reset_rx.recv_timeout(timeout) {
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                log::debug!("Inactivity timer expired, activating screensaver");
                let _ = event_tx.send(AppEvent::ActivateScreensaver);
                // Block until reset to avoid re-firing while screensaver is active
                if reset_rx.recv().is_err() {
                    return;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
            Ok(()) => {}
        }
    }
}

fn construct_page(
    spec: PageSpec,
    tx: &Sender<AppEvent>,
    signing_activity: &Arc<Mutex<signing_activity::SigningActivity>>,
    watermark: &Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
) -> Box<dyn Page<Display>> {
    match spec {
        PageSpec::PinCreate => Box::new(pin::Page::new(
            tx.clone(),
            "Create\nnew PIN",
            pin::Mode::Create,
        )),
        PageSpec::PinConfirm => Box::new(pin::Page::new(
            tx.clone(),
            "Confirm\nPIN",
            pin::Mode::Confirm,
        )),
        PageSpec::PinVerify => {
            Box::new(pin::Page::new(tx.clone(), "Enter\nPIN", pin::Mode::Verify))
        }
        PageSpec::Menu => Box::new(menu::Page::new(tx.clone())),
        PageSpec::Status => Box::new(status::Page::new(tx.clone(), signing_activity.clone())),
        PageSpec::Signatures => {
            Box::new(signatures::Page::new(tx.clone(), signing_activity.clone()))
        }
        PageSpec::Watermarks => Box::new(watermarks::Page::new(tx.clone(), watermark.clone())),
        PageSpec::Blockchain => Box::new(blockchain::Page::new(tx.clone())),
        PageSpec::About => Box::new(about::Page::new(tx.clone())),
        PageSpec::Dialog {
            message,
            on_dismiss,
        } => Box::new(dialog::Page::new(tx.clone(), &message, on_dismiss)),
        PageSpec::Confirmation {
            message,
            on_confirm,
            on_cancel,
            warning,
            button_text,
        } => Box::new(confirmation::Page::new(
            tx.clone(),
            &message,
            on_confirm,
            on_cancel,
            warning,
            &button_text,
        )),
        PageSpec::ConfirmationWithPairs {
            title,
            pairs,
            on_confirm,
            on_cancel,
            warning,
            button_text,
        } => Box::new(confirmation::Page::new_with_pairs(
            tx.clone(),
            &title,
            pairs,
            on_confirm,
            on_cancel,
            warning,
            &button_text,
        )),
        PageSpec::Error { title, message } => Box::new(error::Page::new(&title, &message)),
        PageSpec::Notice {
            title,
            message,
            on_dismiss,
        } => Box::new(notice::Page::new(tx.clone(), &title, &message, on_dismiss)),
        PageSpec::DeviceLocked => unreachable!("DeviceLocked handled directly in apply_effects"),
    }
}

fn apply_effects(
    app: &mut App,
    effects: Vec<Effect>,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
    cpu_boost: Option<&cpu_freq::CpuBoost>,
    screensaver_reset_tx: &Sender<()>,
) -> epd_2in13_v4::EpdResult<()> {
    for effect in effects {
        match effect {
            Effect::ShowPage(spec) => {
                apply_show_page(app, device, current_page, spec)?;
            }
            Effect::ShowProgress {
                message,
                estimated_duration,
                modal,
                percent,
            } => {
                apply_show_progress(
                    app,
                    device,
                    current_page,
                    &message,
                    estimated_duration,
                    modal,
                    percent,
                )?;
            }
            Effect::WakeDisplay => device.display_wake()?,
            Effect::SleepDisplay => device.display_sleep()?,
            Effect::SleepDevice => device.sleep()?,
            Effect::ClearDisplay => {
                device.display.clear(BinaryColor::On)?;
                device.display.update()?;
            }
            Effect::Emit(event) => {
                let _ = app.tx.send(event);
            }
            Effect::SendKeys(json) => {
                let _ = app.start_signer_tx.send(json);
            }
            Effect::InitWatermark { context } => {
                apply_init_watermark(app, device, &context)?;
            }
            Effect::SpawnKeygen { pin } => spawn_keygen(app.tx.clone(), pin, cpu_boost),
            Effect::SpawnPinVerify { pin } => spawn_pin_verify(app.tx.clone(), pin, cpu_boost),
            Effect::SpawnStorageSetup => spawn_storage_setup(app.tx.clone()),
            Effect::SyncDisk => setup::sync_disk(),
            Effect::DropPrivileges => {
                if let Err(e) = storage::drop_privileges() {
                    fatal_error(device, "SECURITY ERROR", &e);
                }
            }
            Effect::RemountKeysReadonly => {
                if let Err(e) = storage::remount_keys_readonly() {
                    fatal_error(device, "SECURITY ERROR", &e);
                }
            }
            Effect::WriteSetupMarker => {
                if let Err(e) = setup::write_setup_marker() {
                    log::error!("Failed to write setup marker: {e}");
                }
            }
            Effect::SetKeyPermissions => {
                if let Err(e) = tezos_encrypt::set_key_permissions() {
                    log::error!("Failed to set key permissions: {e}");
                }
            }
            Effect::ProcessWatermarkConfig => apply_watermark_config(device),
            Effect::VerifyStorage => apply_verify_storage(device),
            Effect::UpdateWatermark {
                pkh,
                chain_id,
                new_level,
            } => {
                apply_watermark_update(app, device, current_page, &pkh, chain_id, new_level)?;
            }
            Effect::ResetActivity => {
                let _ = screensaver_reset_tx.send(());
            }
            Effect::DropCurrentPage => {
                *current_page = Box::new(screensaver::Page::new());
                current_page.show(&mut device.display)?;
                device.display.update()?;
            }
            Effect::RebuildSavedPage => {
                if let Some(spec) = app.current_page_spec.clone() {
                    let page = construct_page(spec, &app.tx, &app.signing_activity, &app.watermark);
                    app.current_page_modal = page.is_modal();
                    app.needs_animation = false;
                    *current_page = page;
                    current_page.show(&mut device.display)?;
                    device.display.update()?;
                }
            }
            Effect::FatalError { title, message } => fatal_error(device, &title, &message),
            Effect::Exit(code) => {
                log::info!("Exiting with code {code}");
                std::process::exit(code);
            }
            Effect::Sleep(duration) => sleep_with_animation(app, device, current_page, duration)?,
        }
    }
    Ok(())
}

fn apply_show_page(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
    spec: PageSpec,
) -> epd_2in13_v4::EpdResult<()> {
    if matches!(spec, PageSpec::DeviceLocked) {
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
        );
        device.display.update()?;
    } else {
        app.current_page_spec = Some(spec.clone());
        let page = construct_page(spec, &app.tx, &app.signing_activity, &app.watermark);
        app.current_page_modal = page.is_modal();
        app.needs_animation = false;
        *current_page = page;
        current_page.show(&mut device.display)?;
        device.display.update()?;
    }
    Ok(())
}

fn apply_show_progress(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
    message: &str,
    estimated_duration: Option<Duration>,
    modal: bool,
    percent: u8,
) -> epd_2in13_v4::EpdResult<()> {
    if let Some(duration) = estimated_duration {
        let progress = progress::Page::new_timed(message, duration).with_modal(modal);
        app.animation_interval = progress.animation_interval();
        app.needs_animation = true;
        app.current_page_modal = modal;
        *current_page = Box::new(progress);
    } else {
        let mut progress = progress::Page::new(message);
        progress.set_progress(message, percent);
        app.current_page_modal = false;
        app.needs_animation = false;
        *current_page = Box::new(progress);
    }
    current_page.show(&mut device.display)?;
    device.display.update()?;
    Ok(())
}

fn apply_init_watermark(
    app: &mut App,
    device: &mut Device,
    context: &str,
) -> epd_2in13_v4::EpdResult<()> {
    log::info!("Creating high watermark tracker...");
    // Watermarks live on /data; if the init script failed to mount it,
    // creating them would hit the read-only rootfs and abort obscurely.
    if !storage::is_data_mounted() {
        fatal_error(
            device,
            "DATA UNAVAILABLE",
            "Data partition not mounted. Re-flash the SD card with the host utility.",
        );
    }
    let config = signer_server::SignerConfig::default();
    let pkhs: Vec<PublicKeyHash> = tezos_signer::get_keys()
        .iter()
        .filter_map(|k| PublicKeyHash::from_b58check(&k.value).ok())
        .collect();
    let hwm = signer_server::create_high_watermark(&config, &pkhs)
        .map_err(|e| std::io::Error::other(format!("Failed to create watermark: {e}")))?;
    let Ok(mut wm_lock) = app.watermark.write() else {
        fatal_error(
            device,
            "LOCK POISONED",
            &format!("Watermark lock poisoned during {context}"),
        );
    };
    *wm_lock = hwm;
    Ok(())
}

fn spawn_keygen(
    tx: Sender<AppEvent>,
    pin: Secret<Vec<u8>>,
    cpu_boost: Option<&cpu_freq::CpuBoost>,
) {
    let boost = cpu_boost.cloned();
    std::thread::spawn(move || {
        if let Some(ref b) = boost {
            b.boost();
        }
        let result = generate_and_encrypt_keys(&pin);
        if let Some(ref b) = boost {
            b.restore();
        }
        match result {
            Ok(json) => {
                let _ = tx.send(AppEvent::KeyGenSuccess(json));
            }
            Err(e) => {
                let _ = tx.send(AppEvent::KeyGenFailed(e));
            }
        }
    });
}

fn spawn_pin_verify(
    tx: Sender<AppEvent>,
    pin: Secret<Vec<u8>>,
    cpu_boost: Option<&cpu_freq::CpuBoost>,
) {
    let boost = cpu_boost.cloned();
    std::thread::spawn(move || {
        if let Some(ref b) = boost {
            b.boost();
        }
        let start = std::time::Instant::now();
        let result = tezos_encrypt::decrypt_secret_keys(&pin, {
            let tx = tx.clone();
            move || {
                let _ = tx.send(AppEvent::PinVerifyProgress {
                    message: "Upgrading PIN...".into(),
                    estimated_duration: Duration::from_secs(12),
                });
            }
        });
        if let Some(ref b) = boost {
            b.restore();
        }
        match result {
            Ok(outcome) => {
                log::info!("Decrypting time: {:?}", start.elapsed());
                let (json, migration) = outcome.into_parts();
                let _ = tx.send(AppEvent::PinVerified { json, migration });
            }
            Err(e) => {
                log::error!("PIN verification failed: {e}");
                log::info!("Decrypting time: {:?}", start.elapsed());
                let _ = tx.send(AppEvent::PinVerificationFailed);
            }
        }
    });
}

fn spawn_storage_setup(tx: Sender<AppEvent>) {
    std::thread::spawn(move || {
        let result = storage::setup_storage(|msg, pct| {
            tx.send(AppEvent::StorageProgress {
                message: msg.to_string(),
                percent: pct,
            })
            .map_err(|e| e.to_string())
        });
        match result {
            Ok(()) => {
                let _ = tx.send(AppEvent::StorageSetupComplete);
            }
            Err(e) => {
                let _ = tx.send(AppEvent::StorageSetupFailed(e));
            }
        }
    });
}

fn apply_watermark_config(device: &mut Device) {
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
            fatal_error(device, "WATERMARK ERROR", &e);
        }
    }
}

fn apply_verify_storage(device: &mut Device) {
    if let Err(e) = setup::verify_partitions() {
        fatal_error(device, "SETUP FAILED", &e);
    }
    if let Err(e) = setup::create_directories() {
        fatal_error(device, "SETUP FAILED", &e);
    }
}

fn apply_watermark_update(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
    pkh: &str,
    chain_id: ChainId,
    new_level: u32,
) -> epd_2in13_v4::EpdResult<()> {
    log::info!("Updating watermark for {pkh} on chain {chain_id:?} to level {new_level}");
    let wm_opt = match app.watermark.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::warn!("Watermark lock poisoned in update handler, recovering");
            poisoned.into_inner()
        }
    };

    let error_msg = if let Some(wm_lock) = wm_opt.as_ref() {
        if let Ok(pkh_parsed) = PublicKeyHash::from_b58check(pkh) {
            let mut wm = match wm_lock.write() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    log::warn!("Watermark inner lock poisoned in update handler, recovering");
                    poisoned.into_inner()
                }
            };
            if let Err(e) = wm.update_to_level(chain_id, &pkh_parsed, new_level) {
                log::error!("Failed to update watermark: {e}");
                Some(format!("Update failed:\n{e}"))
            } else {
                log::info!("Watermark updated to level {new_level} for {pkh}");
                let _ = app.tx.send(AppEvent::WatermarkUpdateSuccess);
                None
            }
        } else {
            log::error!("Invalid PKH for watermark update: {pkh}");
            Some("Update failed:\nInvalid key hash".into())
        }
    } else {
        log::warn!("Watermark not initialized yet");
        Some("Update failed:\nWatermark not ready".into())
    };

    if let Some(msg) = error_msg {
        let page = Box::new(dialog::Page::new(
            app.tx.clone(),
            &msg,
            AppEvent::DialogDismissed,
        ));
        app.current_page_modal = true;
        *current_page = page;
        current_page.show(&mut device.display)?;
        device.display.update()?;
    }
    Ok(())
}

/// Generate keys and encrypt them with the PIN
///
/// **SECURITY**: Keys are generated in memory and ONLY the encrypted form
/// is written to disk. Plaintext secret keys NEVER touch the filesystem.
///
/// Returns the secret keys JSON (for immediate use in signing mode).
fn generate_and_encrypt_keys(pin: &[u8]) -> Result<Secret<String>, String> {
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
    let secret_keys_json = build_secret_keys_json(&keys);

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

fn setup_signal_handler(tx: &crossbeam_channel::Sender<AppEvent>) {
    let tx_for_signal = tx.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        log::info!("Received Ctrl+C, shutting down...");
        let _ = tx_for_signal.send(AppEvent::Shutdown);
    }) {
        log::error!("Failed to set Ctrl-C handler: {e}");
    }
}

/// Initialize CPU frequency control (userspace governor).
///
/// Returns `Some(CpuBoost)` if the governor is available, `None` otherwise.
fn init_cpu_freq_control() -> Option<cpu_freq::CpuBoost> {
    match cpu_freq::CpuBoost::new() {
        Ok(boost) => Some(boost),
        Err(e) => {
            log::warn!("CPU freq control unavailable: {e}");
            None
        }
    }
}

/// Initialize LED control.
///
/// Returns `Some(Led)` if the sysfs brightness file is writable, `None` otherwise.
fn init_led_control() -> Option<led::Led> {
    match led::Led::new() {
        Ok(led) => Some(led),
        Err(e) => {
            log::warn!("LED control unavailable: {e}");
            None
        }
    }
}

type Callback = Option<Arc<dyn Fn() + Send + Sync>>;

/// Create pre/post connection callbacks that bracket a signer connection with
/// LED on/off and CPU frequency boost/restore.
fn connection_callbacks(
    cpu_boost: Option<&cpu_freq::CpuBoost>,
    led: Option<&led::Led>,
) -> (Callback, Callback) {
    match (cpu_boost, led) {
        (None, None) => (None, None),
        (cpu, led) => {
            let cpu_pre = cpu.cloned();
            let cpu_post = cpu.cloned();
            let led_pre = led.cloned();
            let led_post = led.cloned();
            (
                Some(Arc::new(move || {
                    if let Some(ref l) = led_pre {
                        l.on();
                    }
                    if let Some(ref b) = cpu_pre {
                        b.boost();
                    }
                })),
                Some(Arc::new(move || {
                    if let Some(ref b) = cpu_post {
                        b.restore();
                    }
                    if let Some(ref l) = led_post {
                        l.off();
                    }
                })),
            )
        }
    }
}

/// Build OCaml-compatible `secret_keys` JSON from in-memory keys.
///
/// Pre-sizes the output `Secret<String>` so `String::push_str` never
/// reallocates, which would copy the plaintext into a new heap block and
/// leave the old block un-zeroed. The single returned buffer is the only
/// place plaintext lives.
fn build_secret_keys_json(keys: &[&StoredKey]) -> Secret<String> {
    let n: usize = keys.iter().filter(|k| k.secret_key.is_some()).count();
    // 2 bytes for `[]`, plus a per-entry budget covering the skeleton, an
    // alias headroom, and a 64-byte upper bound on the base58 secret
    // (BLS12-381 BLsk is 54 chars, libs/signer/src/bls.rs:93).
    let cap = 2 + n.saturating_mul(192);

    let mut secret: Secret<String> = Secret::new(String::with_capacity(cap));
    let buf: &mut String = &mut secret;
    buf.push('[');
    let mut first = true;
    for key in keys {
        let Some(sk) = key.secret_key.as_ref() else {
            continue;
        };
        if !first {
            buf.push(',');
        }
        first = false;
        buf.push_str(r#"{"name":""#);
        write_escaped(buf, &key.alias);
        buf.push_str(r#"","value":"unencrypted:"#);
        // Base58 alphabet contains no `"`, `\`, or control bytes — write raw.
        buf.push_str(sk);
        buf.push_str(r#""}"#);
    }
    buf.push(']');
    secret
}

/// Escape a JSON string body: `"`, `\`, and ASCII control bytes as
/// `\u00XX`. No other escapes are needed because non-ASCII UTF-8 is valid
/// inside a JSON string.
fn write_escaped(out: &mut String, s: &str) {
    use core::fmt::Write;
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                write!(out, "\\u{:04x}", c as u32).expect("write to String is infallible");
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_signer_lib::wallet::OcamlKeyEntry;
    use zeroize::Zeroizing;

    const SAMPLE_SK: &str = "BLsk2snGqdSb7qBDhKbc62AxbZXJycDvA5QmeYYhB7Nb3wFuMMbq9x";

    fn make_key(alias: &str, sk: Option<&str>) -> StoredKey {
        StoredKey {
            alias: alias.to_string(),
            public_key_hash: format!("tz4{alias}"),
            public_key: format!("BLpk{alias}"),
            secret_key: sk.map(|s| Zeroizing::new(s.to_string())),
        }
    }

    #[test]
    fn emit_round_trip() {
        let k1 = make_key("consensus", Some(SAMPLE_SK));
        let k2 = make_key("companion", Some(SAMPLE_SK));
        let keys = [&k1, &k2];

        let secret = build_secret_keys_json(&keys);
        let parsed: Vec<OcamlKeyEntry<String>> =
            serde_json::from_str(&secret).expect("emitter must produce valid JSON");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "consensus");
        assert_eq!(parsed[0].value, format!("unencrypted:{SAMPLE_SK}"));
        assert_eq!(parsed[1].name, "companion");
        assert_eq!(parsed[1].value, format!("unencrypted:{SAMPLE_SK}"));
    }

    #[test]
    fn emit_no_realloc() {
        let k1 = make_key("consensus", Some(SAMPLE_SK));
        let k2 = make_key("companion", Some(SAMPLE_SK));
        let keys = [&k1, &k2];
        let n: usize = keys.iter().filter(|k| k.secret_key.is_some()).count();
        let expected_cap = 2 + n.saturating_mul(192);

        let secret = build_secret_keys_json(&keys);

        assert_eq!(
            secret.capacity(),
            expected_cap,
            "build_secret_keys_json reallocated its output buffer (capacity grew during emit)",
        );
        assert!(
            secret.len() <= expected_cap,
            "emitted output {len} exceeded preallocated capacity {expected_cap}",
            len = secret.len(),
        );
    }

    #[test]
    fn emit_escapes_alias() {
        let alias = "a\"b\\c";
        let k = make_key(alias, Some(SAMPLE_SK));
        let secret = build_secret_keys_json(&[&k]);

        let parsed: Vec<OcamlKeyEntry<String>> = serde_json::from_str(&secret)
            .expect("escaped alias must produce valid JSON parseable by serde_json");
        assert_eq!(parsed[0].name, alias);
    }

    #[test]
    fn emit_empty_input() {
        let secret = build_secret_keys_json(&[]);
        assert_eq!(&*secret, "[]");
    }

    #[test]
    fn emit_prefix_present() {
        let k = make_key("consensus", Some(SAMPLE_SK));
        let secret = build_secret_keys_json(&[&k]);
        assert!(
            secret.contains("unencrypted:"),
            "emitter dropped the `unencrypted:` prefix",
        );
    }
}
