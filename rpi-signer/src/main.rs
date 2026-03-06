mod app;
mod chain_info;
mod constants;
mod cpu_freq;
mod events;
mod fonts;
mod network_status;
mod pages;
mod setup;
mod signer_server;
mod storage;
mod tap_counter;
mod tezos_encrypt;
mod tezos_signer;
mod util;
mod watermark_setup;
mod widgets;

use app::{App, AppState, Effect, LoopAction, PageSpec};
use crossbeam_channel::Sender;
use russignol_signer_lib::{
    ChainId, HighWatermark,
    bls::PublicKeyHash,
    signing_activity,
    wallet::{KeyManager, OcamlKeyEntry, StoredKey},
};
use std::sync::RwLock;

use embedded_graphics::geometry::Dimensions;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::{DrawTarget, Point};
use epd_2in13_v4::display::Display;
use epd_2in13_v4::{Device, device};
use events::AppEvent;
use pages::{Page, confirmation, dialog, greeting, pin, screensaver, signatures, status};
use russignol_ui::pages::{error, progress};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use constants::KEYS_DIR;

/// Show a fatal error on the display and exit (never returns)
fn fatal_error(device: &mut Device, title: &str, message: &str) -> ! {
    log::error!("FATAL: {title} - {message}");
    let mut error_page = error::Page::new(title, message);
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
    let pre_sign_callback = cpu_boost
        .clone()
        .map(|b| Arc::new(move || b.boost()) as Arc<dyn Fn() + Send + Sync>);

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
        cpu_boost.as_ref(),
    );

    // Signer thread will naturally terminate when the server returns
    // No abort needed - threads clean up on drop
    drop(signer_handle);
    log::info!("Shutdown complete");

    result
}

fn run_ui_loop(
    signing_activity: &Arc<Mutex<signing_activity::SigningActivity>>,
    start_signer_tx: &crossbeam_channel::Sender<String>,
    tx: &crossbeam_channel::Sender<AppEvent>,
    rx: &crossbeam_channel::Receiver<AppEvent>,
    watermark: &Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    cpu_boost: Option<&cpu_freq::CpuBoost>,
) -> epd_2in13_v4::EpdResult<()> {
    const SCREENSAVER_TIMEOUT: Duration = Duration::from_secs(180);

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

    // Page save slots live in the runtime (not App) because they hold Box<dyn Page<Display>>
    let mut saved_page: Option<Box<dyn Page<Display>>> = None;
    let mut shutdown_saved_page: Option<Box<dyn Page<Display>>> = None;

    loop {
        let timeout = app.recv_timeout();

        let event = match rx.recv_timeout(timeout) {
            Ok(event) => event,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                handle_timeout(
                    &mut app,
                    &mut device,
                    &mut current_page,
                    tx,
                    SCREENSAVER_TIMEOUT,
                )?;
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
                    &mut device,
                    &mut current_page,
                    &mut saved_page,
                    &mut shutdown_saved_page,
                    touch_point,
                )?;
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
            apply_effects(
                &mut app,
                effects,
                &mut device,
                &mut current_page,
                &mut saved_page,
                &mut shutdown_saved_page,
                cpu_boost,
            )?;
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
    tx: &crossbeam_channel::Sender<AppEvent>,
    screensaver_timeout: Duration,
) -> epd_2in13_v4::EpdResult<()> {
    // Fire debounced tap if its delay has expired
    if let Some((point, tap_time)) = app.pending_tap
        && tap_time.elapsed() >= app.tap_counter.max_gap()
    {
        app.pending_tap = None;
        if current_page.handle_touch(point) {
            app.tap_counter.reset();
        }
    }

    // Check for inactivity timeout (screensaver)
    if let AppState::Active {
        screensaver_active,
        last_activity,
    } = &app.state
        && !screensaver_active
        && !current_page.is_modal()
        && last_activity.elapsed() >= screensaver_timeout
    {
        log::debug!("Inactivity timer expired, activating screensaver");
        let _ = tx.send(AppEvent::ActivateScreensaver);
    }

    // Animation tick
    if app.needs_animation && !app.is_screensaver_active() {
        current_page.show(&mut device.display)?;
        device.display.update()?;
    }
    Ok(())
}

fn handle_touch(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
    saved_page: &mut Option<Box<dyn Page<Display>>>,
    shutdown_saved_page: &mut Option<Box<dyn Page<Display>>>,
    touch_point: Point,
) -> epd_2in13_v4::EpdResult<()> {
    let now = Instant::now();

    if app.is_screensaver_active() {
        // Screensaver: all taps count toward shutdown
        if app.tap_counter.record_tap(now) {
            log::info!("Tap-to-shutdown threshold reached, showing confirmation");
            app.tap_counter.reset();
            device.display_wake()?;
            if let AppState::Active {
                screensaver_active, ..
            } = &mut app.state
            {
                *screensaver_active = false;
            }
            *shutdown_saved_page = saved_page.take();
            *current_page = Box::new(confirmation::Page::new(
                app.tx.clone(),
                "Shutdown the device?",
                AppEvent::Shutdown,
                AppEvent::CancelShutdown,
                false,
                "Shutdown",
            ));
            app.current_page_modal = true;
            app.needs_animation = false;
            current_page.show(&mut device.display)?;
            device.display.update()?;
        } else {
            log::debug!("Touch detected while screensaver active, waking up");
            let _ = app.tx.send(AppEvent::DeactivateScreensaver);
        }
    } else if current_page.is_modal() {
        // Modal pages: buttons must always work, no shutdown counter
        current_page.handle_touch(touch_point);
        if let AppState::Active { last_activity, .. } = &mut app.state {
            *last_activity = now;
        }
    } else {
        // Non-modal pages: debounce to suppress page-swap during multi-tap
        let is_followup = app.tap_counter.has_recent_taps(now);
        let triggered = app.tap_counter.record_tap(now);

        if triggered {
            log::info!("Tap-to-shutdown threshold reached, showing confirmation");
            app.tap_counter.reset();
            app.pending_tap = None;
            let old_page = std::mem::replace(
                current_page,
                Box::new(confirmation::Page::new(
                    app.tx.clone(),
                    "Shutdown the device?",
                    AppEvent::Shutdown,
                    AppEvent::CancelShutdown,
                    false,
                    "Shutdown",
                )),
            );
            *shutdown_saved_page = Some(old_page);
            app.current_page_modal = true;
            app.needs_animation = false;
            current_page.show(&mut device.display)?;
            device.display.update()?;
        } else if is_followup {
            app.pending_tap = None;
        } else {
            app.pending_tap = Some((touch_point, now));
        }

        if let AppState::Active { last_activity, .. } = &mut app.state {
            *last_activity = now;
        }
    }

    Ok(())
}

fn construct_page(
    spec: PageSpec,
    tx: &Sender<AppEvent>,
    signing_activity: &Arc<Mutex<signing_activity::SigningActivity>>,
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
        PageSpec::Status => Box::new(status::Page::new(tx.clone(), signing_activity.clone())),
        PageSpec::Signatures => {
            Box::new(signatures::Page::new(tx.clone(), signing_activity.clone()))
        }
        PageSpec::Screensaver => Box::new(screensaver::Page::new()),
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
        PageSpec::DeviceLocked => unreachable!("DeviceLocked handled directly in apply_effects"),
    }
}

fn apply_effects(
    app: &mut App,
    effects: Vec<Effect>,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
    saved_page: &mut Option<Box<dyn Page<Display>>>,
    shutdown_saved_page: &mut Option<Box<dyn Page<Display>>>,
    cpu_boost: Option<&cpu_freq::CpuBoost>,
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
                if let AppState::Active { last_activity, .. } = &mut app.state {
                    *last_activity = Instant::now();
                }
            }
            Effect::ResetTapCounter => app.tap_counter.reset(),
            Effect::SaveCurrentPage => {
                *saved_page = Some(std::mem::replace(
                    current_page,
                    Box::new(screensaver::Page::new()),
                ));
            }
            Effect::RestoreSavedPage => {
                if let Some(page) = saved_page.take() {
                    *current_page = page;
                }
                current_page.show(&mut device.display)?;
                device.display.update()?;
            }
            Effect::RestoreShutdownPage => {
                apply_restore_shutdown(app, device, current_page, shutdown_saved_page)?;
            }
            Effect::FatalError { title, message } => fatal_error(device, &title, &message),
            Effect::Exit(code) => std::process::exit(code),
            Effect::Sleep(duration) => std::thread::sleep(duration),
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
        let page = construct_page(spec, &app.tx, &app.signing_activity);
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

fn spawn_keygen(tx: Sender<AppEvent>, pin: Vec<u8>, cpu_boost: Option<&cpu_freq::CpuBoost>) {
    let boost = cpu_boost.cloned();
    std::thread::spawn(move || {
        if let Some(ref b) = boost {
            b.boost();
        }
        match generate_and_encrypt_keys(&pin) {
            Ok(json) => {
                let _ = tx.send(AppEvent::KeyGenSuccess(json));
            }
            Err(e) => {
                let _ = tx.send(AppEvent::KeyGenFailed(e));
            }
        }
    });
}

fn spawn_pin_verify(tx: Sender<AppEvent>, pin: Vec<u8>, cpu_boost: Option<&cpu_freq::CpuBoost>) {
    let boost = cpu_boost.cloned();
    std::thread::spawn(move || {
        if let Some(ref b) = boost {
            b.boost();
        }
        let start = std::time::Instant::now();
        match tezos_encrypt::decrypt_secret_keys(&pin) {
            Ok(json) => {
                log::info!("Decrypting time: {:?}", start.elapsed());
                let _ = tx.send(AppEvent::PinVerified(json));
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

fn apply_restore_shutdown(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
    shutdown_saved_page: &mut Option<Box<dyn Page<Display>>>,
) -> epd_2in13_v4::EpdResult<()> {
    if let Some(page) = shutdown_saved_page.take() {
        *current_page = page;
    } else {
        *current_page = Box::new(status::Page::new(
            app.tx.clone(),
            app.signing_activity.clone(),
        ));
    }
    app.needs_animation = false;
    app.current_page_modal = current_page.is_modal();
    current_page.show(&mut device.display)?;
    device.display.update()?;
    Ok(())
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
        Ok(boost) => {
            boost.spawn_watcher();
            Some(boost)
        }
        Err(e) => {
            log::warn!("CPU freq control unavailable: {e}");
            None
        }
    }
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
