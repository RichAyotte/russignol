mod app;
mod chain_info;
mod constants;
mod cpu_freq;
mod events;
mod fonts;
mod image_info;
mod led;
mod log_writer;
mod network_status;
mod pages;
mod provision;
mod rootfs_check;
mod secret;
mod setup;
mod signer_server;
mod storage;
mod text;
mod tezos_encrypt;
mod tezos_signer;
mod util;
mod watermark_setup;
mod widgets;

use app::{App, Effect, LoopAction, PageSpec, PendingRender, STORE_ENCRYPT_ESTIMATE};
use crossbeam_channel::Sender;
use russignol_signer_lib::{
    ChainId, DeviceKey, HighWatermark, KeyRole, PublicKeyHash, signing_activity,
};
use std::sync::RwLock;

use embedded_graphics::geometry::Dimensions;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::{DrawTarget, Point};
use epd_2in13_v4::display::{Display, UpdateOutcome};
use epd_2in13_v4::{Device, device};
use events::{AppEvent, ConfigPresence};
use pages::{
    Page, about, confirmation, dialog, greeting, menu, notice, pin, screensaver, signatures, status,
};
use russignol_ui::pages::{error, progress};
use secret::Secret;
use setup::BootStage;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use constants::{LOG_DIR, LOG_FILE};

/// Show a fatal error on the display and exit (never returns)
fn fatal_error(device: &mut Device, title: &str, message: &str) -> ! {
    log::error!("FATAL: {title} - {message}");
    let mut error_page = error::Page::new(title, message);
    let _ = error_page.show(&mut device.display);
    let _ = device.display.update_transition();
    std::process::exit(1)
}

/// What an init script recorded in the variable `constants::BOOT_FAULT_ENV`
/// names. Both scripts export it on every boot, empty where the boot
/// partition mounted, so empty reads as no fault rather than as one with no
/// text.
fn boot_fault(recorded: Option<&str>) -> Option<&str> {
    recorded.filter(|fault| !fault.is_empty())
}

fn halt_on_boot_fault(device: &mut Device) {
    let recorded = std::env::var(constants::BOOT_FAULT_ENV).ok();
    if let Some(fault) = boot_fault(recorded.as_deref()) {
        fatal_error(device, "BOOT FAULT", fault);
    }
}

/// Whether this boot's mounts are checked, and if so whether `/keys` may be
/// writable under it. An unmarked boot holds `/keys` writable because both
/// init scripts leave it so for key generation (`mount_keys_partition` in
/// `rootfs-overlay-dev/etc/init.d/S20russignol`, `init_keys_partition` in
/// `rootfs-overlay-hardened/init`), and it is checked rather than skipped as
/// a first boot: an unmounted `/keys` has no marker in it, and that is the
/// boot the check exists to halt. A process still root holds `/keys`
/// writable for the staged work it was kept root for.
const fn mount_check(stage: BootStage, is_root: bool) -> Option<bool> {
    match stage {
        BootStage::NoPartitions => None,
        BootStage::Unmarked => Some(true),
        BootStage::Provisioned => Some(is_root),
    }
}

fn halt_on_wrong_mounts(device: &mut Device, keys_writable: bool) {
    if let Err(fault) = storage::verify_boot_mounts(keys_writable) {
        fatal_error(device, "BOOT FAULT", &fault);
    }
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

/// Signer-thread callbacks that translate signing events into `AppEvent`s on
/// the UI channel. Bundled so `main` constructs them in one place.
struct SignerEventCallbacks {
    watermark_error: signer_server::WatermarkErrorCallback,
    signing: Arc<dyn Fn() + Send + Sync>,
    large_gap: signer_server::LargeGapCallback,
    missing_watermark: signer_server::MissingWatermarkCallback,
    unknown_key: signer_server::UnknownKeyCallback,
}

fn build_signer_event_callbacks(app_tx: &Sender<AppEvent>) -> SignerEventCallbacks {
    let tx_for_callback = app_tx.clone();
    let watermark_error: signer_server::WatermarkErrorCallback =
        Arc::new(move |pkh, chain_id, error| {
            let _ = tx_for_callback.send(AppEvent::WatermarkError {
                pkh: pkh.to_b58check(),
                chain_id,
                error_message: error.to_string(),
            });
        });

    let tx_for_signing = app_tx.clone();
    let signing: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        let _ = tx_for_signing.send(AppEvent::Invalidate);
    });

    let tx_for_large_gap = app_tx.clone();
    let large_gap: signer_server::LargeGapCallback =
        Arc::new(move |pkh, chain_id, current_level, requested_level| {
            let _ = tx_for_large_gap.send(AppEvent::LargeWatermarkGap {
                pkh: pkh.to_b58check(),
                chain_id,
                current_level,
                requested_level,
            });
        });

    let tx_for_missing = app_tx.clone();
    let missing_watermark: signer_server::MissingWatermarkCallback =
        Arc::new(move |pkh, chain_id, requested_level| {
            let _ = tx_for_missing.send(AppEvent::WatermarkMissing {
                pkh: pkh.to_b58check(),
                chain_id,
                requested_level,
            });
        });

    let tx_for_unknown = app_tx.clone();
    let unknown_key: signer_server::UnknownKeyCallback = Arc::new(move |pkh| {
        let _ = tx_for_unknown.send(AppEvent::UnknownKeyRequested {
            pkh: pkh.to_b58check(),
        });
    });

    SignerEventCallbacks {
        watermark_error,
        signing,
        large_gap,
        missing_watermark,
        unknown_key,
    }
}

fn main() -> epd_2in13_v4::EpdResult<()> {
    init_logging();
    image_info::log_image_info();

    // Before any key is generated, so the pool it fans out over is created in
    // the background class and a signature never waits behind it.
    russignol_signer_lib::xmss::deprioritize_key_generation();

    let signing_activity = Arc::new(Mutex::new(signing_activity::SigningActivity::default()));
    let (app_tx, app_rx) = crossbeam_channel::unbounded();

    // Channel of already-parsed key managers (secrets loaded once at unlock)
    let (start_signer_tx, start_signer_rx) =
        crossbeam_channel::bounded::<russignol_signer_lib::ServerKeyManager>(1);

    // Watermark will be created after PIN entry and encryption unlock
    let watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>> = Arc::new(RwLock::new(None));

    let event_callbacks = build_signer_event_callbacks(&app_tx);

    setup_signal_handler(&app_tx);

    // Spawn task that waits for keys to be ready before starting signer
    let signing_activity_clone = signing_activity.clone();
    let watermark_for_signer = watermark.clone();
    let watermark_callback_for_signer = Some(event_callbacks.watermark_error);
    let signing_callback_for_signer = Some(event_callbacks.signing);
    let large_gap_callback_for_signer = Some(event_callbacks.large_gap);
    let missing_watermark_callback_for_signer = Some(event_callbacks.missing_watermark);
    let unknown_key_callback_for_signer = Some(event_callbacks.unknown_key);
    let tx_for_signer = app_tx.clone();

    let cpu_boost = init_cpu_freq_control();
    let led = init_led_control();
    let (pre_sign_callback, post_sign_callback) =
        connection_callbacks(cpu_boost.as_ref(), led.as_ref());

    let boost_for_warm = cpu_boost.clone();
    let signer_handle = std::thread::spawn(move || {
        // Wait for key manager produced once at unlock (in memory only)
        if let Ok(key_manager) = start_signer_rx.recv() {
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
                missing_watermark: missing_watermark_callback_for_signer,
                unknown_key: unknown_key_callback_for_signer,
                pre_sign: pre_sign_callback,
                post_sign: post_sign_callback,
            };

            if let Err(e) = signer_server::start_integrated_signer(
                &config,
                key_manager,
                &signing_activity_clone,
                watermark.as_ref(),
                &callbacks,
                blocks_per_cycle,
                boost_for_warm,
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
    start_signer_tx: &crossbeam_channel::Sender<russignol_signer_lib::ServerKeyManager>,
    tx: &crossbeam_channel::Sender<AppEvent>,
    rx: &crossbeam_channel::Receiver<AppEvent>,
    watermark: &Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    cpu_boost: Option<&cpu_freq::CpuBoost>,
) -> epd_2in13_v4::EpdResult<()> {
    const SCREENSAVER_TIMEOUT: Duration = Duration::from_mins(1);
    // A partial refresh runs a few hundred ms, so a deferred render retries
    // within a few wakeups and lands almost immediately after the panel
    // goes idle.
    const RENDER_RETRY_POLL: Duration = Duration::from_millis(50);

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

    halt_on_boot_fault(&mut device);

    let stage = setup::boot_stage();
    let is_first_boot = stage.is_first_boot();

    // CRITICAL: Check for error conditions BEFORE showing any UI
    if is_first_boot && let Err(e) = setup::verify_partitions_early() {
        fatal_error(&mut device, "SETUP ERROR", &e);
    }

    if is_first_boot {
        verify_rootfs_integrity(&mut device);
    }

    let pending_watermark_level = recover_watermark_config(&mut device, is_first_boot);

    // Placed after `recover_watermark_config`, which is what demotes a boot with
    // nothing to keep `/keys` writable for, so a process still root here holds
    // it writable on purpose.
    let is_root = unsafe { libc::geteuid() } == 0;
    if let Some(keys_writable) = mount_check(stage, is_root) {
        halt_on_wrong_mounts(&mut device, keys_writable);
    }

    let mut app = App::new(
        is_first_boot,
        tx.clone(),
        signing_activity.clone(),
        start_signer_tx.clone(),
        watermark.clone(),
    );
    app.pending_watermark_level = pending_watermark_level;

    let mut current_page: Box<dyn Page<Display>> = if is_first_boot {
        log::info!("First boot detected - starting setup flow");
        Box::new(greeting::Page::new(tx.clone()))
    } else {
        log::info!("Normal boot - showing PIN verification");
        Box::new(pin::Page::new(tx.clone(), "Enter\n PIN", pin::Mode::Verify))
    };
    render_page_transition(&mut device, &mut current_page)?;

    loop {
        let timeout = match app.pending_render {
            PendingRender::None => app.recv_timeout(),
            _ => app.recv_timeout().min(RENDER_RETRY_POLL),
        };

        match rx.recv_timeout(timeout) {
            Ok(first) => {
                let exit = drain_events(
                    &mut app,
                    &mut device,
                    &mut current_page,
                    rx,
                    first,
                    cpu_boost,
                    &screensaver_reset_tx,
                );
                if exit {
                    break;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                handle_timeout(&mut app, &mut device, &mut current_page)?;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                log::info!("Event channel disconnected, exiting event loop");
                break;
            }
        }

        let kind = app.pending_render.take();
        if app.should_flush_repaint(kind) {
            match kind {
                PendingRender::None => {}
                PendingRender::InPlace => {
                    if try_render_page(&mut device, &mut current_page)? == UpdateOutcome::Busy {
                        app.pending_render.record_invalidate();
                    }
                }
                PendingRender::Transition => {
                    try_render_page_transition(
                        &mut device,
                        &mut current_page,
                        &mut app.pending_render,
                    )?;
                }
            }
        }
    }

    Ok(())
}

/// Process `first` plus everything already queued, in arrival order.
/// Invalidate events are recorded into the app's pending render rather than
/// rendered, so the caller flushes a burst as at most one render — a touch
/// never waits behind queued e-paper repaints. Returns whether the loop
/// should exit.
fn drain_events(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
    rx: &crossbeam_channel::Receiver<AppEvent>,
    first: AppEvent,
    cpu_boost: Option<&cpu_freq::CpuBoost>,
    screensaver_reset_tx: &Sender<()>,
) -> bool {
    let mut next = Some(first);
    while let Some(event) = next {
        match event {
            AppEvent::Touch(touch_point) => {
                handle_touch(app, current_page, touch_point, screensaver_reset_tx);
            }
            AppEvent::Invalidate => app.pending_render.record_invalidate(),
            event => {
                let (action, effects) = app.handle_event(event);

                if action != LoopAction::Continue {
                    // A failed effect otherwise unwinds to `main` and exits
                    // with the last frame still on the bistable panel — a
                    // crash that reads as a hang. Render it instead
                    // (fatal_error diverges).
                    if let Err(e) = apply_effects(
                        app,
                        effects,
                        device,
                        current_page,
                        cpu_boost,
                        screensaver_reset_tx,
                    ) {
                        fatal_error(device, "SYSTEM ERROR", &e.to_string());
                    }
                    if action == LoopAction::Break {
                        return true;
                    }
                }
            }
        }
        next = rx.try_recv().ok();
    }
    false
}

/// Draw the current page and push the frame in place unless the panel is
/// mid-refresh; a busy panel drops the frame, and the caller decides
/// whether anything retries.
fn try_render_page(
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
) -> epd_2in13_v4::EpdResult<UpdateOutcome> {
    current_page.show(&mut device.display)?;
    device.display.try_update()
}

/// Draw the current page and push the frame as a page transition, the
/// moment where a due anti-ghosting full refresh is allowed to land. A busy
/// panel defers instead: the transition is recorded in `pending` and the
/// event loop's retry poll re-pushes the redrawn page once the panel goes
/// idle.
fn try_render_page_transition(
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
    pending: &mut PendingRender,
) -> epd_2in13_v4::EpdResult<()> {
    current_page.show(&mut device.display)?;
    if device.display.try_update_transition()? == UpdateOutcome::Busy {
        pending.record_transition();
    }
    Ok(())
}

/// Draw the current page and push the frame as a page transition, waiting
/// out any in-flight refresh. For sites that must land before the loop
/// continues (boot, terminal paths).
fn render_page_transition(
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
) -> epd_2in13_v4::EpdResult<()> {
    current_page.show(&mut device.display)?;
    device.display.update_transition()?;
    Ok(())
}

fn handle_timeout(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
) -> epd_2in13_v4::EpdResult<()> {
    if app.needs_animation && !app.is_screensaver_active() {
        // A busy panel drops this frame; the next animation tick redraws.
        try_render_page(device, current_page)?;
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
            // A busy panel drops this frame; the next animation tick redraws.
            if let Err(e) = try_render_page(device, current_page) {
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
        return;
    }
    current_page.handle_touch(touch_point);
    let _ = screensaver_reset_tx.send(());
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
        PageSpec::Status => Box::new(status::Page::new(
            tx.clone(),
            signing_activity.clone(),
            watermark.clone(),
        )),
        PageSpec::Signatures => {
            Box::new(signatures::Page::new(tx.clone(), signing_activity.clone()))
        }
        PageSpec::Keys => Box::new(pages::keys::Page::new(tx.clone(), watermark.clone())),
        PageSpec::Provision => Box::new(pages::provision::Page::new(tx.clone())),
        PageSpec::About => Box::new(about::Page::new(tx.clone())),
        PageSpec::Greeting => Box::new(greeting::Page::new(tx.clone())),
        PageSpec::Image { back } => Box::new(pages::image_info::Page::new(tx.clone(), back)),
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
            Effect::ShowDeviceLocked => apply_show_device_locked(device)?,
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
                device.display.update_full()?;
            }
            Effect::Emit(event) => {
                let _ = app.tx.send(event);
            }
            Effect::StartSigner => {
                if let Err(e) = app.start_signer() {
                    fatal_error(device, "SIGNER START ERROR", &e);
                }
            }
            Effect::InitWatermark {
                context,
                secret_keys,
            } => {
                apply_init_watermark(app, device, &context, &secret_keys, cpu_boost)?;
            }
            Effect::SpawnKeygen { pin } => spawn_keygen(app.tx.clone(), pin, cpu_boost),
            Effect::SpawnPinVerify { pin } => spawn_pin_verify(app.tx.clone(), pin, cpu_boost),
            Effect::SpawnStageRequest { pin, key } => spawn_stage_request(&app.tx, pin, key),
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
            Effect::ProcessWatermarkConfig => apply_watermark_config(app, device),
            Effect::ValidateWatermarkConfig => apply_validate_watermark_config(app),
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
                apply_drop_current_page(app, device, current_page)?;
            }
            Effect::RebuildSavedPage => apply_rebuild_saved_page(app, device, current_page)?,
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

/// Rebuild the page the app last showed, where it remembers one.
fn apply_rebuild_saved_page(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
) -> epd_2in13_v4::EpdResult<()> {
    let Some(spec) = app.current_page_spec.clone() else {
        return Ok(());
    };
    let page = construct_page(spec, &app.tx, &app.signing_activity, &app.watermark);
    app.current_page_modal = page.is_modal();
    app.needs_animation = false;
    *current_page = page;
    try_render_page_transition(device, current_page, &mut app.pending_render)
}

/// Swap in the screensaver page and push it. Blocking: the push must
/// complete before the `SleepDisplay` that follows in the same effect list,
/// so nothing may defer here.
fn apply_drop_current_page(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
) -> epd_2in13_v4::EpdResult<()> {
    // The screensaver frame supersedes any deferred render — wake rebuilds
    // the saved page — and a surviving transition could land a due
    // anti-ghosting full on the panel after it goes to sleep.
    app.pending_render = PendingRender::None;
    *current_page = Box::new(screensaver::Page::new());
    // A transition, not a forced full: with a 1-minute idle timeout an
    // unconditional full would flash every minute of hands-off watching; a
    // due anti-ghosting full still lands here behind the logo swap.
    current_page.show(&mut device.display)?;
    device.display.update_transition()?;
    Ok(())
}

fn apply_show_page(
    app: &mut App,
    device: &mut Device,
    current_page: &mut Box<dyn Page<Display>>,
    spec: PageSpec,
) -> epd_2in13_v4::EpdResult<()> {
    app.current_page_spec = Some(spec.clone());
    let page = construct_page(spec, &app.tx, &app.signing_activity, &app.watermark);
    app.current_page_modal = page.is_modal();
    app.needs_animation = false;
    *current_page = page;
    try_render_page_transition(device, current_page, &mut app.pending_render)
}

/// Draw the locked screen, which is the last thing this boot puts on the panel.
fn apply_show_device_locked(device: &mut Device) -> epd_2in13_v4::EpdResult<()> {
    device.display.clear(BinaryColor::On)?;
    let font = u8g2_fonts::FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
    let display_center = device.display.bounding_box().center();
    pages::drawn(font.render_aligned(
        "LOCKED\nPower cycle to retry",
        display_center,
        u8g2_fonts::types::VerticalPosition::Center,
        u8g2_fonts::types::HorizontalAlignment::Center,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        &mut device.display,
    ))?;
    device.display.update_transition()
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
    try_render_page_transition(device, current_page, &mut app.pending_render)?;
    Ok(())
}

fn apply_init_watermark(
    app: &mut App,
    device: &mut Device,
    context: &str,
    secret_keys: &Secret<String>,
    cpu_boost: Option<&cpu_freq::CpuBoost>,
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

    // The manager reaches the signer thread through `app.pending_key_manager` and
    // the parameters go into the watermark store, so the JSON and its base58
    // values decode once per unlock rather than once per signer start.
    // A tz6 key's load is its base58 decode, quadratic in the value, and it
    // runs at the boosted clock like the decrypt ahead of it rather than at
    // the idle one.
    let loaded = {
        let _held = cpu_boost.map(cpu_freq::CpuBoost::hold);
        signer_server::load_secret_keys(secret_keys.as_str())
    };
    let (key_manager, mark_params) = match loaded {
        Ok(loaded) => loaded,
        Err(e) => fatal_error(
            device,
            "KEY LOAD ERROR",
            &format!("Failed to load secret keys: {e}"),
        ),
    };
    let pkhs = key_manager.list_keys();

    // A mark is bound to its chain. If chain_info is absent, an unrelated chain
    // id yields marks that fail to verify, which the missing-watermark recovery
    // then re-establishes.
    let chain_id = chain_info::read_chain_info()
        .ok()
        .and_then(|info| ChainId::from_b58check(&info.id))
        .unwrap_or_else(|| ChainId::from_bytes(&[0u8; 32]));

    let hwm = signer_server::create_high_watermark(&config, &pkhs, mark_params, chain_id)
        .map_err(|e| std::io::Error::other(format!("Failed to create watermark: {e}")))?;

    app.pending_key_manager = Some(key_manager);

    // Apply a staged config level as an authenticated floor now that the per-key
    // MAC key exists. Never-lower: an existing higher mark is preserved. This is
    // the only floor-establishment path that runs without a live baker request;
    // if it fails, the signing-time recovery dialog remains the backstop.
    if let (Some(level), Some(wm_arc)) = (app.pending_watermark_level.take(), hwm.as_ref()) {
        match wm_arc.write() {
            Ok(mut wm) => {
                for pkh in &pkhs {
                    if let Err(e) = wm.seed_floor(chain_id, pkh, level) {
                        log::error!(
                            "Failed to seed watermark floor for {}: {e}",
                            pkh.to_b58check()
                        );
                    }
                }
            }
            Err(_) => log::error!("Watermark lock poisoned while seeding floor"),
        }
    }

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
        let _held = boost.as_ref().map(cpu_freq::CpuBoost::hold);
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

fn spawn_pin_verify(
    tx: Sender<AppEvent>,
    pin: Secret<Vec<u8>>,
    cpu_boost: Option<&cpu_freq::CpuBoost>,
) {
    let boost = cpu_boost.cloned();
    std::thread::spawn(move || {
        let _held = boost.as_ref().map(cpu_freq::CpuBoost::hold);
        let start = std::time::Instant::now();
        let result = tezos_encrypt::decrypt_secret_keys(&pin, {
            let tx = tx.clone();
            move || {
                let _ = tx.send(AppEvent::PinVerifyProgress {
                    message: "Upgrading PIN...".into(),
                    estimated_duration: STORE_ENCRYPT_ESTIMATE,
                });
            }
        });
        let event = match result {
            Ok(outcome) => {
                log::info!("Decrypting time: {:?}", start.elapsed());
                let (json, migration) = outcome.into_parts();
                // A staged request waits out a PIN-blob migration rather than
                // running beside it: both keep the keys partition writable for
                // this boot, and the migration ends in a reboot the request
                // will still be staged for.
                match migration {
                    None => provision_staged_request(&tx, &pin, json, &provision::Paths::device()),
                    Some(_) => AppEvent::PinVerified { json, migration },
                }
            }
            Err(e) => {
                log::error!("PIN verification failed: {e}");
                log::info!("Decrypting time: {:?}", start.elapsed());
                AppEvent::PinVerificationFailed
            }
        };
        let _ = tx.send(event);
    });
}

/// Carry out the provisioning request staged for this boot, if there is one.
///
/// Runs here rather than on the UI thread because generating a tz6 key walks
/// every epoch in its span and takes tens of minutes on the device.
///
/// Clearing the request is attempted whatever the run does, and a clear that
/// failed rides on the answer rather than being dropped: while the request is
/// there, every boot after this one is a privileged boot that provisions again.
fn provision_staged_request(
    tx: &Sender<AppEvent>,
    pin: &[u8],
    json: Secret<String>,
    paths: &provision::Paths,
) -> AppEvent {
    let key = match provision::staged_request(paths.request()) {
        Ok(None) => {
            return AppEvent::PinVerified {
                json,
                migration: None,
            };
        }
        Ok(Some(key)) => key,
        Err(e) => {
            let reason = format!("{e}");
            return match provision::clear_request(paths.request()) {
                Ok(()) => AppEvent::ProvisionFailed { json, reason },
                Err(e) => AppEvent::ProvisionFailed {
                    json,
                    reason: format!("{reason}; the request would not clear: {e}"),
                },
            };
        }
    };

    let what = match key {
        DeviceKey::Bls(role) => provision::Provisioning::Bls(role),
        DeviceKey::XmssConsensus => provision::Provisioning::Xmss(constants::XMSS_EPOCHS),
    };
    let _ = tx.send(AppEvent::PinVerifyProgress {
        message: format!("Generating {}...", key.device_alias()),
        estimated_duration: provision::estimate(key),
    });

    let outcome = provision::provision_key(paths.store(), pin, json.as_str(), what);
    let uncleared = provision::clear_request(paths.request())
        .err()
        .map(|e| format!("{e}"));
    match outcome {
        // The card holds what the run wrote, so that is what the device
        // serves: unlocking on the store it read would leave the signer
        // serving a secret the card no longer carries.
        Ok(provisioned) => AppEvent::KeysProvisioned {
            json: provisioned,
            key,
            uncleared,
        },
        Err(reason) => AppEvent::ProvisionFailed {
            json,
            reason: match uncleared {
                None => reason,
                Some(e) => format!("{reason}; the request would not clear: {e}"),
            },
        },
    }
}

/// Check `pin` against the card and, where it opens it, stage a request for
/// the next boot to provision `key`.
///
/// The check is a decrypt of the card's own key store rather than anything
/// held in memory: the store is what a provisioning boot will open with the
/// same PIN, so a PIN that stages a request is one that boot can act on.
fn spawn_stage_request(tx: &Sender<AppEvent>, pin: Secret<Vec<u8>>, key: DeviceKey) {
    let tx = tx.clone();
    std::thread::spawn(move || {
        let paths = provision::Paths::device();
        let event = match stage_request(&paths, &pin, key) {
            Ok(()) => AppEvent::ProvisionRequested,
            Err(reason) => AppEvent::ProvisionRequestFailed { reason },
        };
        let _ = tx.send(event);
    });
}

/// The PIN check and the write behind it.
fn stage_request(paths: &provision::Paths, pin: &[u8], key: DeviceKey) -> Result<(), String> {
    let blob =
        std::fs::read(paths.store()).map_err(|e| format!("The card would not read.\n{e}"))?;
    // A wrong PIN and a store that will not parse both come back as
    // InvalidData, so the two are one reading at this API and the operator is
    // given the one they can act on. The log keeps the other, as
    // spawn_pin_verify does at unlock.
    russignol_crypto::decrypt(pin, &blob).map_err(|e| {
        log::error!("The card would not open: {e}");
        "Invalid PIN".to_string()
    })?;
    provision::stage_request(paths.request(), key)
        .map_err(|e| format!("The request would not be written.\n{e}"))
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

/// What a boot does with a staged watermark config and with its privileges,
/// before the PIN page is drawn.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BootRecovery {
    /// Leave the staged config alone. Either setup has yet to run, the init
    /// script did not keep us privileged, or a PIN-blob migration is competing
    /// for the writable keys partition.
    None,
    /// Consume it and keep root: the provisioning run that follows the PIN
    /// needs the keys partition writable, and hands privileges off with its
    /// own result.
    Consume,
    /// Consume it, then hand privileges off before the signer thread starts.
    ConsumeAndDemote,
}

/// The work a card has staged for this boot to carry out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StagedWork {
    /// Nothing beyond serving signatures.
    None,
    /// A v1 PIN blob, whose migration is competing for the writable keys
    /// partition.
    PinMigration,
    /// A request to provision one key.
    Provisioning,
}

impl StagedWork {
    /// What the two markers on the card amount to.
    ///
    /// A PIN migration comes first where both are staged: it ends in a reboot
    /// the provisioning request is still staged for.
    const fn staged(migration_pending: bool, provision_pending: bool) -> Self {
        if migration_pending {
            Self::PinMigration
        } else if provision_pending {
            Self::Provisioning
        } else {
            Self::None
        }
    }
}

/// What this boot's posture makes safe.
///
/// Writing `/keys` needs root and a writable mount, which only the init script
/// can arrange and only for the boot it arranged them on. Handing them off
/// before the work that needs them has run leaves that work unable to write at
/// all.
const fn boot_recovery(is_first_boot: bool, is_root: bool, staged: StagedWork) -> BootRecovery {
    if is_first_boot || !is_root {
        return BootRecovery::None;
    }
    match staged {
        StagedWork::PinMigration => BootRecovery::None,
        StagedWork::Provisioning => BootRecovery::Consume,
        StagedWork::None => BootRecovery::ConsumeAndDemote,
    }
}

/// First-boot rootfs integrity check against the hash the host recorded in
/// the flash manifest. A mismatch is fatal: setup would otherwise generate
/// keys on a card that is already corrupting. The check detects accidental
/// corruption only — the SD card is attacker-mutable, so it makes no
/// authenticity claim, and the shown message must not either.
fn verify_rootfs_integrity(device: &mut Device) {
    let message = "Verifying image";
    // Created on the first progress tick: a skipped check (dev image, no
    // manifest hash) never hashes, and must not cost an e-paper refresh.
    let mut page: Option<progress::Page> = None;
    let mut last_drawn = 0u8;
    let result = rootfs_check::verify_rootfs(|percent| {
        // E-paper refreshes are slow; redraw at coarse steps only
        if page.is_none() || percent >= last_drawn.saturating_add(20) {
            last_drawn = percent;
            let page = page.get_or_insert_with(|| progress::Page::new(message));
            page.set_progress(message, percent);
            let _ = page.show(&mut device.display);
            let _ = device.display.update();
        }
    });

    match result {
        rootfs_check::RootfsCheck::Verified => log::info!("Rootfs integrity verified"),
        rootfs_check::RootfsCheck::Skipped(reason) => {
            log::info!("Rootfs integrity check skipped: {reason}");
        }
        rootfs_check::RootfsCheck::Mismatch { expected, actual } => {
            log::error!("Rootfs hash mismatch: expected {expected}, got {actual}");
            fatal_error(
                device,
                "CARD CORRUPTION",
                "System files differ from what was flashed. The SD card is likely corrupted or worn out. Re-flash it with the host utility.",
            );
        }
    }
}

/// Consume a staged boot-partition watermark config on a normal boot, and
/// restore the read-only-keys, unprivileged posture where nothing later on this
/// boot needs the other one.
///
/// The init script leaves the signer running as root with `/keys` writable only
/// where work is staged that needs it, so `save_chain_info` (which writes
/// `/keys/chain_info.json`) can succeed. Consuming the config is best-effort:
/// the on-device recovery dialog remains the fallback, so a consume failure must
/// not brick a healthy device. The remount and privilege drop are load-bearing
/// security steps and stay fatal on failure, matching the first-boot path — and
/// a provisioning boot takes them from its own run instead, after the key store
/// it was booted to write has been written.
fn recover_watermark_config(device: &mut Device, is_first_boot: bool) -> Option<u32> {
    let is_root = unsafe { libc::geteuid() } == 0;
    let migration_pending = std::path::Path::new(tezos_encrypt::SECRET_KEYS_ENC_PATH).exists();
    let provision_pending = std::path::Path::new(constants::PROVISION_REQUEST_FILE).exists();

    let recovery = boot_recovery(
        is_first_boot,
        is_root,
        StagedWork::staged(migration_pending, provision_pending),
    );
    match recovery {
        BootRecovery::None => return None,
        BootRecovery::Consume => log::info!(
            "Provisioning request staged - consuming any watermark config and keeping root for the run"
        ),
        BootRecovery::ConsumeAndDemote => {
            log::info!("Privileged boot - consuming any watermark config, then demoting");
        }
    }
    let pending_level = match watermark_setup::process_watermark_config() {
        watermark_setup::WatermarkResult::Configured { chain_name, level } => {
            log::info!("Recovered chain info: {chain_name}, staged floor level {level}");
            Some(level)
        }
        watermark_setup::WatermarkResult::NotFound => {
            log::info!("No watermark config found during recovery");
            None
        }
        watermark_setup::WatermarkResult::Error(e) => {
            log::error!("Watermark config recovery failed (continuing): {e}");
            None
        }
    };

    // Order is load-bearing: consume with /keys writable, then remount it
    // read-only and drop privileges before the signer thread can start.
    if recovery == BootRecovery::ConsumeAndDemote {
        if let Err(e) = storage::remount_keys_readonly() {
            fatal_error(device, "SECURITY ERROR", &e);
        }
        if let Err(e) = storage::drop_privileges() {
            fatal_error(device, "SECURITY ERROR", &e);
        }
    }
    pending_level
}

fn apply_watermark_config(app: &mut App, device: &mut Device) {
    app.pending_watermark_level = match watermark_setup::process_watermark_config() {
        watermark_setup::WatermarkResult::Configured { chain_name, level } => {
            log::info!("Chain info recorded: {chain_name}, staged floor level {level}");
            Some(level)
        }
        watermark_setup::WatermarkResult::NotFound => {
            log::info!(
                "No watermark config found - signer will reject signing until watermarks are set"
            );
            None
        }
        watermark_setup::WatermarkResult::Error(e) => {
            log::error!("Watermark config error: {e}");
            fatal_error(device, "WATERMARK ERROR", &e);
        }
    };
}

/// Validate the staged watermark config before key generation without consuming
/// it, and report the outcome so the setup gate can branch. The consuming pass
/// (`apply_watermark_config`) runs later, after keygen.
fn apply_validate_watermark_config(app: &App) {
    let presence = match watermark_setup::validate_watermark_config() {
        watermark_setup::WatermarkResult::Configured { chain_name, level } => {
            log::info!("Watermark config staged and valid: {chain_name}, floor level {level}");
            ConfigPresence::Present
        }
        watermark_setup::WatermarkResult::NotFound => {
            log::warn!("No watermark config staged for the pre-keygen check");
            ConfigPresence::Missing
        }
        watermark_setup::WatermarkResult::Error(e) => {
            log::warn!("Staged watermark config failed the pre-keygen check: {e}");
            ConfigPresence::Invalid
        }
    };
    let _ = app.tx.send(AppEvent::WatermarkConfigChecked(presence));
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
        try_render_page_transition(device, current_page, &mut app.pending_render)?;
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
    // Walk KeyRole::ALL so emit order matches list_keys (consensus then
    // companion). The tz6 key is not generated here: it costs tens of minutes
    // and is provisioned on demand rather than at every first boot.
    let generated = KeyRole::ALL
        .into_iter()
        .map(|role| {
            log::info!(
                "Generating {} key (in memory)...",
                DeviceKey::Bls(role).device_alias()
            );
            provision::Generated::new(provision::Provisioning::Bls(role))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let entries: Vec<provision::Entry<'_>> =
        generated.iter().map(provision::Generated::entry).collect();
    log::info!("Encrypting secret keys...");
    let secret_keys_json = provision::write_store(
        Path::new(russignol_crypto::SECRET_KEYS_ENC_V2_PATH),
        pin,
        &entries,
    )?;
    log::info!("Key store written to disk");

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

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_signer_lib::KeyRole;

    #[test]
    fn a_boot_fault_is_what_the_init_script_recorded_and_none_where_it_recorded_nothing() {
        assert_eq!(boot_fault(None), None);
        assert_eq!(boot_fault(Some("")), None);
        assert_eq!(
            boot_fault(Some("Data partition would not mount.")),
            Some("Data partition would not mount.")
        );
    }

    #[test]
    fn no_mount_check_before_the_partitions_exist() {
        assert_eq!(mount_check(BootStage::NoPartitions, true), None);
        assert_eq!(mount_check(BootStage::NoPartitions, false), None);
    }

    /// An unmounted keys partition has no setup marker in it, so the boot
    /// reads as unmarked, and the check has to run on it regardless.
    #[test]
    fn an_unmarked_boot_is_checked_holding_keys_writable() {
        assert_eq!(mount_check(BootStage::Unmarked, false), Some(true));
        assert_eq!(mount_check(BootStage::Unmarked, true), Some(true));
    }

    #[test]
    fn a_privileged_provisioned_boot_is_checked_holding_keys_writable() {
        assert_eq!(mount_check(BootStage::Provisioned, true), Some(true));
    }

    #[test]
    fn an_unprivileged_provisioned_boot_is_checked_holding_keys_read_only() {
        assert_eq!(mount_check(BootStage::Provisioned, false), Some(false));
    }

    const PIN: &[u8] = b"12345678";

    /// A card as a provisioning boot finds it: a written key store, and the
    /// plaintext the boot holds in memory after the PIN.
    fn card(paths: &provision::Paths, roles: &[KeyRole]) -> Secret<String> {
        let generated: Vec<provision::Generated> = roles
            .iter()
            .map(|role| {
                provision::Generated::new(provision::Provisioning::Bls(*role))
                    .expect("a BLS key generates")
            })
            .collect();
        let entries: Vec<provision::Entry<'_>> =
            generated.iter().map(provision::Generated::entry).collect();
        provision::write_store(paths.store(), PIN, &entries)
            .expect("a store over a writable directory")
    }

    /// A request naming `key`, staged the way the operator's flow stages it:
    /// a request this test wrote itself is one that stays readable after the
    /// writer's own spelling moves.
    fn stage(paths: &provision::Paths, key: DeviceKey) {
        provision::stage_request(paths.request(), key).expect("a writable data partition");
    }

    /// Deny writes to `dir` for the length of `run`, so a write into it fails
    /// the way a read-only keys partition makes it fail on the device.
    fn with_read_only<T>(dir: &std::path::Path, run: impl FnOnce() -> T) -> T {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(dir).unwrap().permissions().mode();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let outcome = run();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
        outcome
    }

    /// The aliases a store names, in the order it holds them.
    fn aliases(store: &str) -> Vec<String> {
        provision::read_store(store)
            .expect("a store this test wrote")
            .into_iter()
            .map(|entry| entry.alias.to_string())
            .collect()
    }

    /// A PIN that does not open the card stages nothing. The request is what
    /// makes the next boot generate a key over the one it replaces, and that
    /// boot asks for no second confirmation.
    #[test]
    fn a_pin_that_does_not_open_the_card_stages_no_request() {
        let keys = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        let paths = provision::Paths::under(data.path(), keys.path());
        let _card = card(&paths, &[KeyRole::Consensus]);

        let refused = stage_request(&paths, b"87654321", DeviceKey::XmssConsensus);

        let Err(reason) = refused else {
            panic!("a wrong PIN must stage nothing")
        };
        assert_eq!(reason, "Invalid PIN");
        assert!(!paths.request().exists(), "a request was staged anyway");
    }

    /// The PIN that opens the card is what stages the request, and the request
    /// names the key the operator picked.
    #[test]
    fn the_cards_own_pin_stages_the_key_it_was_given() {
        let keys = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        let paths = provision::Paths::under(data.path(), keys.path());
        let _card = card(&paths, &[KeyRole::Consensus]);

        stage_request(&paths, PIN, DeviceKey::XmssConsensus).expect("the card's own PIN");

        assert_eq!(
            provision::staged_request(paths.request()).unwrap(),
            Some(DeviceKey::XmssConsensus)
        );
    }

    /// A card that will not read is reported rather than answered with a
    /// refused PIN: the operator would read that as the wrong PIN and try
    /// again against a card no PIN can open.
    #[test]
    fn a_card_that_will_not_read_is_not_a_refused_pin() {
        let keys = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        let paths = provision::Paths::under(data.path(), keys.path());

        let Err(reason) = stage_request(&paths, PIN, DeviceKey::XmssConsensus) else {
            panic!("a card with no store must report")
        };
        assert!(
            reason.contains("would not read"),
            "the reason names the read: {reason}"
        );
        assert!(!paths.request().exists(), "a request was staged anyway");
    }

    /// A run whose request will not clear has still written the card, so the
    /// device serves the keys the card holds rather than the ones it read. The
    /// other order leaves the signer serving a secret no longer on the card,
    /// and every boot after this one repeats the run.
    #[test]
    fn a_run_whose_request_will_not_clear_unlocks_on_the_store_it_wrote() {
        let keys = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        let paths = provision::Paths::under(data.path(), keys.path());
        let before = card(&paths, &[KeyRole::Consensus]);
        stage(&paths, DeviceKey::Bls(KeyRole::Companion));
        let (tx, _rx) = crossbeam_channel::unbounded();

        let event = with_read_only(data.path(), || {
            provision_staged_request(&tx, PIN, before, &paths)
        });

        let AppEvent::KeysProvisioned {
            json,
            key,
            uncleared,
        } = event
        else {
            panic!("a run that wrote the card must answer with what it wrote: {event:?}")
        };
        assert_eq!(key, DeviceKey::Bls(KeyRole::Companion));
        assert_eq!(aliases(&json), vec!["consensus_tz4", "companion_tz4"]);
        assert!(
            paths.request().exists(),
            "the request could not have been cleared"
        );
        assert!(
            uncleared.is_some(),
            "the operator is told the run repeats on the next boot"
        );
    }

    /// The store the run wrote is what the device unlocks on, and the request
    /// is gone so the boot after this one is a normal one.
    #[test]
    fn a_completed_run_clears_its_request_and_unlocks_on_what_it_wrote() {
        let keys = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        let paths = provision::Paths::under(data.path(), keys.path());
        let before = card(&paths, &[KeyRole::Consensus]);
        stage(&paths, DeviceKey::Bls(KeyRole::Companion));
        let (tx, _rx) = crossbeam_channel::unbounded();

        let event = provision_staged_request(&tx, PIN, before, &paths);

        let AppEvent::KeysProvisioned {
            json,
            key,
            uncleared,
        } = event
        else {
            panic!("a completed run must answer with the store it wrote: {event:?}")
        };
        assert_eq!(key, DeviceKey::Bls(KeyRole::Companion));
        assert_eq!(aliases(&json), vec!["consensus_tz4", "companion_tz4"]);
        assert!(!paths.request().exists(), "the request was not cleared");
        assert_eq!(uncleared, None, "nothing was left to report");
    }

    /// A staged request is what makes a boot a provisioning one, so a boot
    /// without one carries the PIN's own outcome forward and unlocks on the
    /// store it read.
    #[test]
    fn a_boot_with_no_request_staged_unlocks_on_the_store_it_read() {
        let keys = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        let paths = provision::Paths::under(data.path(), keys.path());
        let before = card(&paths, &[KeyRole::Consensus]);
        let expected = aliases(&before);
        let (tx, _rx) = crossbeam_channel::unbounded();

        let event = provision_staged_request(&tx, PIN, before, &paths);

        let AppEvent::PinVerified { json, migration } = event else {
            panic!("nothing staged must unlock as a normal boot does: {event:?}")
        };
        assert!(migration.is_none());
        assert_eq!(aliases(&json), expected);
    }

    /// A run that could not write the card leaves the device serving the keys
    /// it read, and takes the request with it: the operator asked for one run,
    /// and a request that survives a failure repeats it on every boot after.
    #[test]
    fn a_failed_run_serves_the_store_it_read_and_clears_its_request() {
        let keys = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        let paths = provision::Paths::under(data.path(), keys.path());
        let before = card(&paths, &[KeyRole::Consensus]);
        let expected = aliases(&before);
        stage(&paths, DeviceKey::Bls(KeyRole::Companion));
        let (tx, _rx) = crossbeam_channel::unbounded();

        let event = with_read_only(keys.path(), || {
            provision_staged_request(&tx, PIN, before, &paths)
        });

        let AppEvent::ProvisionFailed { json, reason } = event else {
            panic!("a run that could not write the card must report: {event:?}")
        };
        assert_eq!(aliases(&json), expected);
        assert!(
            reason.contains("key store"),
            "the reason names what would not be written: {reason}"
        );
        assert!(!paths.request().exists(), "the request was not cleared");
    }

    /// A boot that could neither provision nor clear its request carries both
    /// failures: the second is why the operator sees this run again on the
    /// next boot, and the first is why the card is unchanged.
    #[test]
    fn a_failed_run_whose_request_survives_reports_both() {
        let keys = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        let paths = provision::Paths::under(data.path(), keys.path());
        let before = card(&paths, &[KeyRole::Consensus]);
        stage(&paths, DeviceKey::Bls(KeyRole::Companion));
        let (tx, _rx) = crossbeam_channel::unbounded();

        let event = with_read_only(keys.path(), || {
            with_read_only(data.path(), || {
                provision_staged_request(&tx, PIN, before, &paths)
            })
        });

        let AppEvent::ProvisionFailed { reason, .. } = event else {
            panic!("a run that could not write the card must report: {event:?}")
        };
        assert!(
            reason.contains("key store") && reason.contains("would not clear"),
            "the reason carries both failures: {reason}"
        );
        assert!(
            paths.request().exists(),
            "the request could not have been cleared"
        );
    }

    /// A request naming no key of this device stops the boot and takes the
    /// request with it. Reading it as nothing staged would leave the keys
    /// partition writable on every boot after, with nothing to say why.
    #[test]
    fn a_request_naming_no_device_key_fails_the_boot_and_clears_itself() {
        let keys = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        let paths = provision::Paths::under(data.path(), keys.path());
        let before = card(&paths, &[KeyRole::Consensus]);
        let expected = aliases(&before);
        std::fs::write(paths.request(), "consensus_tz9").unwrap();
        let (tx, _rx) = crossbeam_channel::unbounded();

        let event = provision_staged_request(&tx, PIN, before, &paths);

        let AppEvent::ProvisionFailed { json, reason } = event else {
            panic!("a request naming no device key must report: {event:?}")
        };
        assert_eq!(aliases(&json), expected);
        assert!(
            reason.contains("consensus_tz9"),
            "the reason names what was staged: {reason}"
        );
        assert!(!paths.request().exists(), "the request was not cleared");
    }

    #[test]
    fn recover_gate_truth_table() {
        use BootRecovery::{Consume, ConsumeAndDemote, None};

        // The one posture where consuming a staged config and handing
        // privileges off is safe: a normal boot (setup done), running as root
        // (init kept us privileged for it), with nothing else staged.
        assert_eq!(
            boot_recovery(false, true, StagedWork::None),
            ConsumeAndDemote
        );

        // A provisioning run follows the PIN and writes the keys partition, so
        // that boot keeps root and demotes with the run's own result.
        assert_eq!(
            boot_recovery(false, true, StagedWork::Provisioning),
            Consume
        );

        // Every other posture leaves the staged config alone.
        for staged in [
            StagedWork::None,
            StagedWork::PinMigration,
            StagedWork::Provisioning,
        ] {
            for (first_boot, root) in [(true, true), (false, false), (true, false)] {
                assert_eq!(
                    boot_recovery(first_boot, root, staged),
                    None,
                    "first_boot={first_boot} root={root} staged={staged:?}"
                );
            }
        }
        assert_eq!(boot_recovery(false, true, StagedWork::PinMigration), None);
    }

    /// A PIN migration and a provisioning request can both be staged, and the
    /// migration goes first: it ends in a reboot the request is still staged
    /// for, where running the provisioning first would write a key store the
    /// migration then re-encrypts under a format it is mid-way through.
    #[test]
    fn a_pin_migration_outranks_a_staged_provisioning() {
        assert_eq!(StagedWork::staged(true, true), StagedWork::PinMigration);
        assert_eq!(StagedWork::staged(true, false), StagedWork::PinMigration);
        assert_eq!(StagedWork::staged(false, true), StagedWork::Provisioning);
        assert_eq!(StagedWork::staged(false, false), StagedWork::None);
    }
}
