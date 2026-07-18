use crossbeam_channel::Sender;
use russignol_signer_lib::{ChainId, HighWatermark, signing_activity};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::events::{AppEvent, BackTarget, ConfigPresence};
use crate::secret::Secret;
use crate::setup;
use crate::tezos_encrypt::MigrationEvent;

/// Visible duration for the migration progress page before the device reboots.
const MIGRATION_REBOOT_COUNTDOWN: Duration = Duration::from_secs(5);

/// Exit code that the init script supervisor interprets as "reboot the device".
/// Must stay in sync with the matching constants in
/// `rpi-signer/buildroot-external/rootfs-overlay-dev/etc/init.d/S20russignol`
/// and `rpi-signer/buildroot-external/rootfs-overlay-hardened/init`.
const EXIT_CODE_REBOOT: i32 = 42;

fn push_reboot_progress(message: &str, effects: &mut Vec<Effect>) {
    effects.push(Effect::ShowProgress {
        message: message.into(),
        estimated_duration: Some(MIGRATION_REBOOT_COUNTDOWN),
        modal: true,
        percent: 0,
    });
    effects.push(Effect::Sleep(MIGRATION_REBOOT_COUNTDOWN));
    effects.push(Effect::Exit(EXIT_CODE_REBOOT));
}

/// Show a modal migration-error notice that the user must acknowledge.
/// Nothing else is queued — the dismiss event drives the next step so
/// the renderer never paints the menu over an unread error.
fn push_migration_notice(
    title: &str,
    message: &str,
    json: Secret<String>,
    effects: &mut Vec<Effect>,
) {
    effects.push(Effect::ShowPage(PageSpec::Notice {
        title: title.into(),
        message: message.into(),
        on_dismiss: AppEvent::AcknowledgeMigrationNotice { json },
    }));
}

/// Retained distinct unknown pkhs; the requesting peer is untrusted network
/// input, so alert state must stay fixed-size no matter how many keys it
/// invents.
const UNKNOWN_KEY_CAP: usize = 8;

/// Content of an active unknown-key alert, produced by
/// [`UnknownKeyAlert::active`]. The modal notice message is built from this
/// value as-is; nothing re-derives counts from the underlying state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertContent<'a> {
    /// The most recently retained unknown pkh.
    pub pkh: &'a str,
    /// How many other distinct unknown pkhs are retained.
    pub others: usize,
    /// Whether unknown pkhs beyond the retention cap were seen.
    pub overflow: bool,
}

/// Bounded record of signing requests for keys the device does not hold.
///
/// Retains at most [`UNKNOWN_KEY_CAP`] distinct pkhs for dedup; past the cap
/// only a one-shot overflow marker changes, so between dismissals a flooding
/// peer gets at most cap + 1 repaints no matter how many keys it invents.
#[derive(Debug, Default)]
pub struct UnknownKeyAlert {
    /// Distinct pkhs retained for dedup, in arrival order.
    pkhs: Vec<String>,
    /// Whether unknown pkhs beyond the retention cap were seen.
    overflow: bool,
    /// Whether the alert modal is showing; dismissal hides it without forgetting.
    active: bool,
}

impl UnknownKeyAlert {
    /// Record a requested unknown pkh. Returns true when the alert content
    /// changed in a way worth a repaint: a newly retained pkh, or the first
    /// pkh past the cap. Repeats of retained pkhs and everything after the
    /// overflow flip return false; non-retained pkhs are never stored, so
    /// dedup is lossy past the cap.
    pub fn record(&mut self, pkh: &str) -> bool {
        if self.pkhs.iter().any(|p| p == pkh) {
            return false;
        }
        if self.pkhs.len() < UNKNOWN_KEY_CAP {
            self.pkhs.push(pkh.to_string());
        } else if self.overflow {
            return false;
        } else {
            self.overflow = true;
        }
        self.active = true;
        true
    }

    /// Hide the alert. Retained pkhs and the overflow marker survive, so
    /// acknowledged keys never re-alert while a genuinely new key still does.
    pub fn dismiss(&mut self) {
        self.active = false;
    }

    /// The alert content, when an alert is active.
    pub fn active(&self) -> Option<AlertContent<'_>> {
        if !self.active {
            return None;
        }
        let pkh = self.pkhs.last()?;
        Some(AlertContent {
            pkh,
            others: self.pkhs.len() - 1,
            overflow: self.overflow,
        })
    }
}

/// Title of the unknown-key modal, sized for the notice title band.
const UNKNOWN_KEY_TITLE: &str = "Unknown Key";

/// Fixed guidance naming the problem and the fix. Wraps to two lines in the
/// notice's message font; the pkh line above it plus these two lines fill the
/// three-line message box (`pages::notice::MESSAGE_BOX_HEIGHT`).
const UNKNOWN_KEY_GUIDANCE: &str =
    "This device lacks this key. Fix the baker's signer config and restart it.";

/// Body of the unknown-key modal: the offending pkh truncated head+tail with an
/// ASCII marker, a compact `+N` count when other distinct unknown keys were
/// seen (`+N+` marks the count as a lower bound past the retention cap), then
/// the guidance. The count stays compact so the pkh keeps to one line. All
/// ASCII: the display fonts (`libs/ui/src/fonts.rs`) cover only ISO-8859-1 and
/// have no U+2026 glyph, so truncation uses `crate::text::truncate_middle`.
fn unknown_key_message(content: &AlertContent) -> String {
    let pkh = crate::text::truncate_middle(content.pkh, 8, 6);
    let suffix = match (content.others, content.overflow) {
        (0, false) => String::new(),
        (n, false) => format!(" +{n}"),
        (n, true) => format!(" +{n}+"),
    };
    format!("{pkh}{suffix}\n{UNKNOWN_KEY_GUIDANCE}")
}

/// Policy for the config-presence gate before key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatePolicy {
    /// Refuse key generation unless a valid config is staged. A wrong or absent
    /// watermark floor is a slashing risk, so an unprovisioned card must not
    /// commit key material it can never validly sign from.
    HardFail,
    /// Proceed regardless; the config is consumed post-keygen as before.
    WarnAndContinue,
}

/// Active gate policy. A node-connected flash always stages the config, so a
/// hard gate is invisible on the normal path; it blocks only an offline flash
/// that could not stage one. The `warn-only-gate` build feature selects the
/// warn-and-continue policy for offline-flash images.
const KEYGEN_GATE_POLICY: GatePolicy = if cfg!(feature = "warn-only-gate") {
    GatePolicy::WarnAndContinue
} else {
    GatePolicy::HardFail
};

/// Whether the setup flow may proceed to key generation, given the config-
/// presence check and the gate policy.
fn should_proceed_to_keygen(presence: ConfigPresence, policy: GatePolicy) -> bool {
    match policy {
        GatePolicy::WarnAndContinue => true,
        GatePolicy::HardFail => presence == ConfigPresence::Present,
    }
}

/// Title of the pre-keygen config-gate fatal page.
const CONFIG_GATE_TITLE: &str = "Card Not Ready";

/// Shown when key generation is blocked because no valid watermark config is
/// staged. Directs the operator to provision the card on a node-connected host,
/// the only source of chain id and watermark floor. The fatal page word-wraps,
/// so the text carries no manual line breaks.
const CONFIG_GATE_MESSAGE: &str =
    "No watermark config is staged on this card. Prepare it on the host with: russignol check disk";

/// Maximum failed PIN attempts before lockout
const MAX_FAILED_ATTEMPTS: u32 = 5;
/// Lockout duration after max failed attempts (5 minutes)
const LOCKOUT_DURATION: Duration = Duration::from_mins(5);

/// Application lifecycle state — scopes mutable variables to their lifecycle phase
#[derive(Debug)]
pub enum AppState {
    /// First boot: key generation flow
    Setup { first_pin: Option<Secret<Vec<u8>>> },
    /// Normal boot: PIN verification
    PinEntry {
        failed_attempts: u32,
        lockout_until: Option<Instant>,
    },
    /// Keys decrypted, signer running
    Active { screensaver_active: bool },
    /// Terminal: too many failed PIN attempts
    Locked,
}

/// Loop control returned by event handlers
#[derive(Debug, PartialEq, Eq)]
pub enum LoopAction {
    /// Skip remaining processing, continue loop
    Continue,
    /// Apply effects and exit the loop
    Break,
    /// Apply effects, continue loop (default)
    Proceed,
}

/// Deferred render work for the event loop's single flush site. A push that
/// bails on a busy panel is re-recorded here and retried on a short poll, so
/// the loop never blocks on the panel. Variant order is escalation order: a
/// transition subsumes an in-place repaint, never the reverse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum PendingRender {
    #[default]
    None,
    /// Redraw the current page and push it in place.
    InPlace,
    /// Push with transition policy, where a due anti-ghosting full may land.
    Transition,
}

impl PendingRender {
    pub fn record_invalidate(&mut self) {
        self.record(Self::InPlace);
    }

    pub fn record_transition(&mut self) {
        self.record(Self::Transition);
    }

    /// Merge `kind`, keeping the more demanding of the two.
    fn record(&mut self, kind: Self) {
        *self = (*self).max(kind);
    }

    /// Consume the pending work, leaving none.
    pub fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

/// Identifies which page to show without constructing it
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageSpec {
    PinCreate,
    PinConfirm,
    PinVerify,
    Menu,
    Status,
    Signatures,
    Watermarks,
    Blockchain,
    About,
    Greeting,
    Image {
        back: BackTarget,
    },
    Dialog {
        message: String,
        on_dismiss: AppEvent,
    },
    Confirmation {
        message: String,
        on_confirm: AppEvent,
        on_cancel: AppEvent,
        warning: bool,
        button_text: String,
    },
    ConfirmationWithPairs {
        title: String,
        pairs: Vec<(String, String)>,
        on_confirm: AppEvent,
        on_cancel: AppEvent,
        warning: bool,
        button_text: String,
    },
    Error {
        title: String,
        message: String,
    },
    Notice {
        title: String,
        message: String,
        on_dismiss: AppEvent,
    },
    DeviceLocked,
}

/// Side effects returned by handlers — descriptions of work to be done
#[derive(Debug, PartialEq, Eq)]
pub enum Effect {
    ShowPage(PageSpec),
    ShowProgress {
        message: String,
        estimated_duration: Option<Duration>,
        modal: bool,
        percent: u8,
    },
    WakeDisplay,
    SleepDisplay,
    SleepDevice,
    ClearDisplay,
    Emit(AppEvent),
    SendKeys(Secret<String>),
    InitWatermark {
        context: String,
        /// Decrypted secret keys, used to derive the per-key watermark MAC keys.
        secret_keys: Secret<String>,
    },
    SpawnKeygen {
        pin: Secret<Vec<u8>>,
    },
    SpawnPinVerify {
        pin: Secret<Vec<u8>>,
    },
    SpawnStorageSetup,
    SyncDisk,
    DropPrivileges,
    RemountKeysReadonly,
    WriteSetupMarker,
    SetKeyPermissions,
    ProcessWatermarkConfig,
    ValidateWatermarkConfig,
    VerifyStorage,
    UpdateWatermark {
        pkh: String,
        chain_id: ChainId,
        new_level: u32,
    },
    ResetActivity,
    DropCurrentPage,
    RebuildSavedPage,
    FatalError {
        title: String,
        message: String,
    },
    Exit(i32),
    Sleep(Duration),
}

/// Consolidated application state for the UI event loop
pub struct App {
    pub state: AppState,
    pub current_page_modal: bool,
    pub current_page_spec: Option<PageSpec>,
    pub tx: Sender<AppEvent>,
    pub signing_activity: Arc<Mutex<signing_activity::SigningActivity>>,
    pub start_signer_tx: Sender<Secret<String>>,
    pub watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    /// Floor level staged by a consumed boot-partition config, applied as an
    /// authenticated mark after PIN unlock. `None` once seeded or absent.
    pub pending_watermark_level: Option<u32>,
    /// Signing requests for keys the device does not hold, surfaced as a
    /// modal acknowledge dialog.
    pub unknown_keys: UnknownKeyAlert,
    pub needs_animation: bool,
    pub animation_interval: Duration,
    /// Render work deferred to the loop's flush site; survives loop
    /// iterations when a push bails on a busy panel.
    pub pending_render: PendingRender,
}

impl App {
    pub fn new(
        is_first_boot: bool,
        tx: Sender<AppEvent>,
        signing_activity: Arc<Mutex<signing_activity::SigningActivity>>,
        start_signer_tx: Sender<Secret<String>>,
        watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    ) -> Self {
        let state = if is_first_boot {
            AppState::Setup { first_pin: None }
        } else {
            AppState::PinEntry {
                failed_attempts: 0,
                lockout_until: None,
            }
        };
        Self {
            state,
            current_page_modal: false,
            current_page_spec: None,
            tx,
            signing_activity,
            start_signer_tx,
            watermark,
            pending_watermark_level: None,
            unknown_keys: UnknownKeyAlert::default(),
            needs_animation: false,
            animation_interval: Duration::from_secs(1),
            pending_render: PendingRender::None,
        }
    }

    pub fn is_screensaver_active(&self) -> bool {
        matches!(
            self.state,
            AppState::Active {
                screensaver_active: true,
                ..
            }
        )
    }

    /// Whether an `Invalidate` should redraw the current page. Suppressed only
    /// by the screensaver, which has nothing to repaint. Modals are not
    /// suppressed: an unchanged modal frame dies in the frame diff, not in a
    /// gate, so a signing burst never flashes it.
    pub fn should_repaint_on_invalidate(&self) -> bool {
        !self.is_screensaver_active()
    }

    /// Whether the pending render warrants a flush, evaluated at flush time
    /// against the post-batch state: a mid-batch page change or screensaver
    /// toggle is reflected here, not when the event was recorded. A
    /// transition is never suppressed — it is a real page change that must
    /// land; the screensaver gate only drops repaints of a frame nobody can
    /// see.
    pub fn should_flush_repaint(&self, pending: PendingRender) -> bool {
        match pending {
            PendingRender::None => false,
            PendingRender::InPlace => self.should_repaint_on_invalidate(),
            PendingRender::Transition => true,
        }
    }

    pub fn recv_timeout(&self) -> Duration {
        self.animation_interval
    }

    pub fn set_screensaver(&mut self, active: bool) {
        if let AppState::Active {
            screensaver_active, ..
        } = &mut self.state
        {
            *screensaver_active = active;
        }
    }

    /// Effects to wake a sleeping display without repainting the saved page,
    /// when the screensaver is active. For callers that paint the display
    /// themselves (a `ShowPage` renders its own frame); rebuilding the saved
    /// page first would paint it and then immediately overpaint it, a double
    /// e-paper flash. Waking always restarts the inactivity clock: the
    /// screensaver timer thread parks in `reset_rx.recv()` after firing and
    /// only `Effect::ResetActivity` re-arms it.
    fn wake_without_rebuild_effects(&mut self) -> Vec<Effect> {
        if self.is_screensaver_active() {
            self.set_screensaver(false);
            return vec![Effect::WakeDisplay, Effect::ResetActivity];
        }
        vec![]
    }

    /// Effects to wake a sleeping display and repaint the saved page, when the
    /// screensaver is active. For callers with no frame of their own to paint.
    fn wake_from_screensaver_effects(&mut self) -> Vec<Effect> {
        let mut effects = self.wake_without_rebuild_effects();
        if !effects.is_empty() {
            // Between waking the panel and re-arming the timer: the panel must
            // be awake before the rebuild paints.
            effects.insert(1, Effect::RebuildSavedPage);
        }
        effects
    }

    pub fn handle_event(&mut self, event: AppEvent) -> (LoopAction, Vec<Effect>) {
        match event {
            AppEvent::Shutdown => self.handle_shutdown(),
            AppEvent::FatalError { title, message } => (
                LoopAction::Proceed,
                vec![Effect::FatalError { title, message }],
            ),
            event if matches!(self.state, AppState::Setup { .. }) => self.handle_setup(event),
            event if matches!(self.state, AppState::PinEntry { .. }) => {
                self.handle_pin_entry(event)
            }
            event if matches!(self.state, AppState::Active { .. }) => self.handle_active(event),
            _ => (LoopAction::Continue, vec![]),
        }
    }

    fn handle_shutdown(&self) -> (LoopAction, Vec<Effect>) {
        log::info!("Shutting down UI...");
        let mut effects = vec![Effect::SyncDisk];
        if self.is_screensaver_active() {
            effects.push(Effect::WakeDisplay);
        }
        effects.push(Effect::ClearDisplay);
        effects.push(Effect::SleepDevice);
        (LoopAction::Break, effects)
    }

    fn handle_setup(&mut self, event: AppEvent) -> (LoopAction, Vec<Effect>) {
        // The first-boot greeting can open the Image screen, which returns to
        // it; both go through the shared navigation map. No other navigation
        // targets are reachable before setup completes.
        if matches!(event, AppEvent::ShowImage { .. } | AppEvent::ShowGreeting)
            && let Some(spec) = Self::navigation_page(&event)
        {
            return (LoopAction::Proceed, vec![Effect::ShowPage(spec)]);
        }

        let mut effects = Vec::new();
        match event {
            AppEvent::StartSetup => {
                log::info!("User tapped Begin, starting setup...");
                if setup::needs_storage_setup() {
                    log::info!("Storage setup needed - creating partitions...");
                    effects.push(Effect::ShowProgress {
                        message: "Preparing storage...".into(),
                        estimated_duration: None,
                        modal: false,
                        percent: 0,
                    });
                    effects.push(Effect::SpawnStorageSetup);
                } else {
                    effects.push(Effect::Emit(AppEvent::StorageSetupComplete));
                }
            }
            AppEvent::StorageProgress { message, percent } => {
                effects.push(Effect::ShowProgress {
                    message,
                    estimated_duration: None,
                    modal: false,
                    percent,
                });
            }
            AppEvent::StorageSetupComplete => {
                log::info!("Storage setup complete, verifying partitions and checking config...");
                effects.push(Effect::VerifyStorage);
                effects.push(Effect::ValidateWatermarkConfig);
            }
            AppEvent::WatermarkConfigChecked(presence) => {
                if should_proceed_to_keygen(presence, KEYGEN_GATE_POLICY) {
                    effects.push(Effect::ShowPage(PageSpec::PinCreate));
                } else {
                    log::warn!("Key generation blocked: no valid watermark config staged");
                    // Dead-end for this boot: the card can only be provisioned on
                    // a node-connected host, so end on the button-less fatal page
                    // (the supervisor keeps it visible until power-off).
                    effects.push(Effect::FatalError {
                        title: CONFIG_GATE_TITLE.into(),
                        message: CONFIG_GATE_MESSAGE.into(),
                    });
                }
            }
            AppEvent::StorageSetupFailed(e) => {
                effects.push(Effect::FatalError {
                    title: "STORAGE FAILED".into(),
                    message: e,
                });
            }
            AppEvent::FirstPinEntered(pin) => {
                log::info!("First PIN entered, asking for confirmation");
                if let AppState::Setup { first_pin } = &mut self.state {
                    *first_pin = Some(pin);
                }
                effects.push(Effect::ShowPage(PageSpec::PinConfirm));
            }
            AppEvent::PinMismatch => {
                log::warn!("PINs don't match, restarting PIN entry");
                if let AppState::Setup { first_pin } = &mut self.state {
                    *first_pin = None;
                }
                effects.push(Effect::ShowPage(PageSpec::Error {
                    title: "PIN MISMATCH".into(),
                    message: "PINs don't match. Please try again.".into(),
                }));
                effects.push(Effect::Sleep(Duration::from_secs(2)));
                effects.push(Effect::ShowPage(PageSpec::PinCreate));
            }
            AppEvent::PinEntered(pin) => {
                effects.extend(self.handle_setup_pin_confirm(pin));
            }
            AppEvent::KeyGenSuccess(secret_keys_json) => {
                effects.extend(self.finalize_first_boot(secret_keys_json));
            }
            AppEvent::KeyGenFailed(e) => {
                effects.push(Effect::FatalError {
                    title: "KEY GEN FAILED".into(),
                    message: e,
                });
            }
            _ => {}
        }
        (LoopAction::Proceed, effects)
    }

    /// Complete first-boot setup once keys exist: persist and lock down the
    /// keys, drop to the unprivileged runtime, arm watermarks, and enter the
    /// active state with the decrypted keys handed to the signer.
    fn finalize_first_boot(&mut self, secret_keys_json: Secret<String>) -> Vec<Effect> {
        log::info!("Keys generated and encrypted successfully");
        let mut effects = vec![
            Effect::ProcessWatermarkConfig,
            Effect::WriteSetupMarker,
            Effect::SetKeyPermissions,
            Effect::SyncDisk,
            Effect::RemountKeysReadonly,
            Effect::DropPrivileges,
            Effect::InitWatermark {
                context: "first boot setup".into(),
                secret_keys: secret_keys_json.clone(),
            },
        ];
        self.state = AppState::Active {
            screensaver_active: false,
        };
        effects.push(Effect::Emit(AppEvent::KeysDecrypted(secret_keys_json)));
        effects
    }

    fn handle_setup_pin_confirm(&mut self, pin: Secret<Vec<u8>>) -> Vec<Effect> {
        let AppState::Setup { first_pin } = &mut self.state else {
            return vec![];
        };
        let Some(ref saved) = *first_pin else {
            return vec![];
        };
        if saved.as_slice() == pin.as_slice() {
            log::info!("PINs match, generating keys...");
            *first_pin = None;
            vec![
                Effect::ShowProgress {
                    message: "Generating keys...".into(),
                    estimated_duration: Some(Duration::from_secs(8)),
                    modal: true,
                    percent: 0,
                },
                Effect::SpawnKeygen { pin },
            ]
        } else {
            vec![Effect::Emit(AppEvent::PinMismatch)]
        }
    }

    fn handle_pin_entry(&mut self, event: AppEvent) -> (LoopAction, Vec<Effect>) {
        let mut effects = Vec::new();
        match event {
            AppEvent::PinEntered(pin) => {
                if let AppState::PinEntry {
                    lockout_until,
                    failed_attempts,
                } = &mut self.state
                    && let Some(lockout_time) = lockout_until
                {
                    if Instant::now() < *lockout_time {
                        log::warn!("Device still locked, ignoring PIN entry");
                        effects.push(Effect::Emit(AppEvent::DeviceLocked));
                        return (LoopAction::Proceed, effects);
                    }
                    log::info!("Lockout expired, allowing PIN entry");
                    *lockout_until = None;
                    *failed_attempts = 0;
                }
                effects.push(Effect::ShowProgress {
                    message: "Verifying PIN...".into(),
                    estimated_duration: Some(Duration::from_secs(8)),
                    modal: true,
                    percent: 0,
                });
                effects.push(Effect::SpawnPinVerify { pin });
            }
            AppEvent::PinVerified { json, migration } => {
                log::info!("PIN verified successfully, secret keys decrypted");
                self.dispatch_pin_verified(json, migration, &mut effects);
            }
            AppEvent::PinVerifyProgress {
                message,
                estimated_duration,
            } => {
                effects.push(Effect::ShowProgress {
                    message,
                    estimated_duration: Some(estimated_duration),
                    modal: true,
                    percent: 0,
                });
            }
            AppEvent::AcknowledgeMigrationNotice { json } => {
                log::info!("Migration notice acknowledged; demoting and proceeding to active");
                self.proceed_to_active(json, true, &mut effects);
            }
            AppEvent::PinVerificationFailed => {
                log::info!("PinVerificationFailed, delegating to InvalidPinEntered");
                effects.push(Effect::Emit(AppEvent::InvalidPinEntered));
            }
            AppEvent::InvalidPinEntered => {
                if let AppState::PinEntry {
                    failed_attempts,
                    lockout_until,
                } = &mut self.state
                {
                    *failed_attempts += 1;
                    log::warn!(
                        "Failed PIN attempt {} of {MAX_FAILED_ATTEMPTS}",
                        *failed_attempts
                    );
                    if *failed_attempts >= MAX_FAILED_ATTEMPTS {
                        *lockout_until = Some(Instant::now() + LOCKOUT_DURATION);
                        log::error!(
                            "Maximum PIN attempts exceeded, device locked for {} seconds",
                            LOCKOUT_DURATION.as_secs()
                        );
                        effects.push(Effect::Emit(AppEvent::DeviceLocked));
                        return (LoopAction::Proceed, effects);
                    }
                    let remaining = MAX_FAILED_ATTEMPTS - *failed_attempts;
                    let message: &str = match remaining {
                        1 => "Invalid PIN\n1 attempt left",
                        2 => "Invalid PIN\n2 attempts left",
                        _ => "Invalid PIN",
                    };
                    effects.push(Effect::ShowPage(PageSpec::Dialog {
                        message: message.into(),
                        on_dismiss: AppEvent::EnterPin,
                    }));
                }
            }
            AppEvent::EnterPin => {
                effects.push(Effect::ShowPage(PageSpec::PinVerify));
            }
            AppEvent::DeviceLocked => {
                log::error!("Device locked due to too many failed PIN attempts");
                self.state = AppState::Locked;
                effects.push(Effect::ShowPage(PageSpec::DeviceLocked));
                effects.push(Effect::Exit(1));
            }
            _ => {}
        }
        (LoopAction::Proceed, effects)
    }

    fn dispatch_pin_verified(
        &mut self,
        json: Secret<String>,
        migration: Option<MigrationEvent>,
        effects: &mut Vec<Effect>,
    ) {
        match migration {
            None => self.proceed_to_active(json, false, effects),
            Some(MigrationEvent::StagedV2) => {
                log::info!("PIN upgrade staged; rebooting to verify-and-promote");
                effects.extend([
                    Effect::SetKeyPermissions,
                    Effect::SyncDisk,
                    Effect::RemountKeysReadonly,
                    Effect::DropPrivileges,
                ]);
                push_reboot_progress("Upgrade staged, rebooting...", effects);
            }
            Some(MigrationEvent::PromotedV2) => {
                log::info!("PIN upgrade complete; demoting to russignol in-process");
                self.proceed_to_active(json, true, effects);
            }
            Some(MigrationEvent::RevertedFromCorruptV2 { reason }) => {
                log::warn!("PIN upgrade reverted from corrupt v2: {reason}");
                push_migration_notice(
                    "PIN UPGRADE FAILED",
                    &format!("Reverted to legacy format.\n{reason}"),
                    json,
                    effects,
                );
            }
            Some(MigrationEvent::StagingFailed { reason }) => {
                log::warn!("PIN upgrade staging failed: {reason}");
                push_migration_notice(
                    "PIN UPGRADE FAILED",
                    &format!("Could not stage v2 blob.\n{reason}"),
                    json,
                    effects,
                );
            }
            Some(MigrationEvent::MigrationDisabled { attempts }) => {
                log::error!(
                    "Migration disabled after {attempts} attempts; device unlocked on legacy format"
                );
                push_migration_notice(
                    "MIGRATION DISABLED",
                    &format!("{attempts} attempts; re-image device.\nUnlocking on legacy format."),
                    json,
                    effects,
                );
            }
        }
    }

    /// Transition to Active and queue the unlock effects. When `demote` is
    /// true the signer is currently running as root (migration boot ack
    /// path) and must hand off privileges before going active: chown/chmod
    /// the canonical, sync, remount /keys ro, drop to russignol. Steady-
    /// state unlocks (no migration) come up as russignol already and skip
    /// the demote sequence.
    fn proceed_to_active(&mut self, json: Secret<String>, demote: bool, effects: &mut Vec<Effect>) {
        self.state = AppState::Active {
            screensaver_active: false,
        };
        if demote {
            effects.extend([
                Effect::SetKeyPermissions,
                Effect::SyncDisk,
                Effect::RemountKeysReadonly,
                Effect::DropPrivileges,
            ]);
        }
        effects.push(Effect::InitWatermark {
            context: "PIN entry".into(),
            secret_keys: json.clone(),
        });
        effects.push(Effect::Emit(AppEvent::KeysDecrypted(json)));
    }

    /// Page opened by a modal-guarded navigation event, if this event is one.
    fn navigation_page(event: &AppEvent) -> Option<PageSpec> {
        match event {
            AppEvent::ShowStatus => Some(PageSpec::Status),
            AppEvent::ShowSignatures => Some(PageSpec::Signatures),
            AppEvent::ShowWatermarks => Some(PageSpec::Watermarks),
            AppEvent::ShowBlockchain => Some(PageSpec::Blockchain),
            AppEvent::ShowAbout => Some(PageSpec::About),
            AppEvent::ShowGreeting => Some(PageSpec::Greeting),
            AppEvent::ShowImage { back } => Some(PageSpec::Image { back: *back }),
            _ => None,
        }
    }

    fn handle_active(&mut self, event: AppEvent) -> (LoopAction, Vec<Effect>) {
        if !self.current_page_modal
            && let Some(spec) = Self::navigation_page(&event)
        {
            return (LoopAction::Proceed, vec![Effect::ShowPage(spec)]);
        }

        let mut effects = Vec::new();
        match event {
            AppEvent::KeysDecrypted(secret_keys_json) => {
                effects.extend([
                    Effect::SendKeys(secret_keys_json),
                    Effect::ShowPage(PageSpec::Menu),
                    Effect::ResetActivity,
                ]);
            }
            AppEvent::ActivateScreensaver => {
                if self.current_page_modal || self.is_screensaver_active() {
                    return (LoopAction::Continue, vec![]);
                }
                self.set_screensaver(true);
                effects.extend([Effect::DropCurrentPage, Effect::SleepDisplay]);
            }
            AppEvent::DeactivateScreensaver if self.is_screensaver_active() => {
                log::info!("Deactivating screensaver");
                effects.extend(self.wake_from_screensaver_effects());
            }
            AppEvent::WatermarkError {
                pkh,
                chain_id,
                error_message,
                current_level,
                requested_level,
            } if !self.current_page_modal => {
                effects.extend(self.watermark_error_effects(
                    pkh,
                    chain_id,
                    &error_message,
                    current_level,
                    requested_level,
                ));
            }
            AppEvent::LargeWatermarkGap {
                pkh,
                chain_id,
                current_level,
                requested_level,
            } if !self.current_page_modal => {
                effects.extend(self.large_watermark_gap_effects(
                    pkh,
                    chain_id,
                    current_level,
                    requested_level,
                ));
            }
            AppEvent::WatermarkMissing {
                pkh,
                chain_id,
                requested_level,
            } if !self.current_page_modal => {
                effects.extend(self.watermark_missing_effects(pkh, chain_id, requested_level));
            }
            AppEvent::UnknownKeyRequested { pkh } => {
                effects.extend(self.unknown_key_requested_effects(&pkh));
            }
            AppEvent::UnknownKeyDismissed => {
                self.unknown_keys.dismiss();
                effects.push(Effect::ShowPage(PageSpec::Menu));
            }
            AppEvent::UpdateWatermarkToLevel {
                pkh,
                chain_id,
                new_level,
            } => {
                effects.push(Effect::UpdateWatermark {
                    pkh,
                    chain_id,
                    new_level,
                });
            }
            AppEvent::WatermarkUpdateSuccess | AppEvent::DialogDismissed | AppEvent::ShowMenu => {
                effects.push(Effect::ShowPage(PageSpec::Menu));
            }
            AppEvent::RequestShutdown => {
                effects.push(Effect::ShowPage(PageSpec::Confirmation {
                    message: "Shutdown the device?".into(),
                    on_confirm: AppEvent::Shutdown,
                    on_cancel: AppEvent::ShowMenu,
                    warning: false,
                    button_text: "Shutdown".into(),
                }));
            }
            _ => {}
        }
        (LoopAction::Proceed, effects)
    }

    /// Record an unknown-key request and, when it is newly retained, raise a
    /// modal acknowledge dialog naming the pkh. Repaints are bounded by
    /// [`UnknownKeyAlert::record`].
    ///
    /// Guard before record: a request arriving while any modal is up is neither
    /// recorded nor shown, so the untrusted peer can never stack a page over an
    /// open dialog. The misconfigured baker repeats the request every block, so
    /// the alert self-corrects once the blocking modal clears.
    fn unknown_key_requested_effects(&mut self, pkh: &str) -> Vec<Effect> {
        if self.current_page_modal {
            return vec![];
        }
        if !self.unknown_keys.record(pkh) {
            return vec![];
        }
        log::warn!(
            "Signing request for unknown key {pkh}: the baker is signing for keys this device does not hold"
        );
        let message = self
            .unknown_keys
            .active()
            .map(|content| unknown_key_message(&content))
            .expect("record returned true, so the alert is active");
        let mut effects = self.wake_without_rebuild_effects();
        effects.push(Effect::ShowPage(PageSpec::Notice {
            title: UNKNOWN_KEY_TITLE.into(),
            message,
            on_dismiss: AppEvent::UnknownKeyDismissed,
        }));
        effects
    }

    fn watermark_error_effects(
        &mut self,
        pkh: String,
        chain_id: ChainId,
        error_message: &str,
        current_level: Option<u32>,
        requested_level: Option<u32>,
    ) -> Vec<Effect> {
        let (Some(current), Some(requested)) = (current_level, requested_level) else {
            log::info!("Non-destructive watermark error (no dialog): {error_message}");
            return vec![];
        };
        let mut effects = self.wake_from_screensaver_effects();
        let chain_short = crate::text::truncate_middle(&chain_id.to_b58check(), 12, 0);
        effects.push(Effect::ShowPage(PageSpec::Confirmation {
            message: format!(
                "Watermark test failed.\nChain: {chain_short}\nCurrent level: {current}"
            ),
            on_confirm: AppEvent::UpdateWatermarkToLevel {
                pkh,
                chain_id,
                new_level: requested,
            },
            on_cancel: AppEvent::DialogDismissed,
            warning: true,
            button_text: format!("Set level to {requested}"),
        }));
        effects
    }

    fn large_watermark_gap_effects(
        &mut self,
        pkh: String,
        chain_id: ChainId,
        current_level: u32,
        requested_level: u32,
    ) -> Vec<Effect> {
        let mut effects = self.wake_from_screensaver_effects();
        let gap = requested_level.saturating_sub(current_level);
        log::warn!(
            "Large level gap detected: {gap} blocks (current: {current_level}, requested: {requested_level})"
        );
        effects.push(Effect::ShowPage(PageSpec::ConfirmationWithPairs {
            title: "Stale watermark.".into(),
            pairs: vec![
                ("Current:".into(), current_level.to_string()),
                ("Requested:".into(), requested_level.to_string()),
                ("Gap:".into(), format!("{gap} blocks")),
            ],
            on_confirm: AppEvent::UpdateWatermarkToLevel {
                pkh,
                chain_id,
                new_level: requested_level,
            },
            on_cancel: AppEvent::DialogDismissed,
            warning: true,
            button_text: format!("Update to {requested_level}"),
        }));
        effects
    }

    fn watermark_missing_effects(
        &mut self,
        pkh: String,
        chain_id: ChainId,
        requested_level: u32,
    ) -> Vec<Effect> {
        let mut effects = self.wake_from_screensaver_effects();
        log::warn!("Missing watermark for {pkh}: offering recovery to level {requested_level}");
        let pkh_short = crate::text::truncate_middle(&pkh, 6, 0);
        effects.push(Effect::ShowPage(PageSpec::Confirmation {
            // The requested level rides on the confirm button ("Set level to
            // N"), not here: with it the message overflows the page's three
            // wrapped rows and the text box clips the overflow.
            message: format!(
                "No watermark: {pkh_short}\nOr run russignol check disk then reboot on host."
            ),
            on_confirm: AppEvent::UpdateWatermarkToLevel {
                pkh,
                chain_id,
                new_level: requested_level,
            },
            on_cancel: AppEvent::DialogDismissed,
            warning: true,
            button_text: format!("Set level to {requested_level}"),
        }));
        effects
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chain_id() -> ChainId {
        ChainId::from_bytes(&[0u8; 32])
    }

    fn test_app(is_first_boot: bool) -> App {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let (signer_tx, _signer_rx) = crossbeam_channel::bounded(1);
        App::new(
            is_first_boot,
            tx,
            Arc::new(Mutex::new(signing_activity::SigningActivity::default())),
            signer_tx,
            Arc::new(RwLock::new(None)),
        )
    }

    fn first_boot_app() -> App {
        test_app(true)
    }

    fn normal_boot_app() -> App {
        test_app(false)
    }

    fn active_app() -> App {
        let mut app = test_app(false);
        app.state = AppState::Active {
            screensaver_active: false,
        };
        app
    }

    fn active_screensaver_app() -> App {
        let mut app = active_app();
        app.set_screensaver(true);
        app
    }

    fn has_effect(effects: &[Effect], expected: &Effect) -> bool {
        effects.iter().any(|e| e == expected)
    }

    /// Lookup wrapper so ordering assertions read like `set_perms < drop_priv`
    /// instead of unwrapping `.iter().position(...)` at every call site.
    struct EffectPositions<'a>(&'a [Effect]);

    impl EffectPositions<'_> {
        fn position_of(&self, expected: &Effect) -> usize {
            self.0
                .iter()
                .position(|e| e == expected)
                .unwrap_or_else(|| panic!("effect {expected:?} not present in {:?}", self.0))
        }
    }

    fn effect_positions(effects: &[Effect]) -> EffectPositions<'_> {
        EffectPositions(effects)
    }

    fn has_show_page(effects: &[Effect], spec: &PageSpec) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::ShowPage(s) if s == spec))
    }

    fn pin(bytes: &[u8]) -> Secret<Vec<u8>> {
        Secret::new(bytes.to_vec())
    }

    fn json(s: &str) -> Secret<String> {
        Secret::new(s.to_string())
    }

    // === State transition tests ===

    #[test]
    fn setup_storage_complete_validates_config_before_pin() {
        let mut app = first_boot_app();
        let (action, effects) = app.handle_event(AppEvent::StorageSetupComplete);
        assert_eq!(action, LoopAction::Proceed);
        assert!(
            has_effect(&effects, &Effect::ValidateWatermarkConfig),
            "storage completion must trigger the config-presence check"
        );
        assert!(
            !has_show_page(&effects, &PageSpec::PinCreate),
            "PIN creation must wait for the config check, not fire on storage completion"
        );
    }

    #[test]
    fn config_present_proceeds_to_pin_create() {
        let mut app = first_boot_app();
        let (_action, effects) =
            app.handle_event(AppEvent::WatermarkConfigChecked(ConfigPresence::Present));
        assert!(has_show_page(&effects, &PageSpec::PinCreate));
    }

    /// The gate ends the boot on the button-less fatal-error page — a
    /// dismissable notice would pretend the dead-end is interactive.
    fn assert_config_gate_is_fatal(effects: &[Effect]) {
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::FatalError { title, message }
                    if title == CONFIG_GATE_TITLE && message == CONFIG_GATE_MESSAGE
            )),
            "a blocked config check must end the boot on the fatal-error page"
        );
        assert!(
            notice_message(effects).is_none(),
            "the dead-end must not be presented as a dismissable notice"
        );
        assert!(
            !has_show_page(effects, &PageSpec::PinCreate),
            "a blocked card must never reach PIN creation"
        );
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::SpawnKeygen { .. })),
            "a blocked card must never spawn keygen"
        );
    }

    #[test]
    fn config_missing_blocks_keygen_fatally() {
        let mut app = first_boot_app();
        let (_action, effects) =
            app.handle_event(AppEvent::WatermarkConfigChecked(ConfigPresence::Missing));
        assert_config_gate_is_fatal(&effects);
    }

    #[test]
    fn config_invalid_blocks_keygen_fatally() {
        let mut app = first_boot_app();
        let (_action, effects) =
            app.handle_event(AppEvent::WatermarkConfigChecked(ConfigPresence::Invalid));
        assert_config_gate_is_fatal(&effects);
    }

    #[test]
    fn keygen_gate_truth_table() {
        use ConfigPresence::*;
        use GatePolicy::*;
        // Hard-fail: only a present, valid config proceeds to keygen.
        assert!(should_proceed_to_keygen(Present, HardFail));
        assert!(!should_proceed_to_keygen(Missing, HardFail));
        assert!(!should_proceed_to_keygen(Invalid, HardFail));
        // Warn-and-continue: never blocks.
        assert!(should_proceed_to_keygen(Present, WarnAndContinue));
        assert!(should_proceed_to_keygen(Missing, WarnAndContinue));
        assert!(should_proceed_to_keygen(Invalid, WarnAndContinue));
    }

    #[test]
    fn keygen_success_transitions_setup_to_active() {
        let mut app = first_boot_app();
        let (_action, _effects) = app.handle_event(AppEvent::KeyGenSuccess(json("{}")));
        assert!(matches!(app.state, AppState::Active { .. }));
    }

    #[test]
    fn pin_verified_no_migration_transitions_pin_entry_to_active() {
        let mut app = normal_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::PinVerified {
            json: json("{}"),
            migration: None,
        });
        assert!(matches!(app.state, AppState::Active { .. }));
        assert!(
            !has_effect(&effects, &Effect::SetKeyPermissions),
            "steady-state unlock must not re-chmod keys (boot came up as russignol)"
        );
        assert!(
            !has_effect(&effects, &Effect::DropPrivileges),
            "steady-state unlock must not drop privileges (boot came up as russignol)"
        );
        assert!(
            !has_effect(&effects, &Effect::RemountKeysReadonly),
            "steady-state unlock must not remount /keys (init already remounted ro)"
        );
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::InitWatermark { .. }))
        );
        assert!(has_effect(
            &effects,
            &Effect::Emit(AppEvent::KeysDecrypted(json("{}")))
        ));
    }

    #[test]
    fn pin_verified_staged_v2_shows_progress_and_exits_for_reboot() {
        let mut app = normal_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::PinVerified {
            json: json("{}"),
            migration: Some(MigrationEvent::StagedV2),
        });
        let positions = effect_positions(&effects);
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::ShowProgress { .. })),
            "expected ShowProgress for STAGED"
        );
        assert!(
            has_effect(&effects, &Effect::Sleep(MIGRATION_REBOOT_COUNTDOWN)),
            "expected Sleep before exit"
        );
        assert!(
            has_effect(&effects, &Effect::Exit(EXIT_CODE_REBOOT)),
            "expected Exit(42) for reboot"
        );
        let set_perms = positions.position_of(&Effect::SetKeyPermissions);
        let sync = positions.position_of(&Effect::SyncDisk);
        let remount = positions.position_of(&Effect::RemountKeysReadonly);
        let drop_priv = positions.position_of(&Effect::DropPrivileges);
        let progress = effects
            .iter()
            .position(|e| matches!(e, Effect::ShowProgress { .. }))
            .expect("ShowProgress present");
        let sleep = positions.position_of(&Effect::Sleep(MIGRATION_REBOOT_COUNTDOWN));
        let exit = positions.position_of(&Effect::Exit(EXIT_CODE_REBOOT));
        assert!(
            set_perms < sync
                && sync < remount
                && remount < drop_priv
                && drop_priv < progress
                && progress < sleep
                && sleep < exit,
            "expected SetKeyPermissions < SyncDisk < RemountKeysReadonly < DropPrivileges < ShowProgress < Sleep < Exit(42), got {set_perms} < {sync} < {remount} < {drop_priv} < {progress} < {sleep} < {exit}"
        );
        assert!(
            !matches!(app.state, AppState::Active { .. }),
            "state should not transition to Active before reboot"
        );
    }

    #[test]
    fn pin_verified_promoted_v2_proceeds_active_with_demote() {
        let mut app = normal_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::PinVerified {
            json: json("secrets"),
            migration: Some(MigrationEvent::PromotedV2),
        });
        let positions = effect_positions(&effects);
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::ShowProgress { .. })),
            "PromotedV2 must not show a reboot progress page"
        );
        assert!(
            !has_effect(&effects, &Effect::Sleep(MIGRATION_REBOOT_COUNTDOWN)),
            "PromotedV2 must not sleep for a reboot countdown"
        );
        assert!(
            !has_effect(&effects, &Effect::Exit(EXIT_CODE_REBOOT)),
            "PromotedV2 must not exit for reboot — demote happens in-process"
        );
        let set_perms = positions.position_of(&Effect::SetKeyPermissions);
        let sync = positions.position_of(&Effect::SyncDisk);
        let remount = positions.position_of(&Effect::RemountKeysReadonly);
        let drop_priv = positions.position_of(&Effect::DropPrivileges);
        assert!(
            set_perms < sync && sync < remount && remount < drop_priv,
            "expected SetKeyPermissions < SyncDisk < RemountKeysReadonly < DropPrivileges (got {set_perms} < {sync} < {remount} < {drop_priv})"
        );
        assert!(
            matches!(
                app.state,
                AppState::Active {
                    screensaver_active: false
                }
            ),
            "PromotedV2 transitions directly to Active"
        );
        assert!(
            has_effect(
                &effects,
                &Effect::Emit(AppEvent::KeysDecrypted(json("secrets")))
            ),
            "expected KeysDecrypted carrying the plaintext"
        );
    }

    #[test]
    fn pin_verified_reverted_shows_notice_and_waits_for_ack() {
        let mut app = normal_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::PinVerified {
            json: json("secrets"),
            migration: Some(MigrationEvent::RevertedFromCorruptV2 {
                reason: "test".into(),
            }),
        });
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::ShowPage(PageSpec::Notice { title, on_dismiss, .. })
                    if title == "PIN UPGRADE FAILED"
                        && matches!(
                            on_dismiss,
                            AppEvent::AcknowledgeMigrationNotice { json } if json.as_str() == "secrets"
                        )
            )),
            "expected Notice page titled PIN UPGRADE FAILED with ack carrier"
        );
        assert!(
            !has_effect(&effects, &Effect::Exit(EXIT_CODE_REBOOT)),
            "no reboot for revert"
        );
        assert!(
            !matches!(app.state, AppState::Active { .. }),
            "must stay in PinEntry until notice is acknowledged"
        );
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::Emit(AppEvent::KeysDecrypted(_)))),
            "KeysDecrypted must not fire before acknowledgment"
        );
        assert!(
            !has_effect(&effects, &Effect::DropPrivileges),
            "DropPrivileges must wait until acknowledgment so the notice renders as root"
        );
        assert!(
            !has_effect(&effects, &Effect::RemountKeysReadonly),
            "RemountKeysReadonly must wait until acknowledgment"
        );
    }

    #[test]
    fn pin_verified_staging_failed_shows_notice_and_waits_for_ack() {
        let mut app = normal_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::PinVerified {
            json: json("secrets"),
            migration: Some(MigrationEvent::StagingFailed {
                reason: "EROFS".into(),
            }),
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::ShowPage(PageSpec::Notice { title, .. }) if title == "PIN UPGRADE FAILED"
        )));
        assert!(!has_effect(&effects, &Effect::Exit(EXIT_CODE_REBOOT)));
        assert!(!matches!(app.state, AppState::Active { .. }));
        assert!(!has_effect(&effects, &Effect::DropPrivileges));
        assert!(!has_effect(&effects, &Effect::RemountKeysReadonly));
    }

    #[test]
    fn pin_verified_migration_disabled_shows_notice_and_waits_for_ack() {
        let mut app = normal_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::PinVerified {
            json: json("secrets"),
            migration: Some(MigrationEvent::MigrationDisabled { attempts: 4 }),
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::ShowPage(PageSpec::Notice { title, .. }) if title == "MIGRATION DISABLED"
        )));
        assert!(!has_effect(&effects, &Effect::Exit(EXIT_CODE_REBOOT)));
        assert!(!matches!(app.state, AppState::Active { .. }));
        assert!(!has_effect(&effects, &Effect::DropPrivileges));
        assert!(!has_effect(&effects, &Effect::RemountKeysReadonly));
    }

    #[test]
    fn acknowledge_migration_notice_proceeds_to_active() {
        let mut app = normal_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::AcknowledgeMigrationNotice {
            json: json("secrets"),
        });
        assert!(matches!(app.state, AppState::Active { .. }));
        assert!(has_effect(
            &effects,
            &Effect::Emit(AppEvent::KeysDecrypted(json("secrets")))
        ));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::InitWatermark { .. }))
        );
        let positions = effect_positions(&effects);
        let set_perms = positions.position_of(&Effect::SetKeyPermissions);
        let sync = positions.position_of(&Effect::SyncDisk);
        let remount = positions.position_of(&Effect::RemountKeysReadonly);
        let drop_priv = positions.position_of(&Effect::DropPrivileges);
        let init_wm = effects
            .iter()
            .position(|e| matches!(e, Effect::InitWatermark { .. }))
            .expect("InitWatermark present");
        let keys_decrypted =
            positions.position_of(&Effect::Emit(AppEvent::KeysDecrypted(json("secrets"))));
        assert!(
            set_perms < sync
                && sync < remount
                && remount < drop_priv
                && drop_priv < init_wm
                && init_wm < keys_decrypted,
            "expected SetKeyPermissions < SyncDisk < RemountKeysReadonly < DropPrivileges < InitWatermark < KeysDecrypted (got {set_perms} < {sync} < {remount} < {drop_priv} < {init_wm} < {keys_decrypted})"
        );
    }

    #[test]
    fn device_locked_transitions_pin_entry_to_locked() {
        let mut app = normal_boot_app();
        let (_action, _effects) = app.handle_event(AppEvent::DeviceLocked);
        assert!(matches!(app.state, AppState::Locked));
    }

    // === Event routing tests ===

    #[test]
    fn events_for_wrong_state_are_ignored() {
        let mut app = first_boot_app();
        // WatermarkUpdateSuccess is for Active state, should produce no effects in Setup
        let (_action, effects) = app.handle_event(AppEvent::WatermarkUpdateSuccess);
        assert!(effects.is_empty());
    }

    #[test]
    fn pin_entered_in_setup_with_first_pin_confirms() {
        let mut app = first_boot_app();
        // Set first_pin
        app.handle_event(AppEvent::FirstPinEntered(pin(&[1, 2, 3, 4])));
        // Now confirm with same PIN
        let (_action, effects) = app.handle_event(AppEvent::PinEntered(pin(&[1, 2, 3, 4])));
        assert!(has_effect(
            &effects,
            &Effect::SpawnKeygen {
                pin: pin(&[1, 2, 3, 4])
            }
        ));
    }

    #[test]
    fn pin_entered_in_setup_with_mismatch_emits_pin_mismatch() {
        let mut app = first_boot_app();
        app.handle_event(AppEvent::FirstPinEntered(pin(&[1, 2, 3, 4])));
        let (_action, effects) = app.handle_event(AppEvent::PinEntered(pin(&[5, 6, 7, 8])));
        assert!(has_effect(&effects, &Effect::Emit(AppEvent::PinMismatch)));
    }

    #[test]
    fn pin_entered_in_pin_entry_verifies() {
        let mut app = normal_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::PinEntered(pin(&[1, 2, 3, 4])));
        assert!(has_effect(
            &effects,
            &Effect::SpawnPinVerify {
                pin: pin(&[1, 2, 3, 4])
            }
        ));
    }

    #[test]
    fn pin_verification_failed_emits_invalid_pin() {
        let mut app = normal_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::PinVerificationFailed);
        assert!(has_effect(
            &effects,
            &Effect::Emit(AppEvent::InvalidPinEntered)
        ));
    }

    // === PIN lockout tests ===

    #[test]
    fn invalid_pin_increments_failed_attempts() {
        let mut app = normal_boot_app();
        app.handle_event(AppEvent::InvalidPinEntered);
        if let AppState::PinEntry {
            failed_attempts, ..
        } = &app.state
        {
            assert_eq!(*failed_attempts, 1);
        } else {
            panic!("Expected PinEntry state");
        }
    }

    #[test]
    fn fifth_invalid_pin_emits_device_locked() {
        let mut app = normal_boot_app();
        for _ in 0..4 {
            app.handle_event(AppEvent::InvalidPinEntered);
        }
        let (_action, effects) = app.handle_event(AppEvent::InvalidPinEntered);
        assert!(has_effect(&effects, &Effect::Emit(AppEvent::DeviceLocked)));
    }

    #[test]
    fn remaining_attempts_message_shows_count() {
        let mut app = normal_boot_app();
        // 3 failures → 2 attempts left
        for _ in 0..3 {
            app.handle_event(AppEvent::InvalidPinEntered);
        }
        let (_action, effects) = app.handle_event(AppEvent::InvalidPinEntered);
        assert!(has_show_page(
            &effects,
            &PageSpec::Dialog {
                message: "Invalid PIN\n1 attempt left".into(),
                on_dismiss: AppEvent::EnterPin,
            }
        ));
    }

    #[test]
    fn two_attempts_left_message() {
        let mut app = normal_boot_app();
        for _ in 0..2 {
            app.handle_event(AppEvent::InvalidPinEntered);
        }
        let (_action, effects) = app.handle_event(AppEvent::InvalidPinEntered);
        assert!(has_show_page(
            &effects,
            &PageSpec::Dialog {
                message: "Invalid PIN\n2 attempts left".into(),
                on_dismiss: AppEvent::EnterPin,
            }
        ));
    }

    // === Modal guard tests ===

    #[test]
    fn watermark_error_when_modal_produces_no_effects() {
        let mut app = active_app();
        app.current_page_modal = true;
        let (_action, effects) = app.handle_event(AppEvent::WatermarkError {
            pkh: "tz4test".into(),
            chain_id: test_chain_id(),
            error_message: "test".into(),
            current_level: Some(100),
            requested_level: Some(50),
        });
        assert!(effects.is_empty());
    }

    #[test]
    fn large_watermark_gap_when_modal_produces_no_effects() {
        let mut app = active_app();
        app.current_page_modal = true;
        let (_action, effects) = app.handle_event(AppEvent::LargeWatermarkGap {
            pkh: "tz4test".into(),
            chain_id: test_chain_id(),
            current_level: 100,
            requested_level: 200,
        });
        assert!(effects.is_empty());
    }

    #[test]
    fn show_status_when_modal_produces_no_effects() {
        let mut app = active_app();
        app.current_page_modal = true;
        let (_action, effects) = app.handle_event(AppEvent::ShowStatus);
        assert!(effects.is_empty());
    }

    #[test]
    fn activate_screensaver_when_modal_is_ignored() {
        let mut app = active_app();
        app.current_page_modal = true;
        let (action, effects) = app.handle_event(AppEvent::ActivateScreensaver);
        assert_eq!(action, LoopAction::Continue);
        assert!(effects.is_empty());
    }

    // === Invalidate repaint gate ===

    #[test]
    fn invalidate_repaints_non_modal_page() {
        let app = active_app();
        assert!(
            app.should_repaint_on_invalidate(),
            "an invalidate must redraw a non-modal page"
        );
    }

    #[test]
    fn invalidate_repaints_while_modal() {
        let mut app = active_app();
        app.current_page_modal = true;
        assert!(
            app.should_repaint_on_invalidate(),
            "a modal page must still redraw; an unchanged frame dies in the diff"
        );
    }

    #[test]
    fn invalidate_suppressed_during_screensaver() {
        let app = active_screensaver_app();
        assert!(
            !app.should_repaint_on_invalidate(),
            "screensaver has nothing to repaint"
        );
    }

    // === PendingRender ===

    #[test]
    fn pending_render_records_invalidate_as_in_place() {
        let mut pending = PendingRender::None;
        pending.record_invalidate();
        assert_eq!(pending, PendingRender::InPlace);
        pending.record_invalidate();
        assert_eq!(pending, PendingRender::InPlace, "repeats must merge");
    }

    #[test]
    fn pending_render_records_transition() {
        let mut pending = PendingRender::None;
        pending.record_transition();
        assert_eq!(pending, PendingRender::Transition);
    }

    #[test]
    fn pending_render_transition_upgrades_in_place() {
        let mut pending = PendingRender::None;
        pending.record_invalidate();
        pending.record_transition();
        assert_eq!(
            pending,
            PendingRender::Transition,
            "a transition subsumes an in-place repaint"
        );
    }

    #[test]
    fn pending_render_invalidate_never_downgrades_transition() {
        let mut pending = PendingRender::Transition;
        pending.record_invalidate();
        assert_eq!(
            pending,
            PendingRender::Transition,
            "an invalidate must not downgrade a pending transition"
        );
    }

    #[test]
    fn pending_render_take_drains() {
        let mut pending = PendingRender::None;
        pending.record_invalidate();
        assert_eq!(pending.take(), PendingRender::InPlace);
        assert_eq!(pending, PendingRender::None);
    }

    // === Flush predicate ===

    #[test]
    fn flush_repaint_table() {
        use PendingRender::{InPlace, None as NoPending, Transition};
        let modal_app = || {
            let mut app = active_app();
            app.current_page_modal = true;
            app
        };
        let cases: &[(&str, App, PendingRender, bool)] = &[
            ("nothing pending", active_app(), NoPending, false),
            (
                "nothing pending during screensaver",
                active_screensaver_app(),
                NoPending,
                false,
            ),
            ("in-place on live page", active_app(), InPlace, true),
            ("in-place while modal flushes", modal_app(), InPlace, true),
            (
                "in-place during screensaver",
                active_screensaver_app(),
                InPlace,
                false,
            ),
            ("transition on live page", active_app(), Transition, true),
            ("transition while modal", modal_app(), Transition, true),
            (
                "transition during screensaver",
                active_screensaver_app(),
                Transition,
                true,
            ),
        ];
        for (name, app, pending, expected) in cases {
            assert_eq!(app.should_flush_repaint(*pending), *expected, "{name}");
        }
    }

    // === Screensaver tests ===

    #[test]
    fn watermark_error_during_screensaver_wakes_display() {
        let mut app = active_screensaver_app();
        let (_action, effects) = app.handle_event(AppEvent::WatermarkError {
            pkh: "tz4test".into(),
            chain_id: test_chain_id(),
            error_message: "test".into(),
            current_level: Some(100),
            requested_level: Some(50),
        });
        assert!(has_effect(&effects, &Effect::WakeDisplay));
        assert!(
            has_effect(&effects, &Effect::ResetActivity),
            "every wake must restart the inactivity clock"
        );
    }

    #[test]
    fn large_watermark_gap_during_screensaver_wakes_display() {
        let mut app = active_screensaver_app();
        let (_action, effects) = app.handle_event(AppEvent::LargeWatermarkGap {
            pkh: "tz4test".into(),
            chain_id: test_chain_id(),
            current_level: 100,
            requested_level: 200,
        });
        assert!(has_effect(&effects, &Effect::WakeDisplay));
        assert!(
            has_effect(&effects, &Effect::ResetActivity),
            "every wake must restart the inactivity clock"
        );
    }

    #[test]
    fn watermark_missing_when_modal_produces_no_effects() {
        let mut app = active_app();
        app.current_page_modal = true;
        let (_action, effects) = app.handle_event(AppEvent::WatermarkMissing {
            pkh: "tz4test".into(),
            chain_id: test_chain_id(),
            requested_level: 600,
        });
        assert!(effects.is_empty());
    }

    #[test]
    fn watermark_missing_during_screensaver_wakes_display() {
        let mut app = active_screensaver_app();
        let (_action, effects) = app.handle_event(AppEvent::WatermarkMissing {
            pkh: "tz4test".into(),
            chain_id: test_chain_id(),
            requested_level: 600,
        });
        assert!(has_effect(&effects, &Effect::WakeDisplay));
        assert!(
            has_effect(&effects, &Effect::ResetActivity),
            "every wake must restart the inactivity clock"
        );
    }

    #[test]
    fn activate_screensaver_when_already_active_is_ignored() {
        let mut app = active_screensaver_app();
        let (action, effects) = app.handle_event(AppEvent::ActivateScreensaver);
        assert_eq!(action, LoopAction::Continue);
        assert!(effects.is_empty());
    }

    #[test]
    fn deactivate_screensaver_restores_saved_page() {
        let mut app = active_screensaver_app();
        let (_action, effects) = app.handle_event(AppEvent::DeactivateScreensaver);
        assert!(has_effect(&effects, &Effect::WakeDisplay));
        assert!(has_effect(&effects, &Effect::RebuildSavedPage));
        assert!(has_effect(&effects, &Effect::ResetActivity));
        assert!(!app.is_screensaver_active());
    }

    #[test]
    fn wake_from_screensaver_rebuilds_page() {
        let mut app = active_screensaver_app();
        let effects = app.wake_from_screensaver_effects();
        assert!(has_effect(&effects, &Effect::WakeDisplay));
        assert!(has_effect(&effects, &Effect::RebuildSavedPage));
        assert!(
            has_effect(&effects, &Effect::ResetActivity),
            "every wake must restart the inactivity clock, or the \
             screensaver timer thread stays parked forever"
        );
        assert!(!app.is_screensaver_active());
    }

    // === Effect correctness tests ===

    #[test]
    fn keygen_success_produces_correct_effect_order() {
        let mut app = first_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::KeyGenSuccess(json("{}")));
        let expected_order = [
            Effect::ProcessWatermarkConfig,
            Effect::WriteSetupMarker,
            Effect::SetKeyPermissions,
            Effect::SyncDisk,
            Effect::RemountKeysReadonly,
            Effect::DropPrivileges,
            Effect::InitWatermark {
                context: "first boot setup".into(),
                secret_keys: json("{}"),
            },
            Effect::Emit(AppEvent::KeysDecrypted(json("{}"))),
        ];
        assert_eq!(effects, expected_order);
    }

    #[test]
    fn shutdown_produces_sync_clear_sleep() {
        let mut app = active_app();
        let (action, effects) = app.handle_event(AppEvent::Shutdown);
        assert_eq!(action, LoopAction::Break);
        assert!(has_effect(&effects, &Effect::SyncDisk));
        assert!(has_effect(&effects, &Effect::ClearDisplay));
        assert!(has_effect(&effects, &Effect::SleepDevice));
    }

    #[test]
    fn shutdown_from_screensaver_wakes_display_first() {
        let mut app = active_screensaver_app();
        let (action, effects) = app.handle_event(AppEvent::Shutdown);
        assert_eq!(action, LoopAction::Break);
        assert!(has_effect(&effects, &Effect::WakeDisplay));
    }

    #[test]
    fn keys_decrypted_sends_keys_and_shows_menu() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::KeysDecrypted(json("keys")));
        assert_eq!(
            effects,
            vec![
                Effect::SendKeys(json("keys")),
                Effect::ShowPage(PageSpec::Menu),
                Effect::ResetActivity,
            ]
        );
    }

    #[test]
    fn start_setup_spawns_storage_setup() {
        // In test env, needs_storage_setup() returns true (no /sys/block/mmcblk0/mmcblk0p3)
        let mut app = first_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::StartSetup);
        assert!(has_effect(&effects, &Effect::SpawnStorageSetup));
    }

    #[test]
    fn pin_mismatch_resets_first_pin_and_shows_error() {
        let mut app = first_boot_app();
        app.handle_event(AppEvent::FirstPinEntered(pin(&[1, 2, 3, 4])));
        let (_action, effects) = app.handle_event(AppEvent::PinMismatch);
        // Should show error then PIN create
        assert!(has_show_page(
            &effects,
            &PageSpec::Error {
                title: "PIN MISMATCH".into(),
                message: "PINs don't match. Please try again.".into(),
            }
        ));
        assert!(has_show_page(&effects, &PageSpec::PinCreate));
        // first_pin should be cleared
        if let AppState::Setup { first_pin } = &app.state {
            assert!(first_pin.is_none());
        } else {
            panic!("Expected Setup state");
        }
    }

    #[test]
    fn activate_screensaver_drops_page_and_sleeps() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::ActivateScreensaver);
        assert_eq!(
            effects,
            vec![Effect::DropCurrentPage, Effect::SleepDisplay,]
        );
        assert!(app.is_screensaver_active());
    }

    #[test]
    fn watermark_missing_produces_warned_recovery_dialog() {
        let mut app = active_app();
        let chain_id = test_chain_id();
        let (_action, effects) = app.handle_event(AppEvent::WatermarkMissing {
            pkh: "tz4abcdefghijklmnop".into(),
            chain_id,
            requested_level: 600,
        });

        let dialog = effects.iter().find_map(|e| match e {
            Effect::ShowPage(PageSpec::Confirmation {
                message,
                on_confirm,
                warning,
                ..
            }) => Some((message, on_confirm, *warning)),
            _ => None,
        });
        let (message, on_confirm, warning) =
            dialog.expect("expected a Confirmation dialog for a missing watermark");

        assert!(warning, "missing-watermark recovery dialog must be warned");
        assert!(
            message.contains("russignol check disk"),
            "dialog must name the host recovery command, got: {message}"
        );
        assert_eq!(
            on_confirm,
            &AppEvent::UpdateWatermarkToLevel {
                pkh: "tz4abcdefghijklmnop".into(),
                chain_id,
                new_level: 600,
            }
        );
    }

    /// The produced dialog message and icon flag, for asserting the message
    /// fits the confirmation page's clip-prone text column.
    fn confirmation_dialog(effects: &[Effect]) -> (&String, bool) {
        effects
            .iter()
            .find_map(|e| match e {
                Effect::ShowPage(PageSpec::Confirmation {
                    message, warning, ..
                }) => Some((message, *warning)),
                _ => None,
            })
            .expect("expected a Confirmation dialog")
    }

    /// The confirmation page clips whole rows that overflow its text column,
    /// so the widest missing-watermark message — a maximum-length pkh with the
    /// largest possible level — must render within it, or the operator is
    /// asked to confirm a watermark change without seeing which key and level
    /// it applies to.
    #[test]
    fn missing_watermark_message_fits_confirmation_page() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::WatermarkMissing {
            pkh: MAX_TZ4_PKH.into(),
            chain_id: test_chain_id(),
            requested_level: u32::MAX,
        });

        let (message, warning) = confirmation_dialog(&effects);
        let height = crate::pages::confirmation::measure_message_height(message, warning);
        assert!(
            height <= crate::pages::confirmation::MESSAGE_MAX_HEIGHT.cast_unsigned(),
            "message {message:?} needs {height}px but the confirmation page fits {}px",
            crate::pages::confirmation::MESSAGE_MAX_HEIGHT,
        );
    }

    /// The watermark-error dialog shares the clip-prone confirmation page; its
    /// widest message — the largest possible level — must render within it.
    #[test]
    fn watermark_error_message_fits_confirmation_page() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::WatermarkError {
            pkh: MAX_TZ4_PKH.into(),
            chain_id: test_chain_id(),
            error_message: "watermark test failed".into(),
            current_level: Some(u32::MAX - 1),
            requested_level: Some(u32::MAX),
        });

        let (message, warning) = confirmation_dialog(&effects);
        let height = crate::pages::confirmation::measure_message_height(message, warning);
        assert!(
            height <= crate::pages::confirmation::MESSAGE_MAX_HEIGHT.cast_unsigned(),
            "message {message:?} needs {height}px but the confirmation page fits {}px",
            crate::pages::confirmation::MESSAGE_MAX_HEIGHT,
        );
    }

    // === Unknown-key alert tests ===

    /// A maximum-length (36-char) tz4 pkh, the widest the modal must fit.
    const MAX_TZ4_PKH: &str = "tz4HVR43NNbNhLGTHUNCGWEUjYmDT1RGcNjZ";

    /// Feed `UnknownKeyRequested` for `pkh` and return the effects.
    fn request_unknown_key(app: &mut App, pkh: &str) -> Vec<Effect> {
        let (_action, effects) =
            app.handle_event(AppEvent::UnknownKeyRequested { pkh: pkh.into() });
        effects
    }

    fn alert_content(pkh: &str, others: usize, overflow: bool) -> AlertContent<'_> {
        AlertContent {
            pkh,
            others,
            overflow,
        }
    }

    /// The message of the first `ShowPage(Notice)` in `effects`, if any.
    fn notice_message(effects: &[Effect]) -> Option<&str> {
        effects.iter().find_map(|e| match e {
            Effect::ShowPage(PageSpec::Notice { message, .. }) => Some(message.as_str()),
            _ => None,
        })
    }

    // --- Message-builder tests ---

    #[test]
    fn unknown_key_message_single_key_has_no_count_suffix() {
        let msg = unknown_key_message(&alert_content(MAX_TZ4_PKH, 0, false));
        assert!(
            msg.contains("tz4HVR43...RGcNjZ"),
            "the pkh must appear truncated head+tail: {msg}"
        );
        assert!(
            !msg.contains(" +"),
            "a lone key carries no count suffix: {msg}"
        );
        assert!(
            msg.contains(UNKNOWN_KEY_GUIDANCE),
            "the message must carry the guidance line: {msg}"
        );
    }

    #[test]
    fn unknown_key_message_counts_other_keys_compactly() {
        let msg = unknown_key_message(&alert_content(MAX_TZ4_PKH, 1, false));
        assert!(msg.contains("tz4HVR43...RGcNjZ +1"), "{msg}");
        let msg = unknown_key_message(&alert_content(MAX_TZ4_PKH, 5, false));
        assert!(msg.contains("tz4HVR43...RGcNjZ +5"), "{msg}");
    }

    #[test]
    fn unknown_key_message_overflow_marks_lower_bound() {
        let msg = unknown_key_message(&alert_content(MAX_TZ4_PKH, 7, true));
        assert!(msg.contains("tz4HVR43...RGcNjZ +7+"), "{msg}");
    }

    #[test]
    fn unknown_key_message_truncates_pkh_with_ascii_marker() {
        let msg = unknown_key_message(&alert_content(MAX_TZ4_PKH, 0, false));
        assert!(
            msg.contains("..."),
            "the pkh must be truncated with an ASCII marker: {msg}"
        );
        assert!(
            !msg.contains(MAX_TZ4_PKH),
            "the full-length pkh must not appear: {msg}"
        );
    }

    #[test]
    fn unknown_key_message_is_pure_ascii() {
        for content in [
            alert_content(MAX_TZ4_PKH, 0, false),
            alert_content(MAX_TZ4_PKH, 1, false),
            alert_content(MAX_TZ4_PKH, 5, false),
            alert_content(MAX_TZ4_PKH, 7, true),
        ] {
            let msg = unknown_key_message(&content);
            assert!(msg.is_ascii(), "the message must be pure ASCII: {msg}");
        }
    }

    /// The display fonts cover only ISO-8859-1, and `render_aligned` aborts
    /// mid-string at a missing glyph, so every string the modal renders must be
    /// renderable in the font it renders with: the title in `FONT_PROPORTIONAL`,
    /// the message body in `FONT_MEDIUM`.
    #[test]
    fn font_covers_every_unknown_key_string() {
        use embedded_graphics::prelude::Point;
        use u8g2_fonts::{FontRenderer, types::VerticalPosition};

        let title_font = FontRenderer::new::<crate::fonts::FONT_PROPORTIONAL>();
        let message_font = FontRenderer::new::<crate::fonts::FONT_MEDIUM>();
        let renders = |font: &FontRenderer, s: &str| {
            font.get_rendered_dimensions(s, Point::zero(), VerticalPosition::Baseline)
                .is_ok()
        };
        assert!(
            renders(&title_font, UNKNOWN_KEY_TITLE),
            "the title contains a glyph FONT_PROPORTIONAL cannot render"
        );
        for content in [
            alert_content(MAX_TZ4_PKH, 0, false),
            alert_content(MAX_TZ4_PKH, 1, false),
            alert_content(MAX_TZ4_PKH, 7, false),
            alert_content(MAX_TZ4_PKH, 7, true),
        ] {
            let msg = unknown_key_message(&content);
            assert!(
                renders(&message_font, &msg),
                "message {msg:?} contains a glyph FONT_MEDIUM cannot render"
            );
        }
    }

    /// The notice message box clips whole rows that overflow, so the widest,
    /// most-suffixed unknown-key message must render within it or the operator
    /// loses the pkh or the guidance.
    #[test]
    fn unknown_key_message_fits_notice_box() {
        for content in [
            alert_content(MAX_TZ4_PKH, 0, false),
            alert_content(MAX_TZ4_PKH, 7, false),
            alert_content(MAX_TZ4_PKH, 7, true),
        ] {
            let msg = unknown_key_message(&content);
            let height = crate::pages::notice::measure_message_height(&msg);
            assert!(
                height <= crate::pages::notice::MESSAGE_BOX_HEIGHT.cast_unsigned(),
                "message {msg:?} needs {height}px but the notice box is {}px",
                crate::pages::notice::MESSAGE_BOX_HEIGHT,
            );
        }
    }

    /// The config-gate notice shares the clip-prone notice box; its message
    /// must render within it or the operator loses the provisioning guidance.
    #[test]
    fn config_gate_message_fits_notice_box() {
        let height = crate::pages::notice::measure_message_height(CONFIG_GATE_MESSAGE);
        assert!(
            height <= crate::pages::notice::MESSAGE_BOX_HEIGHT.cast_unsigned(),
            "config-gate message needs {height}px but the notice box is {}px",
            crate::pages::notice::MESSAGE_BOX_HEIGHT,
        );
    }

    // --- Show / state-machine tests ---

    #[test]
    fn wake_without_rebuild_omits_page_rebuild() {
        let mut app = active_screensaver_app();
        let effects = app.wake_without_rebuild_effects();
        assert!(has_effect(&effects, &Effect::WakeDisplay));
        assert!(
            has_effect(&effects, &Effect::ResetActivity),
            "every wake must restart the inactivity clock"
        );
        assert!(
            !has_effect(&effects, &Effect::RebuildSavedPage),
            "the no-rebuild wake must not repaint the saved page"
        );
        assert!(!app.is_screensaver_active());
    }

    #[test]
    fn unknown_key_requested_shows_modal_notice() {
        let mut app = active_app();
        let effects = request_unknown_key(&mut app, "tz4wrong1");
        let message = notice_message(&effects).expect("an unknown key must raise a Notice modal");
        assert!(
            message.contains("tz4wrong1"),
            "the notice must name the pkh: {message}"
        );
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::ShowPage(PageSpec::Notice { on_dismiss, .. })
                    if *on_dismiss == AppEvent::UnknownKeyDismissed
            )),
            "the notice must dismiss to the acknowledge event"
        );
        assert_eq!(
            app.unknown_keys.active(),
            Some(alert_content("tz4wrong1", 0, false)),
            "the requested pkh must be recorded"
        );
    }

    #[test]
    fn unknown_key_repeat_does_not_realert() {
        let mut app = active_app();
        request_unknown_key(&mut app, "tz4wrong1");
        let effects = request_unknown_key(&mut app, "tz4wrong1");
        assert!(
            effects.is_empty(),
            "a repeated pkh must not re-alert: {effects:?}"
        );
        assert_eq!(
            app.unknown_keys.active(),
            Some(alert_content("tz4wrong1", 0, false))
        );
    }

    #[test]
    fn unknown_key_requested_when_modal_does_not_record() {
        let mut app = active_app();
        app.current_page_modal = true;
        let effects = request_unknown_key(&mut app, "tz4wrong1");
        assert!(
            effects.is_empty(),
            "no page may land over a modal: {effects:?}"
        );
        assert_eq!(
            app.unknown_keys.active(),
            None,
            "a request arriving under a modal is neither shown nor recorded"
        );
    }

    #[test]
    fn unknown_key_requested_during_screensaver_wakes_and_shows_modal() {
        let mut app = active_screensaver_app();
        let effects = request_unknown_key(&mut app, "tz4wrong1");
        assert!(has_effect(&effects, &Effect::WakeDisplay));
        assert!(
            has_effect(&effects, &Effect::ResetActivity),
            "every wake must restart the inactivity clock"
        );
        assert!(
            notice_message(&effects).is_some_and(|m| m.contains("tz4wrong1")),
            "the alert modal must be shown after waking: {effects:?}"
        );
        assert!(
            !has_effect(&effects, &Effect::RebuildSavedPage),
            "ShowPage(Notice) paints the modal itself; rebuilding the saved page \
             first would double-flash e-paper"
        );
        assert!(!app.is_screensaver_active());
    }

    #[test]
    fn unknown_key_alert_is_bounded_at_cap() {
        let mut app = active_app();
        for i in 1..=UNKNOWN_KEY_CAP {
            let effects = request_unknown_key(&mut app, &format!("tz4wrong{i}"));
            assert!(
                notice_message(&effects).is_some(),
                "pkh {i} is within the cap and must show the modal"
            );
        }
        // One past the cap: flips the overflow marker — one final modal.
        let effects = request_unknown_key(&mut app, "tz4over1");
        assert!(
            notice_message(&effects).is_some(),
            "the overflow flip is the last state change and must show the modal"
        );
        // Beyond that, nothing changes: new pkhs and repeats of non-retained
        // pkhs produce no effects — a flooding peer cannot drive the display.
        for pkh in ["tz4over2", "tz4over3", "tz4over1"] {
            let effects = request_unknown_key(&mut app, pkh);
            assert!(
                effects.is_empty(),
                "past the overflow flip no modal may fire for {pkh}: {effects:?}"
            );
        }
        let last_retained = format!("tz4wrong{UNKNOWN_KEY_CAP}");
        assert_eq!(
            app.unknown_keys.active(),
            Some(alert_content(&last_retained, UNKNOWN_KEY_CAP - 1, true)),
            "the alert reports the retained keys plus the overflow marker"
        );
        assert_eq!(
            app.unknown_keys.pkhs.len(),
            UNKNOWN_KEY_CAP,
            "retained set must stay at the cap"
        );
    }

    #[test]
    fn unknown_key_dismiss_retains_dedup() {
        let mut app = active_app();
        request_unknown_key(&mut app, "tz4wrong1");
        app.handle_event(AppEvent::UnknownKeyDismissed);
        let effects = request_unknown_key(&mut app, "tz4wrong1");
        assert!(
            effects.is_empty(),
            "an acknowledged pkh must not re-alert: {effects:?}"
        );
        assert_eq!(
            app.unknown_keys.active(),
            None,
            "the alert must stay dismissed for an acknowledged pkh"
        );
    }

    #[test]
    fn unknown_key_new_key_realerts_after_dismiss() {
        let mut app = active_app();
        request_unknown_key(&mut app, "tz4wrong1");
        app.handle_event(AppEvent::UnknownKeyDismissed);
        let effects = request_unknown_key(&mut app, "tz4wrong2");
        assert!(
            notice_message(&effects).is_some_and(|m| m.contains("tz4wrong2")),
            "a genuinely new pkh must re-raise the modal after dismissal: {effects:?}"
        );
        assert_eq!(
            app.unknown_keys.active(),
            Some(alert_content("tz4wrong2", 1, false))
        );
    }

    #[test]
    fn unknown_key_dismissed_acks_to_menu() {
        let mut app = active_app();
        request_unknown_key(&mut app, "tz4wrong1");
        let (_action, effects) = app.handle_event(AppEvent::UnknownKeyDismissed);
        assert_eq!(
            app.unknown_keys.active(),
            None,
            "ack clears the active alert"
        );
        assert_eq!(
            effects,
            vec![Effect::ShowPage(PageSpec::Menu)],
            "ack returns to the menu"
        );
    }

    #[test]
    fn only_dismiss_deactivates_unknown_key_alert() {
        let mut app = active_app();
        request_unknown_key(&mut app, "tz4wrong1");
        // A successful signature (the signing callback sends Invalidate)
        // says nothing about the unheld key in a mixed one-held/one-unheld
        // config, so it must not clear the alert.
        app.handle_event(AppEvent::Invalidate);
        app.handle_event(AppEvent::ShowMenu);
        assert_eq!(
            app.unknown_keys.active(),
            Some(alert_content("tz4wrong1", 0, false)),
            "no event other than dismiss may deactivate the alert"
        );
        app.handle_event(AppEvent::UnknownKeyDismissed);
        assert_eq!(app.unknown_keys.active(), None);
    }

    #[test]
    fn watermark_update_to_level_produces_update_effect() {
        let mut app = active_app();
        let chain_id = test_chain_id();
        let (_action, effects) = app.handle_event(AppEvent::UpdateWatermarkToLevel {
            pkh: "tz4test".into(),
            chain_id,
            new_level: 500,
        });
        assert_eq!(
            effects,
            vec![Effect::UpdateWatermark {
                pkh: "tz4test".into(),
                chain_id,
                new_level: 500,
            }]
        );
    }

    #[test]
    fn dialog_dismissed_shows_menu() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::DialogDismissed);
        assert_eq!(effects, vec![Effect::ShowPage(PageSpec::Menu)]);
    }

    #[test]
    fn fatal_error_produces_fatal_effect() {
        let mut app = active_app();
        let (action, effects) = app.handle_event(AppEvent::FatalError {
            title: "OOPS".into(),
            message: "something broke".into(),
        });
        assert_eq!(action, LoopAction::Proceed);
        assert_eq!(
            effects,
            vec![Effect::FatalError {
                title: "OOPS".into(),
                message: "something broke".into(),
            }]
        );
    }

    #[test]
    fn show_menu_navigates_to_menu() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::ShowMenu);
        assert_eq!(effects, vec![Effect::ShowPage(PageSpec::Menu)]);
    }

    #[test]
    fn show_watermarks_navigates_to_watermarks() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::ShowWatermarks);
        assert_eq!(effects, vec![Effect::ShowPage(PageSpec::Watermarks)]);
    }

    #[test]
    fn show_blockchain_navigates_to_blockchain() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::ShowBlockchain);
        assert_eq!(effects, vec![Effect::ShowPage(PageSpec::Blockchain)]);
    }

    #[test]
    fn show_blockchain_when_modal_produces_no_effects() {
        let mut app = active_app();
        app.current_page_modal = true;
        let (_action, effects) = app.handle_event(AppEvent::ShowBlockchain);
        assert!(effects.is_empty());
    }

    #[test]
    fn show_about_navigates_to_about() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::ShowAbout);
        assert_eq!(effects, vec![Effect::ShowPage(PageSpec::About)]);
    }

    #[test]
    fn show_image_navigates_to_image() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::ShowImage {
            back: BackTarget::About,
        });
        assert_eq!(
            effects,
            vec![Effect::ShowPage(PageSpec::Image {
                back: BackTarget::About
            })]
        );
    }

    #[test]
    fn show_image_from_greeting_carries_its_back_target() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::ShowImage {
            back: BackTarget::Greeting,
        });
        assert_eq!(
            effects,
            vec![Effect::ShowPage(PageSpec::Image {
                back: BackTarget::Greeting
            })]
        );
    }

    #[test]
    fn show_greeting_navigates_to_greeting() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::ShowGreeting);
        assert_eq!(effects, vec![Effect::ShowPage(PageSpec::Greeting)]);
    }

    #[test]
    fn greeting_opens_image_screen_during_setup() {
        let mut app = first_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::ShowImage {
            back: BackTarget::Greeting,
        });
        assert_eq!(
            effects,
            vec![Effect::ShowPage(PageSpec::Image {
                back: BackTarget::Greeting
            })]
        );
    }

    #[test]
    fn image_screen_returns_to_greeting_during_setup() {
        let mut app = first_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::ShowGreeting);
        assert_eq!(effects, vec![Effect::ShowPage(PageSpec::Greeting)]);
    }

    #[test]
    fn show_image_when_modal_produces_no_effects() {
        let mut app = active_app();
        app.current_page_modal = true;
        let (_action, effects) = app.handle_event(AppEvent::ShowImage {
            back: BackTarget::About,
        });
        assert!(effects.is_empty());
    }

    #[test]
    fn show_about_when_modal_produces_no_effects() {
        let mut app = active_app();
        app.current_page_modal = true;
        let (_action, effects) = app.handle_event(AppEvent::ShowAbout);
        assert!(effects.is_empty());
    }

    #[test]
    fn request_shutdown_shows_confirmation() {
        let mut app = active_app();
        let (_action, effects) = app.handle_event(AppEvent::RequestShutdown);
        assert!(has_show_page(
            &effects,
            &PageSpec::Confirmation {
                message: "Shutdown the device?".into(),
                on_confirm: AppEvent::Shutdown,
                on_cancel: AppEvent::ShowMenu,
                warning: false,
                button_text: "Shutdown".into(),
            }
        ));
    }
}
