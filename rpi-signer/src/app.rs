use crossbeam_channel::Sender;
use russignol_signer_lib::{ChainId, HighWatermark, signing_activity};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::events::AppEvent;
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
    pub needs_animation: bool,
    pub animation_interval: Duration,
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
            needs_animation: false,
            animation_interval: Duration::from_secs(1),
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

    fn wake_from_screensaver_effects(&mut self) -> Vec<Effect> {
        if self.is_screensaver_active() {
            self.set_screensaver(false);
            return vec![Effect::WakeDisplay, Effect::RebuildSavedPage];
        }
        vec![]
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
                log::info!("Storage setup complete, verifying partitions...");
                effects.push(Effect::VerifyStorage);
                effects.push(Effect::ShowPage(PageSpec::PinCreate));
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
                log::info!("Keys generated and encrypted successfully");
                effects.extend([
                    Effect::ProcessWatermarkConfig,
                    Effect::WriteSetupMarker,
                    Effect::SetKeyPermissions,
                    Effect::SyncDisk,
                    Effect::RemountKeysReadonly,
                    Effect::DropPrivileges,
                    Effect::InitWatermark {
                        context: "first boot setup".into(),
                    },
                ]);
                self.state = AppState::Active {
                    screensaver_active: false,
                };
                effects.push(Effect::Emit(AppEvent::KeysDecrypted(secret_keys_json)));
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
                self.set_screensaver(false);
                effects.extend([
                    Effect::WakeDisplay,
                    Effect::RebuildSavedPage,
                    Effect::ResetActivity,
                ]);
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
        let chain_id_str = chain_id.to_b58check();
        let chain_short = if chain_id_str.len() > 12 {
            format!("{}...", &chain_id_str[..12])
        } else {
            chain_id_str
        };
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
        let pkh_short = if pkh.len() > 6 {
            format!("{}…", &pkh[..6])
        } else {
            pkh.clone()
        };
        effects.push(Effect::ShowPage(PageSpec::Confirmation {
            message: format!(
                "Missing: {pkh_short} set {requested_level}?\nRun russignol watermark init\nthen reboot on host."
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
    fn setup_storage_complete_shows_pin_create() {
        let mut app = first_boot_app();
        let (action, effects) = app.handle_event(AppEvent::StorageSetupComplete);
        assert_eq!(action, LoopAction::Proceed);
        assert!(has_show_page(&effects, &PageSpec::PinCreate));
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
            message.contains("russignol watermark init"),
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
