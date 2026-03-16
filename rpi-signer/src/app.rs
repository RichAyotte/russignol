use crossbeam_channel::Sender;
use russignol_signer_lib::{ChainId, HighWatermark, signing_activity};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::events::AppEvent;
use crate::setup;

/// Maximum failed PIN attempts before lockout
const MAX_FAILED_ATTEMPTS: u32 = 5;
/// Lockout duration after max failed attempts (5 minutes)
const LOCKOUT_DURATION: Duration = Duration::from_secs(300);

/// Application lifecycle state — scopes mutable variables to their lifecycle phase
#[derive(Debug)]
pub enum AppState {
    /// First boot: key generation flow
    Setup { first_pin: Option<Vec<u8>> },
    /// Normal boot: PIN verification
    PinEntry {
        failed_attempts: u32,
        lockout_until: Option<Instant>,
    },
    /// Keys decrypted, signer running
    Active {
        screensaver_active: bool,
        last_activity: Instant,
    },
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
    SendKeys(String),
    InitWatermark {
        context: String,
    },
    SpawnKeygen {
        pin: Vec<u8>,
    },
    SpawnPinVerify {
        pin: Vec<u8>,
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
    pub start_signer_tx: Sender<String>,
    pub watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    pub needs_animation: bool,
    pub animation_interval: Duration,
}

impl App {
    pub fn new(
        is_first_boot: bool,
        tx: Sender<AppEvent>,
        signing_activity: Arc<Mutex<signing_activity::SigningActivity>>,
        start_signer_tx: Sender<String>,
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
                    last_activity: Instant::now(),
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

    fn handle_setup_pin_confirm(&mut self, pin: Vec<u8>) -> Vec<Effect> {
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
            AppEvent::PinVerified(secret_keys_json) => {
                log::info!("PIN verified successfully, secret keys decrypted");
                self.state = AppState::Active {
                    screensaver_active: false,
                    last_activity: Instant::now(),
                };
                effects.push(Effect::InitWatermark {
                    context: "PIN entry".into(),
                });
                effects.push(Effect::Emit(AppEvent::KeysDecrypted(secret_keys_json)));
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

    fn handle_active(&mut self, event: AppEvent) -> (LoopAction, Vec<Effect>) {
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
            AppEvent::DeactivateScreensaver => {
                if self.is_screensaver_active() {
                    log::info!("Deactivating screensaver");
                    self.set_screensaver(false);
                    effects.extend([
                        Effect::WakeDisplay,
                        Effect::RebuildSavedPage,
                        Effect::ResetActivity,
                    ]);
                }
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
            AppEvent::ShowStatus if !self.current_page_modal => {
                effects.push(Effect::ShowPage(PageSpec::Status));
            }
            AppEvent::ShowSignatures if !self.current_page_modal => {
                effects.push(Effect::ShowPage(PageSpec::Signatures));
            }
            AppEvent::ShowWatermarks if !self.current_page_modal => {
                effects.push(Effect::ShowPage(PageSpec::Watermarks));
            }
            AppEvent::ShowBlockchain if !self.current_page_modal => {
                effects.push(Effect::ShowPage(PageSpec::Blockchain));
            }
            AppEvent::ShowAbout if !self.current_page_modal => {
                effects.push(Effect::ShowPage(PageSpec::About));
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
            last_activity: Instant::now(),
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

    fn has_show_page(effects: &[Effect], spec: &PageSpec) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::ShowPage(s) if s == spec))
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
        let (_action, _effects) = app.handle_event(AppEvent::KeyGenSuccess("{}".into()));
        assert!(matches!(app.state, AppState::Active { .. }));
    }

    #[test]
    fn pin_verified_transitions_pin_entry_to_active() {
        let mut app = normal_boot_app();
        let (_action, _effects) = app.handle_event(AppEvent::PinVerified("{}".into()));
        assert!(matches!(app.state, AppState::Active { .. }));
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
        app.handle_event(AppEvent::FirstPinEntered(vec![1, 2, 3, 4]));
        // Now confirm with same PIN
        let (_action, effects) = app.handle_event(AppEvent::PinEntered(vec![1, 2, 3, 4]));
        assert!(has_effect(
            &effects,
            &Effect::SpawnKeygen {
                pin: vec![1, 2, 3, 4]
            }
        ));
    }

    #[test]
    fn pin_entered_in_setup_with_mismatch_emits_pin_mismatch() {
        let mut app = first_boot_app();
        app.handle_event(AppEvent::FirstPinEntered(vec![1, 2, 3, 4]));
        let (_action, effects) = app.handle_event(AppEvent::PinEntered(vec![5, 6, 7, 8]));
        assert!(has_effect(&effects, &Effect::Emit(AppEvent::PinMismatch)));
    }

    #[test]
    fn pin_entered_in_pin_entry_verifies() {
        let mut app = normal_boot_app();
        let (_action, effects) = app.handle_event(AppEvent::PinEntered(vec![1, 2, 3, 4]));
        assert!(has_effect(
            &effects,
            &Effect::SpawnPinVerify {
                pin: vec![1, 2, 3, 4]
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
        let (_action, effects) = app.handle_event(AppEvent::KeyGenSuccess("{}".into()));
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
            Effect::Emit(AppEvent::KeysDecrypted("{}".into())),
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
        let (_action, effects) = app.handle_event(AppEvent::KeysDecrypted("keys".into()));
        assert_eq!(
            effects,
            vec![
                Effect::SendKeys("keys".into()),
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
        app.handle_event(AppEvent::FirstPinEntered(vec![1, 2, 3, 4]));
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
