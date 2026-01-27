pub mod confirmation;
pub mod dialog;
pub mod greeting;
pub mod pin;
pub mod screensaver;
pub mod signatures;
pub mod status;

pub use greeting::GreetingPage;
pub use pin::PinMode;

// Re-export Page trait from the library instead of defining our own
pub use russignol_ui::pages::Page;
