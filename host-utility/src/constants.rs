// Constants for the Russignol Hardware Signer Host Utility
//
// This module centralizes all hardcoded values used throughout the application
// to ensure consistency and make configuration changes easier.

use inquire::ui::Color;

// ============================================================================
// Hardware Identifiers
// ============================================================================

/// USB Vendor ID for Russignol device
pub const USB_VENDOR_ID: &str = "1d6b";

/// USB Product ID for Russignol device
pub const USB_PRODUCT_ID: &str = "0104";

/// Combined USB VID:PID string
pub const USB_VID_PID: &str = "1d6b:0104";

/// Manufacturer name for Russignol device
pub const MANUFACTURER_NAME: &str = "Russignol";

// ============================================================================
// Network Configuration
// ============================================================================

/// IP address of the Russignol signer
pub const SIGNER_IP: &str = "169.254.1.1";

/// Network mask for the point-to-point link
pub const NETWORK_MASK: &str = "/30";

/// Full network configuration string
pub const NETWORK_CONFIG: &str = "169.254.1.2/30";

/// Full URI for the remote signer
pub const SIGNER_URI: &str = "tcp://169.254.1.1:7732";

/// Network interface name for Russignol
pub const INTERFACE_NAME: &str = "russignol";

// ============================================================================
// Key Aliases
// ============================================================================

/// Alias for the consensus key
pub const CONSENSUS_KEY_ALIAS: &str = "russignol-consensus";

/// Alias for the companion key
pub const COMPANION_KEY_ALIAS: &str = "russignol-companion";

/// Alias for the pending consensus key (during rotation)
pub const CONSENSUS_KEY_PENDING_ALIAS: &str = "russignol-consensus-pending";

/// Alias for the pending companion key (during rotation)
pub const COMPANION_KEY_PENDING_ALIAS: &str = "russignol-companion-pending";

/// Alias for the old consensus key backup (during swap verification)
pub const CONSENSUS_KEY_OLD_ALIAS: &str = "russignol-consensus-old";

/// Alias for the old companion key backup (during swap verification)
pub const COMPANION_KEY_OLD_ALIAS: &str = "russignol-companion-old";

// ============================================================================
// System Configuration Paths
// ============================================================================

/// Path to the udev rule file
pub const UDEV_RULE_PATH: &str = "/etc/udev/rules.d/20-russignol.rules";

/// Path to the systemd network configuration file
pub const NETWORK_CONFIG_PATH: &str = "/etc/systemd/network/80-russignol.network";

/// Path to the `NetworkManager` configuration file
pub const NETWORKMANAGER_CONFIG_PATH: &str = "/etc/NetworkManager/conf.d/unmanaged-russignol.conf";

// ============================================================================
// Required Dependencies
// ============================================================================

/// List of required command-line tools
pub const REQUIRED_COMMANDS: &[&str] = &[
    "octez-client",
    "octez-node",
    "ps",
    "grep",
    "ip",
    "ping",
    "udevadm",
    "lsusb",
];

// ============================================================================
// Progress Bar Theming
// ============================================================================

/// Orange theme color - single source of truth for RGB values
/// Uses (255, 175, 0) to exactly match xterm-256 color 214 for consistency
pub const ORANGE: (u8, u8, u8) = (255, 175, 0);

/// Orange theme color (for inquire prompts) - derived from ORANGE
pub const ORANGE_RGB: Color = Color::Rgb {
    r: ORANGE.0,
    g: ORANGE.1,
    b: ORANGE.2,
};

/// Calculate nearest xterm-256 color index from RGB
///
/// The xterm-256 palette (colors 16-231) is a 6×6×6 RGB cube where each
/// component maps to values: 0, 95, 135, 175, 215, 255.
/// Formula: 16 + (36 × `r_idx`) + (6 × `g_idx`) + `b_idx`
const fn rgb_to_xterm256(r: u8, g: u8, b: u8) -> u8 {
    const fn nearest_idx(val: u8) -> u8 {
        if val < 48 {
            0
        } else if val < 115 {
            1
        } else if val < 155 {
            2
        } else if val < 195 {
            3
        } else if val < 235 {
            4
        } else {
            5
        }
    }
    16 + 36 * nearest_idx(r) + 6 * nearest_idx(g) + nearest_idx(b)
}

/// Orange theme color (xterm-256 color code for indicatif) - derived from ORANGE
pub const ORANGE_256: u8 = rgb_to_xterm256(ORANGE.0, ORANGE.1, ORANGE.2);
