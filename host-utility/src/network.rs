//! Public Tezos networks and RPC endpoint resolution.
//!
//! Networks are fetched from teztnets.com with a hardcoded fallback so the
//! picker works offline. Endpoint probing is direct HTTP (not octez-client)
//! so it works before octez is installed.

use anyhow::Result;

/// Chain name mainnet has always used; stable enough to hardcode.
pub const MAINNET_CHAIN_NAME: &str = "TEZOS_MAINNET";

/// Mainnet's chain id has never changed, so a Mainnet card can be matched to a
/// Mainnet node without first querying a node for its chain id.
pub const MAINNET_CHAIN_ID: &str = "NetXdQprcVkpaWU";

pub const MAINNET_RPC_URL: &str = "https://rpc.tzbeta.net";
pub const SHADOWNET_RPC_URL: &str = "https://rpc.shadownet.teztnets.com";

/// Hint appended to node-unreachable errors in non-interactive runs.
pub const NON_INTERACTIVE_HINT: &str = "\n  \
    No node is reachable at the configured endpoint. Options:\n  \
    • Pass one explicitly: --endpoint <url>\n  \
    • Persist one: russignol config set rpc-endpoint <url>\n  \
    • Use a public RPC, e.g. https://rpc.tzbeta.net (Mainnet)\n  \
    Note: baking requires your own node; public RPCs are fine for status and watermark reads.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCategory {
    Mainnet,
    LongRunning,
    Protocol,
    /// Short-lived nets (e.g. weeklynet); excluded from the picker.
    Periodic,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicNetwork {
    pub human_name: String,
    /// Chain name as reported by a node's /version; empty when unknown
    /// (fallback entries), in which case name matching skips the entry.
    pub chain_name: String,
    pub rpc_url: String,
    pub category: NetworkCategory,
}

/// Networks guaranteed available when teztnets.com is unreachable.
///
/// Shadownet's chain name is date-stamped and drifts across resets, so only
/// mainnet's is hardcoded; the empty chain name just opts Shadownet out of
/// chain-name matching.
pub fn fallback_networks() -> Vec<PublicNetwork> {
    vec![
        PublicNetwork {
            human_name: "Mainnet".to_string(),
            chain_name: MAINNET_CHAIN_NAME.to_string(),
            rpc_url: MAINNET_RPC_URL.to_string(),
            category: NetworkCategory::Mainnet,
        },
        PublicNetwork {
            human_name: "Shadownet".to_string(),
            chain_name: String::new(),
            rpc_url: SHADOWNET_RPC_URL.to_string(),
            category: NetworkCategory::LongRunning,
        },
    ]
}

fn parse_category(category: &str, chain_name: &str) -> NetworkCategory {
    if chain_name == MAINNET_CHAIN_NAME {
        NetworkCategory::Mainnet
    } else if category.contains("Long-running") {
        NetworkCategory::LongRunning
    } else if category.contains("Protocol") {
        NetworkCategory::Protocol
    } else if category.contains("Periodic") || category.contains("Internal") {
        NetworkCategory::Periodic
    } else {
        NetworkCategory::Other
    }
}

/// Parse the teztnets.com registry (an object keyed by network name).
///
/// Alias entries (`aliasOf`) and entries without an `rpc_url` are dropped.
pub fn parse_teztnets(json: &serde_json::Value) -> Vec<PublicNetwork> {
    let Some(entries) = json.as_object() else {
        return Vec::new();
    };
    entries
        .values()
        .filter_map(|entry| {
            if entry.get("aliasOf").is_some_and(|a| !a.is_null()) {
                return None;
            }
            let rpc_url = entry.get("rpc_url")?.as_str()?.to_string();
            let human_name = entry.get("human_name")?.as_str()?.to_string();
            let chain_name = entry
                .get("chain_name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let category = entry
                .get("category")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            Some(PublicNetwork {
                human_name,
                category: parse_category(category, &chain_name),
                chain_name,
                rpc_url,
            })
        })
        .collect()
}

fn picker_rank(category: NetworkCategory) -> Option<u8> {
    match category {
        NetworkCategory::Mainnet => Some(0),
        NetworkCategory::LongRunning => Some(1),
        NetworkCategory::Protocol => Some(2),
        NetworkCategory::Other => Some(3),
        NetworkCategory::Periodic => None,
    }
}

/// Order networks for the picker: Mainnet, long-running, protocol testnets;
/// periodic nets are excluded.
pub fn order_for_picker(networks: Vec<PublicNetwork>) -> Vec<PublicNetwork> {
    let mut ranked: Vec<(u8, PublicNetwork)> = networks
        .into_iter()
        .filter_map(|n| picker_rank(n.category).map(|rank| (rank, n)))
        .collect();
    ranked.sort_by(|(a, an), (b, bn)| a.cmp(b).then_with(|| an.human_name.cmp(&bn.human_name)));
    ranked.into_iter().map(|(_, n)| n).collect()
}

/// Resolve a node-reported chain name to a network's human name.
pub fn human_name_for_chain(chain_name: &str, networks: &[PublicNetwork]) -> Option<String> {
    if chain_name.is_empty() {
        return None;
    }
    networks
        .iter()
        .find(|n| n.chain_name == chain_name)
        .map(|n| n.human_name.clone())
}

/// Fetch the public network list, falling back to the hardcoded set; the
/// result always contains Mainnet.
pub fn fetch_public_networks() -> Vec<PublicNetwork> {
    let agent = crate::utils::create_http_agent(3);
    let networks = crate::utils::http_get_json(&agent, "https://teztnets.com/teztnets.json")
        .map(|json| parse_teztnets(&json))
        .unwrap_or_default();
    if networks
        .iter()
        .any(|n| n.category == NetworkCategory::Mainnet)
    {
        networks
    } else {
        fallback_networks()
    }
}

/// Check that a Tezos node answers at the endpoint (direct HTTP, no octez).
pub fn probe_endpoint(endpoint: &str) -> Result<()> {
    let agent = crate::utils::create_http_agent(5);
    let url = format!("{endpoint}/chains/main/blocks/head/header");
    crate::utils::http_get_json(&agent, &url).map(|_| ())
}

fn category_label(category: NetworkCategory) -> &'static str {
    match category {
        NetworkCategory::Mainnet => "mainnet",
        NetworkCategory::LongRunning => "long-running testnet",
        NetworkCategory::Protocol => "protocol testnet",
        NetworkCategory::Periodic | NetworkCategory::Other => "testnet",
    }
}

/// One row of the network selection menu.
enum NetworkChoice {
    Network(PublicNetwork),
    /// The RPC endpoint of a node running on this machine.
    Local(String),
    /// Prompt for an IP address or RPC URL.
    Custom,
    Cancel,
}

impl std::fmt::Display for NetworkChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkChoice::Network(n) => write!(
                f,
                "{}  {}  [{}]",
                n.human_name,
                n.rpc_url,
                category_label(n.category)
            ),
            NetworkChoice::Local(endpoint) => {
                write!(f, "Local system  {endpoint}  [this machine]")
            }
            NetworkChoice::Custom => write!(f, "Other (enter an IP address or URL)"),
            NetworkChoice::Cancel => write!(f, "Cancel"),
        }
    }
}

/// Normalize user-entered node input into a canonical RPC URL. A bare host or
/// IP gains the default RPC port (`http://host:8732`), `host:port` gains only
/// the scheme, and a full `http(s)://` URL passes through; trailing slashes are
/// stripped.
fn normalize_endpoint_input(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Endpoint cannot be empty");
    }
    if trimmed.chars().any(char::is_whitespace) {
        anyhow::bail!("Endpoint '{trimmed}' must not contain spaces");
    }

    let normalized = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let host = trimmed
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        if host.is_empty() {
            anyhow::bail!("Endpoint '{trimmed}' is missing a host");
        }
        trimmed.to_string()
    } else if trimmed.contains('/') {
        anyhow::bail!(
            "Endpoint '{trimmed}' must be a bare IP/host or start with http:// or https://"
        );
    } else if trimmed.contains(':') {
        format!("http://{trimmed}")
    } else {
        format!("http://{trimmed}:8732")
    };

    Ok(normalized.trim_end_matches('/').to_string())
}

/// Assemble the flat menu: public networks first, then Local system, Other, and
/// Cancel. `local_endpoint` is passed in so node detection stays out of this
/// pure builder.
fn build_network_choices(
    networks: Vec<PublicNetwork>,
    local_endpoint: String,
) -> Vec<NetworkChoice> {
    let mut choices: Vec<NetworkChoice> =
        networks.into_iter().map(NetworkChoice::Network).collect();
    choices.push(NetworkChoice::Local(local_endpoint));
    choices.push(NetworkChoice::Custom);
    choices.push(NetworkChoice::Cancel);
    choices
}

/// Index of the menu entry whose endpoint matches `current_endpoint`, else 0.
fn starting_cursor(choices: &[NetworkChoice], current_endpoint: &str) -> usize {
    choices
        .iter()
        .position(|choice| match choice {
            NetworkChoice::Network(n) => n.rpc_url == current_endpoint,
            NetworkChoice::Local(endpoint) => endpoint == current_endpoint,
            NetworkChoice::Custom | NetworkChoice::Cancel => false,
        })
        .unwrap_or(0)
}

/// The RPC endpoint of a node on this machine: read from a local octez-node's
/// config, or the default local port when none is found.
fn local_system_endpoint() -> String {
    crate::config::RussignolConfig::detect_rpc_endpoint_from_node()
        .unwrap_or_else(|| crate::config::DEFAULT_RPC_ENDPOINT.to_string())
}

/// Present the network selection menu and apply the choice to `config`.
///
/// Loops until the chosen endpoint answers a probe (persisting it) or the user
/// cancels. The chosen endpoint is applied to `config` in memory and optionally
/// persisted (never creating a first config file silently).
fn pick_network_interactively(config: &mut crate::config::RussignolConfig) -> Result<bool> {
    let theme = crate::utils::create_orange_theme();
    let networks = order_for_picker(fetch_public_networks());
    let local_endpoint = local_system_endpoint();
    loop {
        let choices = build_network_choices(networks.clone(), local_endpoint.clone());
        let cursor = starting_cursor(&choices, &config.rpc_endpoint);

        let selected = inquire::Select::new("Which Tezos network?", choices)
            .with_starting_cursor(cursor)
            .with_help_message(
                "Baking requires your own node; public RPCs are fine for status and \
                 watermark reads.",
            )
            .with_render_config(theme)
            .prompt();

        let candidate = match selected {
            Ok(NetworkChoice::Network(n)) => n.rpc_url,
            Ok(NetworkChoice::Local(endpoint)) => endpoint,
            Ok(NetworkChoice::Custom) => {
                let entered = inquire::Text::new("Node IP address or RPC URL:")
                    .with_default(&config.rpc_endpoint)
                    .with_help_message(
                        "e.g. 192.168.1.50, 192.168.1.50:8732, or https://rpc.example.com",
                    )
                    .with_render_config(theme)
                    .prompt();
                match entered {
                    Ok(input) => match normalize_endpoint_input(&input) {
                        Ok(url) => url,
                        Err(e) => {
                            crate::utils::warning(&format!("{e}"));
                            continue;
                        }
                    },
                    Err(_) => continue,
                }
            }
            Ok(NetworkChoice::Cancel) | Err(_) => return Ok(false),
        };

        match probe_endpoint(&candidate) {
            Ok(()) => {
                crate::utils::success(&format!("Node responding at {candidate}"));
                if candidate != config.rpc_endpoint {
                    config.rpc_endpoint = candidate;
                    offer_to_persist(config);
                }
                return Ok(true);
            }
            Err(e) => {
                crate::utils::warning(&format!("No answer from {candidate}: {e:#}"));
            }
        }
    }
}

/// Ask the user which network to use, returning whether an endpoint now probes
/// OK. Shows the selection menu on every interactive run so a node is never
/// chosen silently.
///
/// Non-interactive runs (`yes` or no TTY) skip the menu: they probe the
/// configured endpoint and return whether it answered, so callers keep their
/// existing error paths and append `NON_INTERACTIVE_HINT`.
pub fn select_endpoint_interactively(
    config: &mut crate::config::RussignolConfig,
    yes: bool,
) -> Result<bool> {
    if yes || crate::confirmation::is_non_interactive() {
        return Ok(probe_endpoint(&config.rpc_endpoint).is_ok());
    }
    pick_network_interactively(config)
}

/// Offer to save the in-memory endpoint; asks before creating a config file
/// that doesn't exist yet.
fn offer_to_persist(config: &crate::config::RussignolConfig) {
    let Ok(path) = crate::config::RussignolConfig::config_path() else {
        return;
    };
    let question = if path.exists() {
        format!("Save {} as the default endpoint?", config.rpc_endpoint)
    } else {
        format!(
            "Create {} with {} as the default endpoint?",
            path.display(),
            config.rpc_endpoint
        )
    };
    let save = inquire::Confirm::new(&question)
        .with_default(path.exists())
        .with_render_config(crate::utils::create_orange_theme())
        .prompt()
        .unwrap_or(false);
    if save {
        match config.save() {
            Ok(()) => crate::utils::success("Endpoint saved"),
            Err(e) => crate::utils::warning(&format!("Could not save config: {e:#}")),
        }
    } else {
        crate::utils::info("Using this endpoint for this run only");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors the live shape of <https://teztnets.com/teztnets.json>
    fn teztnets_fixture() -> serde_json::Value {
        serde_json::json!({
            "mainnet": {
                "human_name": "Mainnet",
                "chain_name": "TEZOS_MAINNET",
                "rpc_url": "https://rpc.tzbeta.net",
                "category": "Long-running Teztnets",
                "masked_from_main_page": true
            },
            "shadownet": {
                "human_name": "Shadownet",
                "chain_name": "TEZOS_SHADOWNET_2026-01-07T12:00:00Z",
                "rpc_url": "https://rpc.shadownet.teztnets.com",
                "category": "Long-running Teztnets"
            },
            "currentnet": {
                "human_name": "Ushuaianet",
                "chain_name": "TEZOS_USHUAIANET_2026-04-21T14:00:00Z",
                "rpc_url": "https://rpc.currentnet.teztnets.com",
                "category": "Protocol Teztnets",
                "aliasOf": "ushuaianet"
            },
            "ushuaianet": {
                "human_name": "Ushuaianet",
                "chain_name": "TEZOS_USHUAIANET_2026-04-21T14:00:00Z",
                "rpc_url": "https://rpc.ushuaianet.teztnets.com",
                "category": "Protocol Teztnets"
            },
            "weeklynet-2026-07-01": {
                "human_name": "Weeklynet",
                "chain_name": "TEZOS-WEEKLYNET-2026-07-01T00:00:00Z",
                "rpc_url": "https://rpc.weeklynet-2026-07-01.teztnets.com",
                "category": "Periodic/Internal Teztnets"
            },
            "brokennet": {
                "human_name": "Brokennet",
                "chain_name": "TEZOS_BROKENNET",
                "category": "Long-running Teztnets"
            }
        })
    }

    #[test]
    fn parse_extracts_fields_and_categories() {
        let networks = parse_teztnets(&teztnets_fixture());
        let mainnet = networks
            .iter()
            .find(|n| n.human_name == "Mainnet")
            .expect("mainnet parsed");
        assert_eq!(mainnet.rpc_url, "https://rpc.tzbeta.net");
        assert_eq!(mainnet.chain_name, "TEZOS_MAINNET");
        assert_eq!(mainnet.category, NetworkCategory::Mainnet);

        let shadownet = networks
            .iter()
            .find(|n| n.human_name == "Shadownet")
            .expect("shadownet parsed");
        assert_eq!(shadownet.category, NetworkCategory::LongRunning);

        let weeklynet = networks
            .iter()
            .find(|n| n.human_name == "Weeklynet")
            .expect("weeklynet parsed");
        assert_eq!(weeklynet.category, NetworkCategory::Periodic);
    }

    #[test]
    fn parse_drops_aliases_and_entries_without_rpc() {
        let networks = parse_teztnets(&teztnets_fixture());
        assert_eq!(
            networks
                .iter()
                .filter(|n| n.human_name == "Ushuaianet")
                .count(),
            1,
            "alias entry must be dropped: {networks:?}"
        );
        assert!(
            !networks.iter().any(|n| n.human_name == "Brokennet"),
            "entry without rpc_url must be dropped"
        );
    }

    #[test]
    fn picker_order_is_mainnet_first_and_periodic_excluded() {
        let ordered = order_for_picker(parse_teztnets(&teztnets_fixture()));
        assert_eq!(ordered[0].human_name, "Mainnet");
        assert_eq!(ordered[1].category, NetworkCategory::LongRunning);
        assert!(
            !ordered
                .iter()
                .any(|n| n.category == NetworkCategory::Periodic),
            "periodic nets excluded: {ordered:?}"
        );
    }

    #[test]
    fn fallback_has_mainnet_and_shadownet_with_exact_urls() {
        let fallback = fallback_networks();
        assert!(fallback.iter().any(
            |n| n.category == NetworkCategory::Mainnet && n.rpc_url == "https://rpc.tzbeta.net"
        ));
        assert!(
            fallback.iter().any(|n| n.human_name == "Shadownet"
                && n.rpc_url == "https://rpc.shadownet.teztnets.com")
        );
    }

    #[test]
    fn hint_names_endpoint_flag_public_rpc_and_baking_caveat() {
        assert!(NON_INTERACTIVE_HINT.contains("--endpoint"));
        assert!(NON_INTERACTIVE_HINT.contains("rpc.tzbeta.net"));
        assert!(NON_INTERACTIVE_HINT.contains("own node"));
    }

    #[test]
    fn chain_name_resolves_to_human_name() {
        let networks = parse_teztnets(&teztnets_fixture());
        assert_eq!(
            human_name_for_chain("TEZOS_MAINNET", &networks),
            Some("Mainnet".to_string())
        );
        assert_eq!(human_name_for_chain("TEZOS_NOPE", &networks), None);
    }

    #[test]
    fn empty_chain_names_never_match() {
        let networks = vec![PublicNetwork {
            human_name: "Mystery".to_string(),
            chain_name: String::new(),
            rpc_url: "https://example.invalid".to_string(),
            category: NetworkCategory::LongRunning,
        }];
        assert_eq!(human_name_for_chain("", &networks), None);
    }

    #[test]
    fn normalize_bare_ip_gets_default_port() {
        assert_eq!(
            normalize_endpoint_input("192.168.1.50").unwrap(),
            "http://192.168.1.50:8732"
        );
    }

    #[test]
    fn normalize_host_port_gets_scheme_only() {
        assert_eq!(
            normalize_endpoint_input("192.168.1.50:8733").unwrap(),
            "http://192.168.1.50:8733"
        );
    }

    #[test]
    fn normalize_full_url_passthrough_and_strips_trailing_slash() {
        assert_eq!(
            normalize_endpoint_input("https://rpc.tzbeta.net/").unwrap(),
            "https://rpc.tzbeta.net"
        );
        assert_eq!(
            normalize_endpoint_input("http://localhost:8732").unwrap(),
            "http://localhost:8732"
        );
    }

    #[test]
    fn normalize_rejects_empty_and_garbage() {
        assert!(normalize_endpoint_input("   ").is_err());
        assert!(normalize_endpoint_input("has space").is_err());
        assert!(normalize_endpoint_input("no/scheme/path").is_err());
        assert!(normalize_endpoint_input("http://").is_err());
    }

    #[test]
    fn choices_list_mainnet_first_then_local_custom_cancel() {
        let networks = order_for_picker(parse_teztnets(&teztnets_fixture()));
        let choices = build_network_choices(networks, "http://localhost:8732".to_string());

        assert!(
            matches!(&choices[0], NetworkChoice::Network(n) if n.human_name == "Mainnet"),
            "first entry is Mainnet"
        );
        let n = choices.len();
        assert!(matches!(&choices[n - 3], NetworkChoice::Local(e) if e == "http://localhost:8732"));
        assert!(matches!(choices[n - 2], NetworkChoice::Custom));
        assert!(matches!(choices[n - 1], NetworkChoice::Cancel));
    }

    #[test]
    fn choices_offline_still_offer_local_mainnet_and_custom() {
        let choices = build_network_choices(
            order_for_picker(fallback_networks()),
            "http://localhost:8732".to_string(),
        );
        assert!(choices.iter().any(|c| matches!(c, NetworkChoice::Local(_))));
        assert!(choices.iter().any(|c| matches!(c, NetworkChoice::Custom)));
        assert!(
            choices
                .iter()
                .any(|c| matches!(c, NetworkChoice::Network(n) if n.human_name == "Mainnet"))
        );
    }

    #[test]
    fn starting_cursor_matches_local_and_network_endpoints() {
        let choices = build_network_choices(
            order_for_picker(fallback_networks()),
            "http://localhost:8732".to_string(),
        );

        let local_idx = choices
            .iter()
            .position(|c| matches!(c, NetworkChoice::Local(_)))
            .unwrap();
        assert_eq!(
            starting_cursor(&choices, "http://localhost:8732"),
            local_idx
        );

        let main_idx = choices
            .iter()
            .position(|c| matches!(c, NetworkChoice::Network(n) if n.human_name == "Mainnet"))
            .unwrap();
        assert_eq!(
            starting_cursor(&choices, "https://rpc.tzbeta.net"),
            main_idx
        );
    }

    #[test]
    fn starting_cursor_defaults_to_zero_when_no_match() {
        let choices = build_network_choices(
            order_for_picker(fallback_networks()),
            "http://localhost:8732".to_string(),
        );
        assert_eq!(starting_cursor(&choices, "https://nowhere.invalid"), 0);
    }
}
