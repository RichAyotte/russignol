//! russignol-signer CLI - High-performance BLS12-381 signer for Tezos
//!
//! Command-line interface matching the OCaml russignol-signer behavior

use clap::{Parser, Subcommand};
use russignol_signer_lib::{
    HighWatermark, RequestHandler, ServerKeyManager, SignerServer, UnencryptedSigner,
    wallet::KeyManager,
};
use std::fs;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "russignol-signer")]
#[command(about = "High-performance BLS12-381 signer for Tezos", long_about = None)]
#[command(version)]
struct Cli {
    /// Signer data directory
    #[arg(short = 'd', long = "base-dir", global = true)]
    base_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all known addresses
    #[command(name = "list")]
    List {
        #[command(subcommand)]
        subcommand: ListCommand,
    },
    /// Show address details
    #[command(name = "show")]
    Show {
        #[command(subcommand)]
        subcommand: ShowCommand,
    },
    /// Launch signer daemon
    #[command(name = "launch")]
    Launch {
        #[command(subcommand)]
        subcommand: LaunchCommand,
    },
}

#[derive(Subcommand)]
enum ListCommand {
    /// List known addresses
    Known {
        /// addresses
        addresses: Option<String>,
    },
}

#[derive(Subcommand)]
enum ShowCommand {
    /// Show address
    Address {
        /// Alias of the key
        name: String,
    },
}

#[derive(Subcommand)]
enum LaunchCommand {
    /// Launch socket signer
    Socket {
        /// signer
        signer: Option<String>,

        /// Listen address
        #[arg(short = 'a', long, default_value = "localhost")]
        address: String,

        /// Listen port
        #[arg(short = 'p', long, default_value = "7732")]
        port: u16,

        /// Magic bytes filter (comma-separated hex, e.g. 0x11,0x12,0x13)
        #[arg(short = 'M', long)]
        magic_bytes: Option<String>,

        /// Enable high watermark protection
        #[arg(short = 'W', long)]
        check_high_watermark: bool,

        /// Allow listing known keys
        #[arg(long)]
        allow_list_known_keys: bool,

        /// Allow proof of possession
        #[arg(long)]
        allow_to_prove_possession: bool,

        /// Require authentication (not yet implemented)
        #[arg(short = 'A', long)]
        require_authentication: bool,

        /// Connection timeout in seconds
        #[arg(short = 't', long)]
        timeout: Option<u64>,

        /// PID file path
        #[arg(short = 'P', long)]
        pidfile: Option<PathBuf>,
    },
}

fn list_known_addresses(key_manager: &KeyManager) {
    let keys = key_manager.load_keys();

    if keys.is_empty() {
        println!("No known keys.");
        return;
    }

    println!("\nKnown keys:");
    println!("{:<20} {:<10}", "Alias", "Address");
    println!("{}", "=".repeat(60));

    for (alias, key) in &keys {
        println!("{alias:<20} {}", key.public_key_hash);
    }
}

fn show_address(key_manager: &KeyManager, name: &str) -> Result<(), String> {
    let keys = key_manager.load_keys();

    let key = keys
        .get(name)
        .ok_or_else(|| format!("Key '{name}' not found"))?;

    println!("\nKey: {name}");
    println!("  Public Key Hash: {}", key.public_key_hash);
    println!("  Public Key:      {}", key.public_key);

    Ok(())
}

/// Parse magic bytes from string like "0x11,0x12,0x13"
fn parse_magic_bytes(s: &str) -> Result<Vec<u8>, String> {
    s.split(',')
        .map(|part| {
            let part = part.trim();
            if let Some(hex) = part.strip_prefix("0x") {
                u8::from_str_radix(hex, 16).map_err(|e| format!("Invalid hex value '{part}': {e}"))
            } else {
                part.parse::<u8>()
                    .map_err(|e| format!("Invalid byte value '{part}': {e}"))
            }
        })
        .collect()
}

/// Write PID file
fn write_pid_file(path: &PathBuf) -> Result<(), String> {
    let pid = std::process::id();
    fs::write(path, pid.to_string()).map_err(|e| format!("Failed to write PID file: {e}"))
}

/// Options for the socket signer daemon
#[expect(
    clippy::struct_excessive_bools,
    reason = "CLI flags map to individual bools"
)]
struct SocketSignerOptions {
    address: String,
    port: u16,
    magic_bytes: Option<String>,
    check_high_watermark: bool,
    allow_list_known_keys: bool,
    allow_to_prove_possession: bool,
    require_authentication: bool,
    timeout: Option<u64>,
    pidfile: Option<PathBuf>,
}

/// Launch socket signer daemon
fn launch_socket_signer(
    cli_key_manager: &KeyManager,
    opts: &SocketSignerOptions,
) -> Result<(), String> {
    // Parse magic bytes if provided
    let magic_bytes_filter = if let Some(mb_str) = &opts.magic_bytes {
        Some(parse_magic_bytes(mb_str)?)
    } else {
        None
    };

    // Load all keys from storage
    let keys = cli_key_manager.load_keys();

    if keys.is_empty() {
        return Err(
            "No keys found. Generate keys first with: russignol-signer gen keys <name> --sig bls"
                .to_string(),
        );
    }

    let key_count = keys.len();
    println!("Loading {key_count} key(s)...");

    // Create server key manager and load signers
    let mut server_key_mgr = ServerKeyManager::new();

    for (alias, stored_key) in &keys {
        if let Some(sk_b58) = &stored_key.secret_key {
            match UnencryptedSigner::from_b58check(sk_b58) {
                Ok(signer) => {
                    // Now that we handle little-endian correctly, the derived PKH matches OCaml
                    let derived_pkh = *signer.public_key_hash();
                    let derived_pkh_b58 = derived_pkh.to_b58check();
                    server_key_mgr.add_signer(derived_pkh, signer, alias.clone());
                    let json_pkh = &stored_key.public_key_hash;
                    println!(
                        "  ✓ Loaded key: {alias} (JSON: {json_pkh}, Derived: {derived_pkh_b58})"
                    );
                }
                Err(e) => {
                    eprintln!("  ✗ Failed to load key '{alias}': {e}");
                }
            }
        }
    }

    // Setup high watermark if enabled
    let watermark = if opts.check_high_watermark {
        // OCaml stores watermark files directly in base_dir (not in a subdirectory)
        // Files: block_high_watermark, attestation_high_watermark, preattestation_high_watermark
        let hwm = HighWatermark::new(cli_key_manager.base_dir())
            .map_err(|e| format!("Failed to create high watermark: {e}"))?;

        println!("✓ High watermark protection enabled");
        let storage_path = cli_key_manager.base_dir().display();
        println!("  Storage: {storage_path}");
        Some(Arc::new(RwLock::new(hwm)))
    } else {
        println!("⚠ High watermark protection DISABLED");
        None
    };

    // Check authentication flag
    if opts.require_authentication {
        return Err("Authentication is not yet implemented (Phase 4). Remove --require-authentication flag.".to_string());
    }

    // Create request handler
    let handler = RequestHandler::new(
        Arc::new(RwLock::new(server_key_mgr)),
        watermark,
        magic_bytes_filter.clone(),
        opts.allow_list_known_keys,
        opts.allow_to_prove_possession,
    );

    // Create server
    // Resolve hostname to socket address
    let address = &opts.address;
    let port = opts.port;
    let addr_str = format!("{address}:{port}");
    let addr = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve address '{addr_str}': {e}"))?
        .next()
        .ok_or_else(|| format!("No addresses found for '{addr_str}'"))?;

    let timeout_duration = opts.timeout.map(Duration::from_secs);

    let server = SignerServer::new(addr, Arc::new(handler), timeout_duration);

    // Write PID file if requested
    if let Some(ref pidfile_path) = opts.pidfile {
        write_pid_file(pidfile_path)?;
        let pidfile_display = pidfile_path.display();
        println!("✓ PID file written: {pidfile_display}");
    }

    // Print configuration
    println!("\n📋 Configuration:");
    println!("  Listen address: {addr}");
    if let Some(ref mb) = magic_bytes_filter {
        let mb_str = mb
            .iter()
            .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  Magic bytes: {mb_str}");
    } else {
        println!("  Magic bytes: None (all operations allowed)");
    }
    if let Some(t) = opts.timeout {
        println!("  Timeout: {t}s");
    } else {
        println!("  Timeout: None");
    }

    // Start server
    println!("\n🚀 Starting signer server on {addr}");
    println!("📡 Waiting for connections...");
    println!("\nPress Ctrl+C to stop\n");

    // Set up Ctrl+C handler - just let it terminate the process naturally
    // The server will run in the main thread
    server.run().map_err(|e| format!("Server error: {e}"))
}

fn main() {
    let cli = Cli::parse();
    let key_manager = KeyManager::new(cli.base_dir.clone());

    let result = match cli.command {
        Commands::List { subcommand } => match subcommand {
            ListCommand::Known { addresses: _ } => {
                list_known_addresses(&key_manager);
                Ok(())
            }
        },
        Commands::Show { subcommand } => match subcommand {
            ShowCommand::Address { name } => show_address(&key_manager, &name),
        },
        Commands::Launch { subcommand } => match subcommand {
            LaunchCommand::Socket {
                signer: _,
                address,
                port,
                magic_bytes,
                check_high_watermark,
                allow_list_known_keys,
                allow_to_prove_possession,
                require_authentication,
                timeout,
                pidfile,
            } => {
                let opts = SocketSignerOptions {
                    address,
                    port,
                    magic_bytes,
                    check_high_watermark,
                    allow_list_known_keys,
                    allow_to_prove_possession,
                    require_authentication,
                    timeout,
                    pidfile,
                };
                launch_socket_signer(&key_manager, &opts)
            }
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
