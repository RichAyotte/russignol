// E2E test code - pedantic lints relaxed for test readability
#![expect(clippy::unused_self, reason = "test context methods may not use self")]
#![expect(
    clippy::cast_possible_truncation,
    reason = "protocol u16 lengths handled"
)]
#![expect(
    clippy::too_many_lines,
    reason = "test functions naturally comprehensive"
)]
#![expect(
    clippy::unnecessary_wraps,
    reason = "Result return type for test consistency"
)]
#![expect(
    clippy::assigning_clones,
    reason = "clone optimization not critical in tests"
)]

//! Watermark Protection End-to-End Test
//!
//! Comprehensive test suite for validating watermark protection on a Russignol device.
//!
//! # Usage
//!
//! ```bash
//! # Run all tests against default device (169.254.1.1:7732)
//! cargo run --example watermark_e2e_test
//!
//! # Run against specific device
//! cargo run --example watermark_e2e_test -- --device 192.168.1.100:7732
//!
//! # Run specific test category
//! cargo run --example watermark_e2e_test -- --category basic
//!
//! # Verbose output
//! cargo run --example watermark_e2e_test -- --verbose
//! ```

use colored::Colorize;
use russignol_signer_lib::{
    ChainId,
    bls::PublicKeyHash,
    protocol::{
        SignerRequest, SignerResponse,
        encoding::{decode_response, encode_request},
    },
    test_utils::{
        create_attestation_data_with_chain, create_block_data_with_chain,
        create_preattestation_data_with_chain,
    },
};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Prompt user and wait for ENTER with proper blocking and error handling.
fn wait_for_user(prompt: &str) -> Result<(), Box<dyn std::error::Error>> {
    print!("{prompt}");
    std::io::Write::flush(&mut std::io::stdout())?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    Ok(())
}

/// Wait for the operator to dismiss a watermark dialog on the device.
/// Used after tests that trigger "Level too low" errors, which show a dialog
/// with a "Set level to N" button and Cancel. `expected_dialog` describes what
/// the dialog should show.
fn wait_for_reset_dialog(expected_dialog: &str) -> Result<(), String> {
    println!();
    println!(
        "    The device should be showing: {}",
        expected_dialog.yellow()
    );
    println!("    This is a watermark dialog with a \"Set level to N\" button and Cancel.");
    println!("    Press Cancel on the device to dismiss it (keep the current watermark).");
    println!("    Press ENTER here when the device shows the home screen...");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Prompt the operator to confirm or cancel the watermark dialog on the device.
/// Returns Ok(true) if they confirmed ("Set level to N"), Ok(false) if they
/// cancelled, or Err if the input was invalid.
fn handle_watermark_error(error_msg: &str) -> Result<bool, String> {
    println!();
    println!(
        "    {}",
        "══════════════════════════════════════════════════════════".yellow()
    );
    println!(
        "    {}",
        "  WATERMARK ERROR - Device interaction required           "
            .yellow()
            .bold()
    );
    println!(
        "    {}",
        "══════════════════════════════════════════════════════════".yellow()
    );
    println!("    Error: {}", error_msg.dimmed());
    println!();
    println!("    The device should be showing a watermark dialog.");
    println!("    Interact with the device, then tell me what you did:");
    println!(
        "       [S] = Pressed \"Set level to N\" on the device (sets the watermark), then press S here"
    );
    println!(
        "       [C] = Pressed Cancel on the device (keeps the current watermark), then press C here"
    );
    print!("    Your choice: ");
    std::io::Write::flush(&mut std::io::stdout()).map_err(|e| e.to_string())?;

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    let choice = input.trim().to_lowercase();

    println!("    Press ENTER when the device shows the home screen...");
    let mut ready = String::new();
    std::io::stdin()
        .read_line(&mut ready)
        .map_err(|e| e.to_string())?;

    if choice == "s" || choice == "set" {
        println!("    Watermark level set on the device.");
        Ok(true)
    } else if choice == "c" || choice == "cancel" {
        println!("    Watermark unchanged.");
        Ok(false)
    } else {
        Err(format!("Invalid choice '{choice}'. Please enter S or C."))
    }
}

/// Assert a Sign response is the chain-mismatch rejection. A foreign chain is
/// refused before any watermark logic, so the message names the mismatch and
/// never a level/round error — any other outcome (including a signature) fails.
fn expect_chain_mismatch(response: SignerResponse) -> Result<(), String> {
    match response {
        SignerResponse::Error(e) if e.contains("Chain mismatch") => Ok(()),
        SignerResponse::Error(e) => Err(format!("Expected a chain-mismatch rejection, got: {e}")),
        SignerResponse::Signature(_) => {
            Err("SECURITY FAILURE: Signed an operation for a foreign chain!".to_string())
        }
        other => Err(format!("Unexpected response: {other:?}")),
    }
}

/// Default device address (link-local USB)
const DEFAULT_DEVICE: &str = "169.254.1.1:7732";

/// A chain the device is never provisioned for. Signing an operation on it must
/// be rejected outright. These are Tezos mainnet's chain bytes: a test/staging
/// device is provisioned for a testnet, so mainnet is always foreign. `main`
/// refuses to run if the provisioned chain equals this, so the rejection tests
/// can never silently pass by signing the "foreign" chain.
const FOREIGN_CHAIN: [u8; 4] = [0x7a, 0x06, 0xa7, 0x70];

/// First level handed out by the shared cursor. The device's first block sign
/// recovers a missing watermark to this level (setting every op-type's floor),
/// so it must sit above any leftover floor a prior run may have lowered.
const LEVEL_BASE: u32 = 100;

/// Gap between successive cursor hand-outs. Wide enough for a test's local
/// offsets (a few levels up or down within its band) without overlapping the
/// neighbouring test's band.
const LEVEL_STRIDE: u32 = 10;

/// Fixed low level the interactive test signs to trip a "level too low" dialog.
/// Below [`LEVEL_BASE`], so it is always under the floor the earlier tests
/// raised, independent of how far the cursor has advanced.
const INTERACTIVE_TRIGGER_LEVEL: u32 = 50;

/// Test result
struct TestResult {
    name: String,
    passed: bool,
    error: Option<String>,
    duration: Duration,
}

/// Test context with device connection info
struct TestContext {
    device_addr: SocketAddr,
    pkh: Option<PublicKeyHash>,
    verbose: bool,
    /// The chain the device is provisioned for; every valid sign targets it.
    provisioned_chain: [u8; 4],
    /// Next level to hand out. Under single-chain enforcement all signs share
    /// one chain, so a (key, op-type) floor rises across every test. A single
    /// cursor keeps each hand-out above the current floor for every op-type; it
    /// is shared (not per-op-type) because the large-gap check compares against
    /// the global max level across op-types, so levels must climb together.
    next_level: Cell<u32>,
}

impl TestContext {
    fn new(
        device: &str,
        provisioned_chain: [u8; 4],
        verbose: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let device_addr: SocketAddr = device.parse()?;

        Ok(Self {
            device_addr,
            pkh: None,
            verbose,
            provisioned_chain,
            next_level: Cell::new(LEVEL_BASE),
        })
    }

    /// Reserve the next level band, returning its base. Callers use the base and
    /// a few levels around it; the stride keeps bands from overlapping.
    fn reserve_level(&self) -> u32 {
        let base = self.next_level.get();
        self.next_level.set(base + LEVEL_STRIDE);
        base
    }

    /// Block operation data on the provisioned chain.
    fn block(&self, level: u32, round: u32) -> Vec<u8> {
        create_block_data_with_chain(&self.provisioned_chain, level, round)
    }

    /// Attestation operation data on the provisioned chain.
    fn attestation(&self, level: u32, round: u32) -> Vec<u8> {
        create_attestation_data_with_chain(&self.provisioned_chain, level, round)
    }

    /// Preattestation operation data on the provisioned chain.
    fn preattestation(&self, level: u32, round: u32) -> Vec<u8> {
        create_preattestation_data_with_chain(&self.provisioned_chain, level, round)
    }

    /// Open a fresh connection, send a Sign request, and return the response.
    /// A new connection per request matches the device closing on error.
    fn sign(&self, pkh: PublicKeyHash, data: Vec<u8>) -> Result<SignerResponse, String> {
        let mut stream = self.connect().map_err(|e| e.to_string())?;
        let request = SignerRequest::Sign {
            pkh: (pkh, 0),
            data,
            signature: None,
        };
        self.send_request(&mut stream, &request)
            .map_err(|e| e.to_string())
    }

    /// Sign and require a signature, logging `what` on success.
    fn expect_signature(
        &self,
        pkh: PublicKeyHash,
        data: Vec<u8>,
        what: &str,
    ) -> Result<(), String> {
        match self.sign(pkh, data)? {
            SignerResponse::Signature(_) => {
                self.log(&format!("{what}: OK"));
                Ok(())
            }
            other => Err(format!("{what} expected a signature, got: {other:?}")),
        }
    }

    fn connect(&self) -> Result<TcpStream, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect_timeout(&self.device_addr, Duration::from_secs(10))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(stream)
    }

    fn send_request(
        &self,
        stream: &mut TcpStream,
        request: &SignerRequest,
    ) -> Result<SignerResponse, Box<dyn std::error::Error>> {
        let request_data = encode_request(request)?;

        // Send length-prefixed message (2-bytes u16)
        let len = (request_data.len() as u16).to_be_bytes();
        stream.write_all(&len)?;
        stream.write_all(&request_data)?;
        stream.flush()?;

        // Read response length (2-bytes u16)
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf)?;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        // Read response data
        let mut response_data = vec![0u8; response_len];
        stream.read_exact(&mut response_data)?;

        // Decode response
        let response = decode_response(&response_data, request)?;
        Ok(response)
    }

    fn log(&self, msg: &str) {
        if self.verbose {
            println!("    {}", msg.dimmed());
        }
    }
}

/// Test suite runner
struct TestSuite {
    ctx: TestContext,
    results: Vec<TestResult>,
    category_filter: Option<String>,
    /// Set to true when any test fails; subsequent tests are skipped
    failed: bool,
}

impl TestSuite {
    fn new(ctx: TestContext, category_filter: Option<String>) -> Self {
        Self {
            ctx,
            results: Vec::new(),
            category_filter,
            failed: false,
        }
    }

    fn should_run_category(&self, category: &str) -> bool {
        match &self.category_filter {
            Some(filter) => {
                let filter_lower = filter.to_lowercase();
                let category_lower = category.to_lowercase();
                // Match if either contains the other (e.g., "interactive-reset" matches "interactive")
                filter_lower.contains(&category_lower) || category_lower.contains(&filter_lower)
            }
            None => true,
        }
    }

    fn run_all(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "═══════════════════════════════════════════════════════════════"
                .blue()
                .bold()
        );
        println!(
            "{}",
            "        RUSSIGNOL WATERMARK E2E TEST SUITE".blue().bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════"
                .blue()
                .bold()
        );
        println!("Device: {}", self.ctx.device_addr.to_string().cyan());
        println!();

        // First, discover the PKH from the device
        self.discover_pkh()?;

        if self.should_run_category("basic") && !self.failed {
            self.run_category_basic()?;
        }

        if (self.should_run_category("multi") || self.should_run_category("operation"))
            && !self.failed
        {
            self.run_category_multi_operation()?;
        }

        if (self.should_run_category("chain") || self.should_run_category("enforcement"))
            && !self.failed
        {
            self.run_category_chain_enforcement()?;
        }

        if self.should_run_category("edge") && !self.failed {
            self.run_category_edge_cases()?;
        }

        if (self.should_run_category("interactive") || self.should_run_category("reset"))
            && !self.failed
        {
            self.run_category_interactive_reset()?;
        }

        self.print_summary();
        Ok(())
    }

    fn discover_pkh(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        print!("{}", "Checking device connection... ".cyan());
        std::io::Write::flush(&mut std::io::stdout()).ok();

        // Try to connect - if it fails, device is likely locked
        let mut stream = if let Ok(s) = self.ctx.connect() {
            println!("{}", "connected".green());
            s
        } else {
            println!("{}", "not ready".yellow());
            println!();
            println!(
                "{}",
                "══════════════════════════════════════════════════════════".yellow()
            );
            println!(
                "{}",
                "  Device is locked. Enter your PIN on the device.        "
                    .yellow()
                    .bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════".yellow()
            );
            println!();
            println!("Press ENTER when the device is unlocked...");

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            // Try to connect again
            print!("{}", "Reconnecting... ".cyan());
            std::io::Write::flush(&mut std::io::stdout()).ok();
            match self.ctx.connect() {
                Ok(s) => {
                    println!("{}", "connected".green());
                    s
                }
                Err(e) => {
                    println!("{}", "failed".red());
                    return Err(format!("Still cannot connect to device: {e}").into());
                }
            }
        };

        println!("{}", "Discovering device keys...".cyan());
        let request = SignerRequest::KnownKeys;
        let response = self.ctx.send_request(&mut stream, &request)?;

        match response {
            SignerResponse::KnownKeys(keys) => {
                if keys.is_empty() {
                    return Err("No keys found on device".into());
                }
                self.ctx.pkh = Some(keys[0]);
                println!(
                    "  {} Using key: {}",
                    "✓".green(),
                    keys[0].to_b58check().yellow()
                );
                if keys.len() > 1 {
                    println!(
                        "  {} Device has {} keys, using first one",
                        "ℹ".blue(),
                        keys.len()
                    );
                }
            }
            SignerResponse::Error(e) => {
                return Err(format!("Failed to get keys: {e}").into());
            }
            _ => {
                return Err("Unexpected response type".into());
            }
        }

        println!();
        Ok(())
    }

    fn run_test<F>(&mut self, name: &str, test_fn: F)
    where
        F: FnOnce(&TestContext, PublicKeyHash) -> Result<(), String>,
    {
        // Skip if a previous test has already failed
        if self.failed {
            return;
        }

        let Some(pkh) = self.ctx.pkh else {
            self.results.push(TestResult {
                name: name.to_string(),
                passed: false,
                error: Some("No PKH available".to_string()),
                duration: Duration::ZERO,
            });
            self.failed = true;
            return;
        };

        print!("  Test: {name} ... ");
        std::io::stdout().flush().ok();

        let start = Instant::now();
        match test_fn(&self.ctx, pkh) {
            Ok(()) => {
                let duration = start.elapsed();
                println!("{} ({:.0?})", "PASS".green().bold(), duration);
                self.results.push(TestResult {
                    name: name.to_string(),
                    passed: true,
                    error: None,
                    duration,
                });
            }
            Err(e) => {
                let duration = start.elapsed();
                println!("{}", "FAIL".red().bold());
                println!("    Error: {}", e.red());
                self.results.push(TestResult {
                    name: name.to_string(),
                    passed: false,
                    error: Some(e),
                    duration,
                });
                self.failed = true;
            }
        }
    }

    fn run_category_basic(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "─── Category 1: Basic Validation ───────────────────────────────"
                .cyan()
                .bold()
        );

        // Test 1.1: Forward progression (block)
        self.run_test("1.1 Forward progression (block)", |ctx, pkh| {
            // Establish the baseline at the first cursor level. On a freshly
            // cleaned device the block watermark is missing, so the device shows
            // a "Set level to N" recovery dialog; confirming it sets every
            // op-type's floor to N. The floor records N as signed, so re-signing N
            // is a replay — forward progression is proven by the N+1 signature
            // below, not by retrying N.
            let base = ctx.reserve_level();
            match ctx.sign(pkh, ctx.block(base, 0))? {
                SignerResponse::Signature(_) => ctx.log(&format!("Signed level {base}")),
                SignerResponse::Error(ref e) if e.contains("not initialized") => {
                    // Missing watermark: the device shows the recovery dialog.
                    if !handle_watermark_error(e)? {
                        return Err(format!("Operator cancelled the watermark dialog: {e}"));
                    }
                    ctx.log(&format!("Recovered missing watermark to level {base}"));
                }
                SignerResponse::Error(ref e) => {
                    return Err(format!(
                        "Watermark already initialized at or above level {base} ({e}); \
                         run with --clean to reset it first"
                    ));
                }
                other => {
                    return Err(format!(
                        "Expected signature at level {base}, got: {other:?}"
                    ));
                }
            }

            // Prove forward progression: N+1 must sign (N+1 > the level-N floor).
            ctx.expect_signature(
                pkh,
                ctx.block(base + 1, 0),
                &format!("Block level {}", base + 1),
            )
        });

        // Test 1.2: Reject lower level (block)
        self.run_test("1.2 Reject lower level (block)", |ctx, pkh| {
            let base = ctx.reserve_level();
            ctx.expect_signature(pkh, ctx.block(base, 0), &format!("Block level {base}"))?;

            match ctx.sign(pkh, ctx.block(base - 1, 0))? {
                SignerResponse::Error(e) if e.contains("Level too low") || e.contains("level") => {
                    ctx.log(&format!("Correctly rejected level {}", base - 1));
                    wait_for_reset_dialog(&format!(
                        "Level too low: \"Set level to {}\" dialog (watermark at {base})",
                        base - 1
                    ))?;
                    Ok(())
                }
                SignerResponse::Error(e) => Err(format!("Got error but unexpected message: {e}")),
                SignerResponse::Signature(_) => {
                    Err("SECURITY FAILURE: Signed at lower level!".to_string())
                }
                other => Err(format!("Unexpected response: {other:?}")),
            }
        });

        // Test 1.3: Reject lower round at same level (block)
        self.run_test("1.3 Reject lower round at same level", |ctx, pkh| {
            let base = ctx.reserve_level();
            ctx.expect_signature(pkh, ctx.block(base, 5), &format!("Block {base}/round 5"))?;

            match ctx.sign(pkh, ctx.block(base, 4))? {
                SignerResponse::Error(e) if e.contains("Round too low") || e.contains("round") => {
                    ctx.log("Correctly rejected round 4 (no dialog shown)");
                    Ok(())
                }
                SignerResponse::Error(e) => Err(format!("Got error but unexpected message: {e}")),
                SignerResponse::Signature(_) => {
                    Err("SECURITY FAILURE: Signed at lower round!".to_string())
                }
                other => Err(format!("Unexpected response: {other:?}")),
            }
        });

        // Test 1.4: Allow higher round at same level
        self.run_test("1.4 Allow higher round at same level", |ctx, pkh| {
            let base = ctx.reserve_level();
            ctx.expect_signature(pkh, ctx.block(base, 5), &format!("Block {base}/round 5"))?;
            ctx.expect_signature(pkh, ctx.block(base, 6), &format!("Block {base}/round 6"))
        });

        // Test 1.5: Forward progression (attestation)
        self.run_test("1.5 Forward progression (attestation)", |ctx, pkh| {
            let base = ctx.reserve_level();
            ctx.expect_signature(
                pkh,
                ctx.attestation(base, 0),
                &format!("Attestation {base}"),
            )?;
            ctx.expect_signature(
                pkh,
                ctx.attestation(base + 1, 0),
                &format!("Attestation {}", base + 1),
            )
        });

        // Test 1.6: Reject lower level (attestation)
        self.run_test("1.6 Reject lower level (attestation)", |ctx, pkh| {
            let base = ctx.reserve_level();
            ctx.expect_signature(
                pkh,
                ctx.attestation(base, 0),
                &format!("Attestation {base}"),
            )?;

            match ctx.sign(pkh, ctx.attestation(base - 1, 0))? {
                SignerResponse::Error(e) if e.contains("Level too low") || e.contains("level") => {
                    ctx.log(&format!(
                        "Correctly rejected attestation level {}",
                        base - 1
                    ));
                    wait_for_reset_dialog(&format!(
                        "Level too low: \"Set level to {}\" dialog (watermark at {base})",
                        base - 1
                    ))?;
                    Ok(())
                }
                SignerResponse::Error(e) => Err(format!("Got error but unexpected message: {e}")),
                SignerResponse::Signature(_) => {
                    Err("SECURITY FAILURE: Signed attestation at lower level!".to_string())
                }
                other => Err(format!("Unexpected response: {other:?}")),
            }
        });

        // Test 1.7: Forward progression (preattestation)
        self.run_test("1.7 Forward progression (preattestation)", |ctx, pkh| {
            let base = ctx.reserve_level();
            ctx.expect_signature(
                pkh,
                ctx.preattestation(base, 0),
                &format!("Preattestation {base}"),
            )?;
            ctx.expect_signature(
                pkh,
                ctx.preattestation(base + 1, 0),
                &format!("Preattestation {}", base + 1),
            )
        });

        Ok(())
    }

    fn run_category_multi_operation(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "─── Category 2: Multi-Operation Isolation ─────────────────────"
                .cyan()
                .bold()
        );

        // Test 2.1: Independent watermarks per operation type
        self.run_test("2.1 Independent watermarks per op type", |ctx, pkh| {
            // Block at the band's top, then attestation and preattestation just
            // below it. Both succeed only because each op-type keeps its own
            // floor: if the floor were shared, a level below the just-signed block
            // would be rejected. base-1 and base-2 still clear their own floors,
            // which the earlier Category 1 signs left well below this band.
            let base = ctx.reserve_level();
            ctx.expect_signature(pkh, ctx.block(base, 0), &format!("Block {base}"))?;
            ctx.expect_signature(
                pkh,
                ctx.attestation(base - 1, 0),
                &format!("Attestation {} below block {base}", base - 1),
            )?;
            ctx.expect_signature(
                pkh,
                ctx.preattestation(base - 2, 0),
                &format!("Preattestation {} below block {base}", base - 2),
            )?;

            // Block just below its own floor must still be rejected.
            match ctx.sign(pkh, ctx.block(base - 1, 0))? {
                SignerResponse::Error(_) => {
                    ctx.log(&format!("Block at {} correctly rejected", base - 1));
                    wait_for_reset_dialog(&format!(
                        "Level too low: \"Set level to {}\" dialog (watermark at {base})",
                        base - 1
                    ))?;
                    Ok(())
                }
                SignerResponse::Signature(_) => {
                    Err("SECURITY FAILURE: Block signed below watermark!".to_string())
                }
                other => Err(format!("Unexpected response: {other:?}")),
            }
        });

        Ok(())
    }

    fn run_category_chain_enforcement(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "─── Category 3: Chain Enforcement ─────────────────────────────"
                .cyan()
                .bold()
        );

        // Test 3.1: Foreign-chain block is rejected
        self.run_test("3.1 Foreign-chain block rejected", |ctx, pkh| {
            let base = ctx.reserve_level();
            ctx.expect_signature(
                pkh,
                ctx.block(base, 0),
                &format!("Provisioned block {base}"),
            )?;

            // A block for a chain the device was not provisioned for is rejected
            // before any watermark check, so its level is irrelevant.
            let foreign = create_block_data_with_chain(&FOREIGN_CHAIN, base + 1, 0);
            expect_chain_mismatch(ctx.sign(pkh, foreign)?)
        });

        // Test 3.2: Foreign-chain attestation is rejected
        self.run_test("3.2 Foreign-chain attestation rejected", |ctx, pkh| {
            let base = ctx.reserve_level();
            ctx.expect_signature(
                pkh,
                ctx.attestation(base, 0),
                &format!("Provisioned attestation {base}"),
            )?;

            let foreign = create_attestation_data_with_chain(&FOREIGN_CHAIN, base + 1, 0);
            expect_chain_mismatch(ctx.sign(pkh, foreign)?)
        });

        Ok(())
    }

    fn run_category_edge_cases(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "─── Category 4: Edge Cases ────────────────────────────────────"
                .cyan()
                .bold()
        );

        // Test 4.3: Same level, same round (replay attempt)
        self.run_test("4.3 Replay attempt (same level/round)", |ctx, pkh| {
            let base = ctx.reserve_level();
            let data = ctx.block(base, 3);
            ctx.expect_signature(pkh, data.clone(), &format!("Block {base}/round 3"))?;

            // Same level/round again is a replay: the round must be strictly higher.
            match ctx.sign(pkh, data)? {
                SignerResponse::Error(e) if e.contains("Round too low") || e.contains("round") => {
                    ctx.log("Replay correctly rejected (no dialog shown)");
                    Ok(())
                }
                SignerResponse::Error(e) => Err(format!("Got error but unexpected message: {e}")),
                SignerResponse::Signature(_) => {
                    Err("SECURITY FAILURE: Replay produced a signature!".to_string())
                }
                other => Err(format!("Unexpected response: {other:?}")),
            }
        });

        // Test 4.4: Invalid magic byte
        self.run_test("4.4 Invalid magic byte rejection", |ctx, pkh| {
            // An invalid magic byte is rejected before chain/watermark checks, so
            // the level and chain are irrelevant here.
            let mut data = ctx.block(1, 0);
            data[0] = 0xFF;

            match ctx.sign(pkh, data)? {
                SignerResponse::Error(e) => {
                    ctx.log(&format!("Correctly rejected invalid magic: {e}"));
                    Ok(())
                }
                SignerResponse::Signature(_) => {
                    Err("Should not sign data with invalid magic byte".to_string())
                }
                other => Err(format!("Unexpected response: {other:?}")),
            }
        });

        Ok(())
    }

    fn run_category_interactive_reset(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "─── Category 5: Interactive Set Level ─────────────────────────"
                .cyan()
                .bold()
        );
        println!(
            "{}",
            "    This category requires user interaction on the device.".yellow()
        );
        println!();

        // Prompt user to clear any dialogs from previous tests
        println!(
            "    {}",
            "══════════════════════════════════════════════════════════".yellow()
        );
        println!(
            "    {}",
            "  PREPARATION: Clear any dialogs on the device           "
                .yellow()
                .bold()
        );
        println!(
            "    {}",
            "══════════════════════════════════════════════════════════".yellow()
        );
        println!();
        println!("    If the device is showing any confirmation dialogs from");
        println!("    previous tests, please dismiss them now (press Cancel).");
        println!("    The device should be showing the home screen.");
        println!();
        wait_for_user("    Press ENTER when the device is ready... ")?;
        println!();

        // Test 5.1: Reset watermark via UI
        self.run_test("5.1 Interactive: Set high watermark", |ctx, pkh| {
            // Raise the block floor above the trigger level the next test uses.
            let high = ctx.reserve_level();
            ctx.expect_signature(pkh, ctx.block(high, 0), &format!("Watermark set to {high}"))
        });

        // This test triggers the error and waits for the operator to confirm the
        // "Set level" dialog or cancel it
        self.run_test(
            "5.2 Interactive: Trigger error and verify user action",
            |ctx, pkh| {
                let trigger = INTERACTIVE_TRIGGER_LEVEL;

                // Sign below the floor 5.1 set — triggers the watermark dialog.
                match ctx.sign(pkh, ctx.block(trigger, 0))? {
                    SignerResponse::Error(e) => {
                        println!();
                        println!(
                            "    {}",
                            "══════════════════════════════════════════════════════════".yellow()
                        );
                        println!(
                            "    {}",
                            "  ACTION REQUIRED: Interact with the device NOW           "
                                .yellow()
                                .bold()
                        );
                        println!(
                            "    {}",
                            "══════════════════════════════════════════════════════════".yellow()
                        );
                        println!("    Watermark error triggered: {}", e.dimmed());
                        println!();
                        println!(
                            "    The device should be showing a \"Set level to {trigger}\" watermark dialog."
                        );
                        println!("    1. Touch \"Set level to {trigger}\" or Cancel on the device screen");
                        println!("    2. Wait for the device to return to the home screen");
                        println!("    3. Then tell me what you pressed:");
                        println!("       [S] = I pressed \"Set level to {trigger}\"");
                        println!("       [C] = I pressed Cancel");
                        print!("    Your choice: ");
                        std::io::Write::flush(&mut std::io::stdout()).map_err(|e| e.to_string())?;

                        let mut input = String::new();
                        std::io::stdin()
                            .read_line(&mut input)
                            .map_err(|e| e.to_string())?;
                        let choice = input.trim().to_lowercase();

                        if choice == "s" || choice == "set" {
                            // Wait for user to confirm device is back to home screen
                            println!("    Press ENTER when the device shows the home screen...");
                            let mut ready = String::new();
                            std::io::stdin()
                                .read_line(&mut ready)
                                .map_err(|e| e.to_string())?;

                            println!("    Verifying the watermark was set...");

                            // "Set level to N" records N as signed, so verify the
                            // lowered floor by signing N+1 — rejected before (higher
                            // floor), now allowed.
                            let verify = ctx.sign(pkh, ctx.block(trigger + 1, 0))?;
                            match verify {
                                SignerResponse::Signature(_) => {
                                    println!(
                                        "    Set level confirmed! Signing at level {} succeeded.",
                                        trigger + 1
                                    );
                                    Ok(())
                                }
                                SignerResponse::Error(verify_e) => Err(format!(
                                    "Set level did not work - still getting error: {verify_e}"
                                )),
                                other => Err(format!(
                                    "Unexpected response after setting level: {other:?}"
                                )),
                            }
                        } else if choice == "c" || choice == "cancel" {
                            // Wait for user to confirm device is back to home screen
                            println!("    Press ENTER when the device shows the home screen...");
                            let mut ready = String::new();
                            std::io::stdin()
                                .read_line(&mut ready)
                                .map_err(|e| e.to_string())?;

                            println!("    Verifying cancel preserved watermark...");

                            // Verify the signing still fails after cancel
                            let verify = ctx.sign(pkh, ctx.block(trigger, 0))?;
                            match verify {
                                SignerResponse::Error(_) => {
                                    println!(
                                        "    Cancel confirmed! Watermark protection still active."
                                    );
                                    Ok(())
                                }
                                SignerResponse::Signature(_) => {
                                    Err("Cancel failed - watermark was unexpectedly changed"
                                        .to_string())
                                }
                                other => Err(format!(
                                    "Unexpected response after cancel: {other:?}"
                                )),
                            }
                        } else {
                            Err(format!("Invalid choice '{choice}'. Please enter S or C."))
                        }
                    }
                    SignerResponse::Signature(_) => {
                        Err("Should have rejected signing at lower level".to_string())
                    }
                    other => Err(format!("Unexpected response: {other:?}")),
                }
            },
        );

        Ok(())
    }

    fn print_summary(&self) {
        println!(
            "\n{}",
            "═══════════════════════════════════════════════════════════════"
                .blue()
                .bold()
        );
        println!("{}", "                    TEST SUMMARY".blue().bold());
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════"
                .blue()
                .bold()
        );

        let passed = self.results.iter().filter(|r| r.passed).count();
        let failed = self.results.iter().filter(|r| !r.passed).count();
        let total = self.results.len();
        let total_duration: Duration = self.results.iter().map(|r| r.duration).sum();

        if failed == 0 {
            println!(
                "\n  {} All tests passed! ({}/{})",
                "✓".green().bold(),
                passed,
                total
            );
        } else {
            println!(
                "\n  {} Tests: {} passed, {} failed (total: {})",
                "✗".red().bold(),
                passed.to_string().green(),
                failed.to_string().red(),
                total
            );

            println!("\n  {} Failed tests:", "Failed:".red().bold());
            for result in self.results.iter().filter(|r| !r.passed) {
                println!("    • {}", result.name.red());
                if let Some(ref err) = result.error {
                    println!("      {}", err.dimmed());
                }
            }
        }

        println!("\n  Total duration: {total_duration:.2?}");
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════\n"
                .blue()
                .bold()
        );

        // Exit with error code if any tests failed
        if failed > 0 {
            std::process::exit(1);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments manually (simple implementation)
    let args: Vec<String> = std::env::args().collect();

    let mut device = DEFAULT_DEVICE.to_string();
    let mut category = None;
    let mut chain_id = None;
    let mut verbose = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--device" | "-d" => {
                i += 1;
                if i < args.len() {
                    device = args[i].clone();
                }
            }
            "--category" | "-c" => {
                i += 1;
                if i < args.len() {
                    category = Some(args[i].clone());
                }
            }
            "--chain-id" => {
                i += 1;
                if i < args.len() {
                    chain_id = Some(args[i].clone());
                }
            }
            "--verbose" | "-v" => {
                verbose = true;
            }
            "--help" | "-h" => {
                println!("Watermark Protection E2E Test Suite\n");
                println!("USAGE:");
                println!("    cargo run --example watermark_e2e_test [OPTIONS]\n");
                println!("OPTIONS:");
                println!("    -d, --device <ADDR>     Device address (default: {DEFAULT_DEVICE})");
                println!("        --chain-id <B58>    Provisioned chain the device signs for");
                println!("    -c, --category <NAME>   Run only tests matching category");
                println!("                            (basic, multi, chain, edge)");
                println!("    -v, --verbose           Verbose output");
                println!("    -h, --help              Print this help");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let chain_id = chain_id.ok_or(
        "--chain-id <b58> is required; run via `cargo xtask watermark-test`, which reads \
         it from the device",
    )?;
    let provisioned_chain: [u8; 4] = ChainId::from_b58check(&chain_id)
        .ok_or_else(|| format!("Invalid --chain-id {chain_id:?}: not a base58 chain id"))?
        .as_bytes()[..4]
        .try_into()
        .expect("chain id has at least 4 bytes");

    if provisioned_chain == FOREIGN_CHAIN {
        return Err(format!(
            "Device is provisioned for {chain_id}, the chain the rejection tests use as foreign; \
             use a device on a different chain"
        )
        .into());
    }

    let ctx = TestContext::new(&device, provisioned_chain, verbose)?;
    let mut suite = TestSuite::new(ctx, category);

    suite.run_all()?;

    Ok(())
}
