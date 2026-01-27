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
    bls::PublicKeyHash,
    protocol::{
        SignerRequest, SignerResponse,
        encoding::{decode_response, encode_request},
    },
    test_utils::{
        GHOSTNET_CHAIN_ID, MAINNET_CHAIN_ID, create_attestation_data,
        create_attestation_data_with_chain, create_block_data, create_block_data_with_chain,
        create_preattestation_data,
    },
};
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

/// Wait for user to dismiss a watermark reset confirmation dialog on the device.
/// Used after tests that trigger "Level too low" errors which show RESET/CANCEL buttons.
/// `expected_dialog` describes what the dialog should show.
fn wait_for_reset_dialog(expected_dialog: &str) -> Result<(), String> {
    println!();
    println!(
        "    The device should be showing: {}",
        expected_dialog.yellow()
    );
    println!("    This is a RESET confirmation dialog with RESET and CANCEL buttons.");
    println!("    Press CANCEL on the device to dismiss it (preserve watermark).");
    println!("    Press ENTER here when the device shows the home screen...");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Handle a watermark error by prompting the user to reset or cancel on the device.
/// Returns Ok(true) if user reset and we should retry, Ok(false) if user cancelled,
/// or Err if something went wrong.
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
    println!("    The device should be showing a watermark error dialog.");
    println!("    Please interact with the device:");
    println!("       [R] = Press RESET on device to clear watermark, then press R here");
    println!("       [C] = Press CANCEL on device to keep watermark, then press C here");
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

    if choice == "r" || choice == "reset" {
        println!("    Watermark reset - will retry operation...");
        Ok(true)
    } else if choice == "c" || choice == "cancel" {
        println!("    Watermark preserved.");
        Ok(false)
    } else {
        Err(format!("Invalid choice '{choice}'. Please enter R or C."))
    }
}

/// Default device address (link-local USB)
const DEFAULT_DEVICE: &str = "169.254.1.1:7732";

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
}

impl TestContext {
    fn new(device: &str, verbose: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let device_addr: SocketAddr = device.parse()?;

        Ok(Self {
            device_addr,
            pkh: None,
            verbose,
        })
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

        if (self.should_run_category("chain") || self.should_run_category("isolation"))
            && !self.failed
        {
            self.run_category_chain_isolation()?;
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
            // Sign at level 100 - may need retry if watermark exists from previous run
            loop {
                let mut stream = ctx.connect().map_err(|e| e.to_string())?;
                let data = create_block_data(100, 0);
                let request = SignerRequest::Sign {
                    pkh: (pkh, 0),
                    data,
                    signature: None,
                };
                let response = ctx
                    .send_request(&mut stream, &request)
                    .map_err(|e| e.to_string())?;

                match response {
                    SignerResponse::Signature(_) => {
                        ctx.log("Signed level 100");
                        break;
                    }
                    SignerResponse::Error(ref e)
                        if e.contains("Watermark") || e.contains("watermark") =>
                    {
                        // Watermark error - prompt user to reset or cancel
                        if handle_watermark_error(e)? {
                            // User reset - retry
                            continue;
                        }
                        // User cancelled - fail test
                        return Err(format!("User cancelled watermark reset: {e}"));
                    }
                    other => {
                        return Err(format!("Expected signature at level 100, got: {other:?}"));
                    }
                }
            }

            // Sign at level 101
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;
            let data = create_block_data(101, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Expected signature at level 101, got: {response:?}"
                ));
            }
            ctx.log("Signed level 101");

            Ok(())
        });

        // Test 1.2: Reject lower level (block)
        self.run_test("1.2 Reject lower level (block)", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Sign at level 200
            let data = create_block_data(200, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Expected signature at level 200, got: {response:?}"
                ));
            }
            ctx.log("Signed level 200");

            // Try to sign at level 199 (should fail)
            let data = create_block_data(199, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };

            // Need new connection as device may close on error
            let mut stream2 = ctx.connect().map_err(|e| e.to_string())?;
            let response = ctx
                .send_request(&mut stream2, &request)
                .map_err(|e| e.to_string())?;

            match response {
                SignerResponse::Error(e) if e.contains("Level too low") || e.contains("level") => {
                    ctx.log("Correctly rejected level 199");
                    wait_for_reset_dialog(
                        "Level too low - RESET confirmation with level 200 → 199",
                    )?;
                    Ok(())
                }
                SignerResponse::Error(e) => Err(format!("Got error but unexpected message: {e}")),
                SignerResponse::Signature(_) => {
                    Err("SECURITY FAILURE: Signed at lower level!".to_string())
                }
                _ => Err(format!("Unexpected response: {response:?}")),
            }
        });

        // Test 1.3: Reject lower round at same level (block)
        self.run_test("1.3 Reject lower round at same level", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Sign at level 300, round 5
            let data = create_block_data(300, 5);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Expected signature at level 300/round 5, got: {response:?}"
                ));
            }
            ctx.log("Signed level 300, round 5");

            // Try to sign at level 300, round 4 (should fail)
            let data = create_block_data(300, 4);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };

            let mut stream2 = ctx.connect().map_err(|e| e.to_string())?;
            let response = ctx
                .send_request(&mut stream2, &request)
                .map_err(|e| e.to_string())?;

            match response {
                SignerResponse::Error(e) if e.contains("Round too low") || e.contains("round") => {
                    ctx.log("Correctly rejected round 4 (no dialog shown)");
                    Ok(())
                }
                SignerResponse::Error(e) => Err(format!("Got error but unexpected message: {e}")),
                SignerResponse::Signature(_) => {
                    Err("SECURITY FAILURE: Signed at lower round!".to_string())
                }
                _ => Err(format!("Unexpected response: {response:?}")),
            }
        });

        // Test 1.4: Allow higher round at same level
        self.run_test("1.4 Allow higher round at same level", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Sign at level 400, round 5
            let data = create_block_data(400, 5);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!("Expected signature at round 5, got: {response:?}"));
            }
            ctx.log("Signed level 400, round 5");

            // Sign at level 400, round 6 (should succeed)
            let data = create_block_data(400, 6);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!("Expected signature at round 6, got: {response:?}"));
            }
            ctx.log("Signed level 400, round 6");

            Ok(())
        });

        // Test 1.5: Forward progression (attestation)
        self.run_test("1.5 Forward progression (attestation)", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Sign attestation at level 500
            let data = create_attestation_data(500, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Expected signature at level 500, got: {response:?}"
                ));
            }
            ctx.log("Signed attestation level 500");

            // Sign at level 501
            let data = create_attestation_data(501, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Expected signature at level 501, got: {response:?}"
                ));
            }
            ctx.log("Signed attestation level 501");

            Ok(())
        });

        // Test 1.6: Reject lower level (attestation)
        self.run_test("1.6 Reject lower level (attestation)", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Sign attestation at level 600
            let data = create_attestation_data(600, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Expected signature at level 600, got: {response:?}"
                ));
            }
            ctx.log("Signed attestation level 600");

            // Try to sign at level 599 (should fail)
            let data = create_attestation_data(599, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };

            let mut stream2 = ctx.connect().map_err(|e| e.to_string())?;
            let response = ctx
                .send_request(&mut stream2, &request)
                .map_err(|e| e.to_string())?;

            match response {
                SignerResponse::Error(e) if e.contains("Level too low") || e.contains("level") => {
                    ctx.log("Correctly rejected attestation level 599");
                    wait_for_reset_dialog(
                        "Level too low - RESET confirmation with level 600 → 599",
                    )?;
                    Ok(())
                }
                SignerResponse::Error(e) => Err(format!("Got error but unexpected message: {e}")),
                SignerResponse::Signature(_) => {
                    Err("SECURITY FAILURE: Signed attestation at lower level!".to_string())
                }
                _ => Err(format!("Unexpected response: {response:?}")),
            }
        });

        // Test 1.7: Forward progression (preattestation)
        self.run_test("1.7 Forward progression (preattestation)", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Sign preattestation at level 700
            let data = create_preattestation_data(700, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Expected signature at level 700, got: {response:?}"
                ));
            }
            ctx.log("Signed preattestation level 700");

            // Sign at level 701
            let data = create_preattestation_data(701, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Expected signature at level 701, got: {response:?}"
                ));
            }
            ctx.log("Signed preattestation level 701");

            Ok(())
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
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Sign block at level 1000
            let data = create_block_data(1000, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;
            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!("Block at 1000 failed: {response:?}"));
            }
            ctx.log("Block at 1000: OK");

            // Sign attestation at level 999 (should succeed - separate watermark)
            let data = create_attestation_data(999, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;
            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Attestation at 999 should succeed (separate watermark), got: {response:?}"
                ));
            }
            ctx.log("Attestation at 999: OK (independent)");

            // Sign preattestation at level 998 (should succeed - separate watermark)
            let data = create_preattestation_data(998, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;
            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Preattestation at 998 should succeed (separate watermark), got: {response:?}"
                ));
            }
            ctx.log("Preattestation at 998: OK (independent)");

            // Now try block at 999 (should fail - block watermark is at 1000)
            let data = create_block_data(999, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let mut stream2 = ctx.connect().map_err(|e| e.to_string())?;
            let response = ctx
                .send_request(&mut stream2, &request)
                .map_err(|e| e.to_string())?;
            match response {
                SignerResponse::Error(_) => {
                    ctx.log("Block at 999: Correctly rejected");
                    wait_for_reset_dialog(
                        "Level too low - RESET confirmation with level 1000 → 999",
                    )?;
                    Ok(())
                }
                SignerResponse::Signature(_) => {
                    Err("SECURITY FAILURE: Block signed below watermark!".to_string())
                }
                _ => Err(format!("Unexpected response: {response:?}")),
            }
        });

        Ok(())
    }

    fn run_category_chain_isolation(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "─── Category 3: Chain ID Isolation ────────────────────────────"
                .cyan()
                .bold()
        );

        // Test 3.1: Different chains have independent watermarks
        self.run_test("3.1 Chain ID isolation", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Sign on "mainnet" chain at level 2000
            let data = create_block_data_with_chain(&MAINNET_CHAIN_ID, 2000, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;
            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!("Mainnet block at 2000 failed: {response:?}"));
            }
            ctx.log("Mainnet block at 2000: OK");

            // Sign on "ghostnet" chain at level 1999 (should succeed - different chain)
            let data = create_block_data_with_chain(&GHOSTNET_CHAIN_ID, 1999, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;
            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Ghostnet block at 1999 should succeed (different chain), got: {response:?}"
                ));
            }
            ctx.log("Ghostnet block at 1999: OK (independent chain)");

            // Try mainnet at 1999 (should fail)
            let data = create_block_data_with_chain(&MAINNET_CHAIN_ID, 1999, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let mut stream2 = ctx.connect().map_err(|e| e.to_string())?;
            let response = ctx
                .send_request(&mut stream2, &request)
                .map_err(|e| e.to_string())?;
            match response {
                SignerResponse::Error(_) => {
                    ctx.log("Mainnet block at 1999: Correctly rejected");
                    wait_for_reset_dialog(
                        "Level too low - RESET confirmation (mainnet) level 2000 → 1999",
                    )?;
                    Ok(())
                }
                SignerResponse::Signature(_) => {
                    Err("SECURITY FAILURE: Mainnet signed below watermark!".to_string())
                }
                _ => Err(format!("Unexpected response: {response:?}")),
            }
        });

        // Test 3.2: Cross-chain attestations are independent
        self.run_test("3.2 Cross-chain attestations independent", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Attestation on mainnet at 2100
            let data = create_attestation_data_with_chain(&MAINNET_CHAIN_ID, 2100, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;
            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!("Mainnet attestation at 2100 failed: {response:?}"));
            }
            ctx.log("Mainnet attestation at 2100: OK");

            // Attestation on ghostnet at 50 (should succeed - different chain)
            let data = create_attestation_data_with_chain(&GHOSTNET_CHAIN_ID, 50, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;
            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Ghostnet attestation at 50 should succeed, got: {response:?}"
                ));
            }
            ctx.log("Ghostnet attestation at 50: OK (independent chain)");

            Ok(())
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

        // Test 4.1: Maximum level value
        // Uses unique chain ID to avoid polluting mainnet watermark with extreme values
        self.run_test("4.1 Maximum level value (u32::MAX)", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Use unique chain ID for this extreme-value test
            let max_level_chain = [0xDE, 0xAD, 0xBE, 0xEF];
            let data = create_block_data_with_chain(&max_level_chain, u32::MAX - 1, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!(
                    "Expected signature at max level, got: {response:?}"
                ));
            }
            ctx.log("Signed at u32::MAX - 1 (on isolated chain)");

            Ok(())
        });

        // Test 4.2: Zero level/round
        self.run_test("4.2 Zero level and round", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Use a different chain for this test to avoid watermark conflicts
            let test_chain = [0xAA, 0xBB, 0xCC, 0xDD];
            let data = create_block_data_with_chain(&test_chain, 0, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!("Expected signature at level 0, got: {response:?}"));
            }
            ctx.log("Signed at level 0, round 0");

            // Level 1 should work
            let data = create_block_data_with_chain(&test_chain, 1, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!("Expected signature at level 1, got: {response:?}"));
            }
            ctx.log("Signed at level 1");

            Ok(())
        });

        // Test 4.3: Same level, same round (replay attempt)
        self.run_test("4.3 Replay attempt (same level/round)", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            let test_chain = [0x11, 0x22, 0x33, 0x44];

            // Sign at level 5000, round 3
            let data = create_block_data_with_chain(&test_chain, 5000, 3);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data: data.clone(),
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;
            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!("First sign at 5000/3 failed: {response:?}"));
            }
            ctx.log("First signature at 5000/3: OK");

            // Try same level/round again (replay - should fail)
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let mut stream2 = ctx.connect().map_err(|e| e.to_string())?;
            let response = ctx
                .send_request(&mut stream2, &request)
                .map_err(|e| e.to_string())?;
            match response {
                SignerResponse::Error(_) => {
                    ctx.log("Replay attempt: Correctly rejected (no dialog shown)");
                    Ok(())
                }
                SignerResponse::Signature(_) => {
                    // Note: Some implementations may allow re-signing the exact same data
                    // This is technically safe as it produces the same signature
                    ctx.log("Replay produced signature (may be acceptable if identical)");
                    Ok(())
                }
                _ => Err(format!("Unexpected response: {response:?}")),
            }
        });

        // Test 4.4: Invalid magic byte
        self.run_test("4.4 Invalid magic byte rejection", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Create data with invalid magic byte (0xFF instead of 0x11/0x12/0x13)
            let mut data = create_block_data(9999, 0);
            data[0] = 0xFF; // Invalid magic byte

            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            match response {
                SignerResponse::Error(e) => {
                    ctx.log(&format!("Correctly rejected invalid magic: {e}"));
                    Ok(())
                }
                SignerResponse::Signature(_) => {
                    Err("Should not sign data with invalid magic byte".to_string())
                }
                _ => Err(format!("Unexpected response: {response:?}")),
            }
        });

        Ok(())
    }

    fn run_category_interactive_reset(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "─── Category 5: Interactive Reset ─────────────────────────────"
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

        // Use a dedicated chain ID for interactive tests
        let interactive_chain = [0xEE, 0xFF, 0x00, 0x11];

        // Test 5.1: Reset watermark via UI
        self.run_test("5.1 Interactive: Set high watermark", |ctx, pkh| {
            let mut stream = ctx.connect().map_err(|e| e.to_string())?;

            // Sign at a high level to set watermark
            let data = create_block_data_with_chain(&interactive_chain, 10000, 0);
            let request = SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            };
            let response = ctx
                .send_request(&mut stream, &request)
                .map_err(|e| e.to_string())?;

            if !matches!(response, SignerResponse::Signature(_)) {
                return Err(format!("Failed to set watermark at 10000: {response:?}"));
            }
            ctx.log("Watermark set to level 10000");
            Ok(())
        });

        // This test triggers the error and waits for user to confirm reset or cancel
        self.run_test(
            "5.2 Interactive: Trigger error and verify user action",
            |ctx, pkh| {
                let mut stream = ctx.connect().map_err(|e| e.to_string())?;

                // Try to sign at lower level - will trigger watermark error on device
                let data = create_block_data_with_chain(&interactive_chain, 100, 0);
                let request = SignerRequest::Sign {
                    pkh: (pkh, 0),
                    data: data.clone(),
                    signature: None,
                };
                let response = ctx
                    .send_request(&mut stream, &request)
                    .map_err(|e| e.to_string())?;

                match response {
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
                        println!("    The device should be showing a reset confirmation dialog.");
                        println!("    1. Touch RESET or CANCEL on the device screen");
                        println!("    2. Wait for the device to return to the home screen");
                        println!("    3. Then tell me what you pressed:");
                        println!("       [R] = I pressed Reset");
                        println!("       [C] = I pressed Cancel");
                        print!("    Your choice: ");
                        std::io::Write::flush(&mut std::io::stdout()).map_err(|e| e.to_string())?;

                        let mut input = String::new();
                        std::io::stdin()
                            .read_line(&mut input)
                            .map_err(|e| e.to_string())?;
                        let choice = input.trim().to_lowercase();

                        if choice == "r" || choice == "reset" {
                            // Wait for user to confirm device is back to home screen
                            println!("    Press ENTER when the device shows the home screen...");
                            let mut ready = String::new();
                            std::io::stdin()
                                .read_line(&mut ready)
                                .map_err(|e| e.to_string())?;

                            println!("    Verifying reset was successful...");

                            // Verify the signing works after reset
                            let mut verify_stream = ctx.connect().map_err(|e| e.to_string())?;
                            let verify_request = SignerRequest::Sign {
                                pkh: (pkh, 0),
                                data: data.clone(),
                                signature: None,
                            };
                            let verify_response = ctx
                                .send_request(&mut verify_stream, &verify_request)
                                .map_err(|e| e.to_string())?;

                            match verify_response {
                                SignerResponse::Signature(_) => {
                                    println!(
                                        "    Reset confirmed! Signing at level 100 succeeded."
                                    );
                                    Ok(())
                                }
                                SignerResponse::Error(verify_e) => Err(format!(
                                    "Reset did not work - still getting error: {verify_e}"
                                )),
                                _ => Err(format!(
                                    "Unexpected response after reset: {verify_response:?}"
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
                            let mut verify_stream = ctx.connect().map_err(|e| e.to_string())?;
                            let verify_request = SignerRequest::Sign {
                                pkh: (pkh, 0),
                                data: data.clone(),
                                signature: None,
                            };
                            let verify_response = ctx
                                .send_request(&mut verify_stream, &verify_request)
                                .map_err(|e| e.to_string())?;

                            match verify_response {
                                SignerResponse::Error(_) => {
                                    println!(
                                        "    Cancel confirmed! Watermark protection still active."
                                    );
                                    Ok(())
                                }
                                SignerResponse::Signature(_) => {
                                    Err("Cancel failed - watermark was unexpectedly reset"
                                        .to_string())
                                }
                                _ => Err(format!(
                                    "Unexpected response after cancel: {verify_response:?}"
                                )),
                            }
                        } else {
                            Err(format!("Invalid choice '{choice}'. Please enter R or C."))
                        }
                    }
                    SignerResponse::Signature(_) => {
                        Err("Should have rejected signing at lower level".to_string())
                    }
                    _ => Err(format!("Unexpected response: {response:?}")),
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
            "--verbose" | "-v" => {
                verbose = true;
            }
            "--help" | "-h" => {
                println!("Watermark Protection E2E Test Suite\n");
                println!("USAGE:");
                println!("    cargo run --example watermark_e2e_test [OPTIONS]\n");
                println!("OPTIONS:");
                println!("    -d, --device <ADDR>     Device address (default: {DEFAULT_DEVICE})");
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

    let ctx = TestContext::new(&device, verbose)?;
    let mut suite = TestSuite::new(ctx, category);

    suite.run_all()?;

    Ok(())
}
