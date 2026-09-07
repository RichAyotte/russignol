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
    ChainId, PublicKey, PublicKeyHash, Scheme, Signature, SignatureVersion,
    protocol::{
        SignerRequest, SignerResponse,
        encoding::{decode_response, encode_request},
    },
    test_utils::{
        create_attestation_data_for_chain, create_attestation_data_with_chain,
        create_block_data_with_chain, create_preattestation_data_with_chain,
    },
};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

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

/// Read a tz6 signature's epoch off its own bytes and decode the signature with
/// the XMSS crate's decoder, so the layout the device framed is checked against
/// both.
fn framed(signature: &Signature) -> Result<(russignol_xmss::Signature, u32), String> {
    let bytes = signature.to_bytes();
    if bytes.len() != Scheme::Xmss.signature_len() {
        return Err(format!(
            "a tz6 signature is {} bytes, got {}",
            Scheme::Xmss.signature_len(),
            bytes.len()
        ));
    }
    let epoch = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
    let decoded = russignol_xmss::Signature::from_bytes(&bytes).map_err(|e| e.to_string())?;
    if decoded.epoch() != epoch {
        return Err(format!(
            "the framing's epoch {epoch} and the decoder's {} disagree",
            decoded.epoch()
        ));
    }
    Ok((decoded, epoch))
}

/// The nearest-rank percentile of `sorted`, or `None` where there are no samples.
fn percentile(sorted: &[Duration], hundredths: usize) -> Option<Duration> {
    let rank = (sorted.len() * hundredths).div_ceil(100).max(1);
    sorted.get(rank - 1).copied()
}

/// Default device address (link-local USB)
const DEFAULT_DEVICE: &str = "169.254.1.1:7732";

/// A chain the device is never provisioned for. Signing an operation on it must
/// be rejected outright. These are Tezos mainnet's chain bytes: a test/staging
/// device is provisioned for a testnet, so mainnet is always foreign. `main`
/// refuses to run if the provisioned chain equals this, so the rejection tests
/// can never silently pass by signing the "foreign" chain.
const FOREIGN_CHAIN: [u8; 4] = [0x7a, 0x06, 0xa7, 0x70];

/// First level handed out by the shared cursor where `--level-base` names none.
/// The device's first block sign recovers a missing watermark to this level
/// (setting every op-type's floor), so it must sit above any leftover floor a
/// prior run may have lowered. A card whose floors sit at a chain level is run
/// with `--level-base` above them rather than cleaned.
const LEVEL_BASE: u32 = 100;

/// Signatures timed per scheme for the latency figures. A hundred puts the p99
/// at the second-slowest sample, which is what the slot budget is judged on.
const LATENCY_SAMPLES: usize = 100;

/// The slot three consensus signatures have to fit inside.
const SLOT: Duration = Duration::from_secs(6);

/// Gap between successive cursor hand-outs. Wide enough for a test's local
/// offsets (a few levels up or down within its band) without overlapping the
/// neighbouring test's band.
const LEVEL_STRIDE: u32 = 10;

/// Fixed low level the below-floor test signs to trip a "level too low"
/// rejection. Below [`LEVEL_BASE`], so it is always under the floor the earlier
/// tests raised, independent of how far the cursor has advanced.
const BELOW_FLOOR_LEVEL: u32 = 50;

/// Test result
struct TestResult {
    name: String,
    outcome: Result<(), String>,
    duration: Duration,
}

/// Test context with device connection info
struct TestContext {
    device_addr: SocketAddr,
    /// The card's first BLS key, which every watermark test signs with.
    pkh: Option<PublicKeyHash>,
    /// The card's XMSS key, where it holds one.
    xmss_pkh: Option<PublicKeyHash>,
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
        level_base: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let device_addr: SocketAddr = device.parse()?;

        Ok(Self {
            device_addr,
            pkh: None,
            xmss_pkh: None,
            verbose,
            provisioned_chain,
            next_level: Cell::new(level_base),
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

    /// Attestation operation data on the provisioned chain, in the layout a key
    /// of `scheme` signs: every scheme but BLS carries a committee slot.
    fn attestation_for(&self, scheme: Scheme, level: u32, round: u32) -> Vec<u8> {
        create_attestation_data_for_chain(scheme, &self.provisioned_chain, level, round)
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
            pkh: (pkh, SignatureVersion::V4),
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
        self.signature(pkh, data, what).map(|_| ())
    }

    /// Sign and return the signature, logging `what` on success.
    fn signature(
        &self,
        pkh: PublicKeyHash,
        data: Vec<u8>,
        what: &str,
    ) -> Result<Signature, String> {
        match self.sign(pkh, data)? {
            SignerResponse::Signature(signature) => {
                self.log(&format!("{what}: OK"));
                Ok(signature)
            }
            other => Err(format!("{what} expected a signature, got: {other:?}")),
        }
    }

    /// Sign `data` as a key's first signature of the run. A key with no
    /// watermark yet has the device show its recovery dialog, which sets every
    /// op-type's floor to the requested level once the operator confirms it.
    /// The floor records that level as signed, so a caller proves progression
    /// with the next level rather than by retrying this one.
    fn establish(&self, pkh: PublicKeyHash, data: Vec<u8>, what: &str) -> Result<(), String> {
        match self.sign(pkh, data)? {
            SignerResponse::Signature(_) => {
                self.log(&format!("{what}: OK"));
                Ok(())
            }
            SignerResponse::Error(ref e) if e.contains("Watermark not initialized") => {
                if !handle_watermark_error(e)? {
                    return Err(format!("Operator cancelled the watermark dialog: {e}"));
                }
                self.log(&format!("{what}: recovered the missing watermark"));
                Ok(())
            }
            SignerResponse::Error(ref e) if e.contains("Large level gap") => Err(format!(
                "{what} raised the level-gap dialog ({e}); answer it on the panel, then run with \
                 a --level-base nearer the floor"
            )),
            SignerResponse::Error(ref e) => Err(format!(
                "{what} was refused ({e}); a floor at or above this level needs --clean, or a \
                 --level-base above it"
            )),
            other => Err(format!("{what} expected a signature, got: {other:?}")),
        }
    }

    /// The public key the device holds for `pkh`.
    fn public_key(&self, pkh: PublicKeyHash) -> Result<PublicKey, String> {
        let mut stream = self.connect().map_err(|e| e.to_string())?;
        match self
            .send_request(&mut stream, &SignerRequest::PublicKey { pkh })
            .map_err(|e| e.to_string())?
        {
            SignerResponse::PublicKey(pk) => Ok(pk),
            other => Err(format!("public key request answered: {other:?}")),
        }
    }

    /// The port closing is what shows the power was cut, rather than the
    /// operator's word for it: a check that took the word would pass with the
    /// device never having gone down.
    fn wait_for_port_closed(&self, window: Duration) -> Result<(), String> {
        let deadline = Instant::now() + window;
        loop {
            if self.connect().is_err() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "the device kept answering at {} for {window:?}, so its power was not cut",
                    self.device_addr
                ));
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    fn wait_for_port(&self, window: Duration) -> Result<(), String> {
        let deadline = Instant::now() + window;
        loop {
            if self.connect().is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "the device did not answer at {} within {window:?}",
                    self.device_addr
                ));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Time [`LATENCY_SAMPLES`] attestations through the signer, a level apart,
    /// after one untimed signature that establishes the key's floor, and judge
    /// three signatures at the p99 against a slot.
    fn latency(&self, pkh: PublicKeyHash, name: &str) -> Result<(), String> {
        let scheme = pkh.scheme();
        let base = self.reserve_level();
        self.establish(
            pkh,
            self.attestation_for(scheme, base, 0),
            &format!("{name} warm-up attestation {base}"),
        )?;

        let mut samples = Vec::with_capacity(LATENCY_SAMPLES);
        for _ in 0..LATENCY_SAMPLES {
            let level = self.reserve_level();
            let data = self.attestation_for(scheme, level, 0);
            let started = Instant::now();
            self.signature(pkh, data, &format!("{name} attestation {level}"))?;
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        let (Some(p50), Some(p90), Some(p99), Some(max)) = (
            percentile(&samples, 50),
            percentile(&samples, 90),
            percentile(&samples, 99),
            samples.last().copied(),
        ) else {
            return Err(format!("no {name} latency samples were taken"));
        };
        let three = p99 * 3;
        println!();
        println!(
            "    {name}: {} samples, p50 {p50:.1?}, p90 {p90:.1?}, p99 {p99:.1?}, max {max:.1?}; \
             three at the p99 take {three:.2?} of the {SLOT:?} slot",
            samples.len(),
        );
        if three >= SLOT {
            return Err(format!(
                "three {name} signatures at the p99 take {three:.2?}, past the {SLOT:?} slot"
            ));
        }
        Ok(())
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

        if self.should_run_category("floor") && !self.failed {
            self.run_category_below_floor()?;
        }

        if self.should_run_category("xmss") && !self.failed {
            self.run_category_xmss()?;
        }

        if self.should_run_category("latency") && !self.failed {
            self.run_category_latency()?;
        }

        // A power cut needs a hand on the device, so this runs only when named.
        if self.category_named("power") && !self.failed {
            self.run_category_power_cut()?;
        }

        self.print_summary();
        Ok(())
    }

    fn category_named(&self, category: &str) -> bool {
        self.category_filter
            .as_deref()
            .is_some_and(|filter| filter.eq_ignore_ascii_case(category))
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
                let Some(bls) = keys.iter().copied().find(|k| k.scheme() == Scheme::Bls) else {
                    return Err("No BLS key found on device".into());
                };
                self.ctx.pkh = Some(bls);
                println!(
                    "  {} Using key: {}",
                    "✓".green(),
                    bls.to_b58check().yellow()
                );
                self.ctx.xmss_pkh = keys.iter().copied().find(|k| k.scheme() == Scheme::Xmss);
                if let Some(tz6) = self.ctx.xmss_pkh {
                    println!("  {} XMSS key: {}", "✓".green(), tz6.to_b58check().yellow());
                } else {
                    println!("  {} No XMSS key on the card", "ℹ".blue());
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
                outcome: Err("No PKH available".to_string()),
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
                    outcome: Ok(()),
                    duration,
                });
            }
            Err(e) => {
                let duration = start.elapsed();
                println!("{}", "FAIL".red().bold());
                println!("    Error: {}", e.red());
                self.results.push(TestResult {
                    name: name.to_string(),
                    outcome: Err(e),
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
            let base = ctx.reserve_level();
            ctx.establish(pkh, ctx.block(base, 0), &format!("Block level {base}"))?;

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
                    ctx.log(&format!(
                        "Correctly rejected level {} (no dialog shown)",
                        base - 1
                    ));
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
                        "Correctly rejected attestation level {} (no dialog shown)",
                        base - 1
                    ));
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
                    ctx.log(&format!(
                        "Block at {} correctly rejected (no dialog shown)",
                        base - 1
                    ));
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

    fn run_category_below_floor(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "─── Category 5: Below-Floor Requests Cannot Lower the Watermark ─"
                .cyan()
                .bold()
        );

        self.run_test(
            "5.1 Below-floor request cannot lower the floor",
            |ctx, pkh| {
                // Establish a floor well above the below-floor probe level.
                let base = ctx.reserve_level();
                ctx.expect_signature(pkh, ctx.block(base, 0), &format!("Floor set to {base}"))?;

                // Below the floor: refused outright, with no dialog on the device.
                match ctx.sign(pkh, ctx.block(BELOW_FLOOR_LEVEL, 0))? {
                    SignerResponse::Error(e)
                        if e.contains("Level too low") || e.contains("level") =>
                    {
                        ctx.log(&format!(
                            "Rejected level {BELOW_FLOOR_LEVEL} (no dialog shown)"
                        ));
                    }
                    SignerResponse::Error(e) => {
                        return Err(format!("Got error but unexpected message: {e}"));
                    }
                    SignerResponse::Signature(_) => {
                        return Err("SECURITY FAILURE: signed below the floor!".to_string());
                    }
                    other => return Err(format!("Unexpected response: {other:?}")),
                }

                // The refusal did not lower the floor: the same level is still refused.
                match ctx.sign(pkh, ctx.block(BELOW_FLOOR_LEVEL, 0))? {
                    SignerResponse::Error(_) => {
                        ctx.log("Floor unchanged: below-floor level still refused");
                    }
                    SignerResponse::Signature(_) => {
                        return Err(
                            "SECURITY FAILURE: below-floor request lowered the watermark!"
                                .to_string(),
                        );
                    }
                    other => return Err(format!("Unexpected response: {other:?}")),
                }

                // Forward progression above the floor still signs — the floor is intact.
                ctx.expect_signature(
                    pkh,
                    ctx.block(base + 1, 0),
                    &format!("Above-floor block {}", base + 1),
                )
            },
        );

        Ok(())
    }

    fn run_category_xmss(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "─── Category 6: XMSS (tz6) Signing ────────────────────────────"
                .cyan()
                .bold()
        );
        let Some(tz6) = self.ctx.xmss_pkh else {
            println!("  {} No XMSS key on the card; skipped", "ℹ".blue());
            return Ok(());
        };

        // Test 6.1: The key the device serves hashes to the address it lists
        self.run_test("6.1 tz6 public key hashes to its address", |ctx, _| {
            let pk = ctx.public_key(tz6)?;
            if pk.scheme() != Scheme::Xmss {
                return Err(format!("expected an XMSS key, got a {} one", pk.scheme()));
            }
            if pk.hash() != tz6 {
                return Err(format!(
                    "the key hashes to {}, not the listed {}",
                    pk.hash().to_b58check(),
                    tz6.to_b58check()
                ));
            }
            ctx.log(&format!(
                "{} key bytes hash to the listed address",
                pk.to_bytes().len()
            ));
            Ok(())
        });

        // Test 6.2: A tz6 attestation verifies under the XMSS crate's own verifier,
        // at the epoch its framing carries and at no other
        self.run_test("6.2 tz6 attestation verifies at its framed epoch", |ctx, _| {
            let base = ctx.reserve_level();
            ctx.establish(
                tz6,
                ctx.attestation_for(Scheme::Xmss, base, 0),
                &format!("tz6 attestation {base}"),
            )?;

            let pk = ctx.public_key(tz6)?;
            let verifier =
                russignol_xmss::PublicKey::from_bytes(&pk.to_bytes()).map_err(|e| e.to_string())?;
            let data = ctx.attestation_for(Scheme::Xmss, base + 1, 0);
            let signature = ctx.signature(
                tz6,
                data.clone(),
                &format!("tz6 attestation {}", base + 1),
            )?;
            let (decoded, epoch) = framed(&signature)?;
            verifier
                .verify(&decoded, None, &data)
                .map_err(|e| format!("the signature does not verify at epoch {epoch}: {e}"))?;

            let mut reframed = signature.to_bytes();
            reframed[..4].copy_from_slice(&(epoch + 1).to_le_bytes());
            let at_next =
                russignol_xmss::Signature::from_bytes(&reframed).map_err(|e| e.to_string())?;
            if verifier.verify(&at_next, None, &data).is_ok() {
                return Err(format!(
                    "the signature also verifies at epoch {}, so the framed epoch binds nothing",
                    epoch + 1
                ));
            }
            ctx.log(&format!("verified at epoch {epoch} and at no other"));
            Ok(())
        });

        // Test 6.3: Each signature spends the next epoch
        self.run_test(
            "6.3 Epoch advances by exactly one per signature",
            |ctx, _| {
                let base = ctx.reserve_level();
                let mut previous: Option<u32> = None;
                for level in base..base + 3 {
                    let signature = ctx.signature(
                        tz6,
                        ctx.attestation_for(Scheme::Xmss, level, 0),
                        &format!("tz6 attestation {level}"),
                    )?;
                    let (_, epoch) = framed(&signature)?;
                    if let Some(previous) = previous
                        && epoch != previous + 1
                    {
                        return Err(format!("epoch {epoch} followed epoch {previous}"));
                    }
                    ctx.log(&format!("attestation {level} spent epoch {epoch}"));
                    previous = Some(epoch);
                }
                Ok(())
            },
        );

        // Test 6.4: Three tz6 signatures fit a slot at the p99
        self.run_test(
            "6.4 Three tz6 attestations fit a slot at the p99",
            |ctx, _| ctx.latency(tz6, "tz6"),
        );

        Ok(())
    }

    fn run_category_latency(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "─── Category 7: Signing Latency Through the Signer ────────────"
                .cyan()
                .bold()
        );

        // Test 7.1: Three tz4 signatures fit a slot at the p99
        self.run_test(
            "7.1 Three tz4 attestations fit a slot at the p99",
            |ctx, pkh| ctx.latency(pkh, "tz4"),
        );

        Ok(())
    }

    fn run_category_power_cut(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "\n{}",
            "─── Category 8: Epoch Across a Power Cut ──────────────────────"
                .cyan()
                .bold()
        );
        let Some(tz6) = self.ctx.xmss_pkh else {
            println!("  {} No XMSS key on the card; skipped", "ℹ".blue());
            return Ok(());
        };

        // Test 8.1: The epoch spent before a power cut is never spent again
        self.run_test(
            "8.1 The first epoch after a power cut is higher",
            |ctx, _| {
                let base = ctx.reserve_level();
                ctx.establish(
                    tz6,
                    ctx.attestation_for(Scheme::Xmss, base, 0),
                    &format!("tz6 attestation {base}"),
                )?;
                let signature = ctx.signature(
                    tz6,
                    ctx.attestation_for(Scheme::Xmss, base + 1, 0),
                    &format!("tz6 attestation {}", base + 1),
                )?;
                let (_, before) = framed(&signature)?;

                println!();
                println!(
                    "    {}",
                    "══════════════════════════════════════════════════════════".yellow()
                );
                println!(
                    "    {}",
                    "  POWER CUT - Device interaction required                 "
                        .yellow()
                        .bold()
                );
                println!(
                    "    {}",
                    "══════════════════════════════════════════════════════════".yellow()
                );
                println!(
                    "    Epoch {before} was just spent. Unplug the card's power lead yourself now: \
                     nothing here cuts it for you."
                );
                ctx.wait_for_port_closed(Duration::from_secs(300))?;
                println!("    The device is down. Restore its power and enter the PIN.");
                ctx.wait_for_port(Duration::from_secs(600))?;
                println!("    The device is back.");

                // While idle the signer writes a ceiling for the level after the
                // last one signed, so a restart loads (base + 2, u32::MAX) and
                // refuses that level whole; base + 3 is the first it signs.
                let signature = ctx.signature(
                    tz6,
                    ctx.attestation_for(Scheme::Xmss, base + 3, 0),
                    &format!("tz6 attestation {}", base + 3),
                )?;
                let (_, after) = framed(&signature)?;
                if after <= before {
                    return Err(format!(
                        "SECURITY FAILURE: epoch {after} after the power cut is not above {before}"
                    ));
                }
                ctx.log(&format!("epoch {before} before the cut, {after} after"));
                Ok(())
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

        let passed = self.results.iter().filter(|r| r.outcome.is_ok()).count();
        let failed = self.results.len() - passed;
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
            for (result, err) in self
                .results
                .iter()
                .filter_map(|r| r.outcome.as_ref().err().map(|e| (r, e)))
            {
                println!("    • {}", result.name.red());
                println!("      {}", err.dimmed());
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
    let mut level_base = LEVEL_BASE;

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
            "--level-base" => {
                i += 1;
                if i < args.len() {
                    level_base = args[i]
                        .parse()
                        .map_err(|e| format!("Invalid --level-base {:?}: {e}", args[i]))?;
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
                println!("                            (basic, multi, chain, edge, floor, xmss,");
                println!("                            latency; power runs only when named)");
                println!("        --level-base <N>    First level the tests sign at, above the");
                println!("                            card's floors (default: {LEVEL_BASE})");
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

    let ctx = TestContext::new(&device, provisioned_chain, verbose, level_base)?;
    let mut suite = TestSuite::new(ctx, category);

    suite.run_all()?;

    Ok(())
}
