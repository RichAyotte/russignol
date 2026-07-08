//! Drives unknown-key requests against a running signer to exercise the
//! unknown-key modal on the device panel.
//!
//! Derives a valid but unheld tz4 keypair from a seed label and sends a single
//! pkh-bearing request per invocation, so an operator can watch the panel and
//! acknowledge between steps.
//!
//! ```sh
//! cargo run --example unknown_key_driver -- known
//! cargo run --example unknown_key_driver -- pubkey alpha
//! cargo run --example unknown_key_driver -- pop alpha
//! cargo run --example unknown_key_driver -- sign alpha
//! cargo run --example unknown_key_driver -- flood alpha 5
//! ```
//!
//! Device address defaults to `169.254.1.1:7732`; override with
//! `RUSSIGNOL_DEVICE=host:port`.

use russignol_signer_lib::{
    bls::{self, PublicKeyHash},
    protocol::{
        SignerRequest, SignerResponse,
        encoding::{decode_response, encode_request},
    },
    test_utils::create_block_data,
};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn device_addr() -> String {
    std::env::var("RUSSIGNOL_DEVICE").unwrap_or_else(|_| "169.254.1.1:7732".to_string())
}

/// A 32-byte seed built from a label, so a given label always derives the same
/// unheld key and distinct labels derive distinct keys.
fn seed_from_label(label: &str) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let bytes = label.as_bytes();
    let n = bytes.len().min(32);
    seed[..n].copy_from_slice(&bytes[..n]);
    seed
}

fn unknown_pkh(label: &str) -> Res<PublicKeyHash> {
    let (pkh, _, _) = bls::generate_key(Some(&seed_from_label(label)))?;
    Ok(pkh)
}

/// Head-8/tail-6 ASCII truncation, mirroring the device's `truncate_middle`,
/// so the printed pkh matches what the panel shows.
fn truncated(pkh: &str) -> String {
    if pkh.len() <= 8 + 6 + 3 {
        return pkh.to_string();
    }
    format!("{}...{}", &pkh[..8], &pkh[pkh.len() - 6..])
}

fn connect() -> Res<TcpStream> {
    let addr = device_addr();
    let stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    Ok(stream)
}

fn send(stream: &mut TcpStream, request: &SignerRequest) -> Res<SignerResponse> {
    let data = encode_request(request)?;
    let len = u16::try_from(data.len())?.to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&data)?;
    stream.flush()?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let response_len = u16::from_be_bytes(len_buf) as usize;
    let mut response_data = vec![0u8; response_len];
    stream.read_exact(&mut response_data)?;
    Ok(decode_response(&response_data, request)?)
}

fn print_response(label: &str, response: &SignerResponse) {
    match response {
        SignerResponse::Error(e) => println!("  {label} -> Error (expected): {e}"),
        other => println!("  {label} -> {other:?}"),
    }
}

fn cmd_known() -> Res<()> {
    let mut stream = connect()?;
    let response = send(&mut stream, &SignerRequest::KnownKeys)?;
    match response {
        SignerResponse::KnownKeys(keys) => {
            println!("Device holds {} key(s):", keys.len());
            for k in &keys {
                println!("  {}", k.to_b58check());
            }
        }
        other => println!("Unexpected response: {other:?}"),
    }
    Ok(())
}

fn cmd_single(label: &str, make: impl Fn(PublicKeyHash) -> SignerRequest) -> Res<()> {
    let pkh = unknown_pkh(label)?;
    let b58 = pkh.to_b58check();
    println!("Unheld pkh (seed \"{label}\"): {b58}");
    println!("Panel should show:            {}", truncated(&b58));
    let mut stream = connect()?;
    let response = send(&mut stream, &make(pkh))?;
    print_response("request", &response);
    Ok(())
}

fn cmd_flood(label: &str, n: u32) -> Res<()> {
    let pkh = unknown_pkh(label)?;
    let b58 = pkh.to_b58check();
    println!(
        "Flooding {n} Sign requests for unheld pkh {}",
        truncated(&b58)
    );
    for i in 1..=n {
        let mut stream = connect()?;
        let request = SignerRequest::Sign {
            pkh: (pkh, 0),
            data: create_block_data(100, 0),
            signature: None,
        };
        let response = send(&mut stream, &request)?;
        print_response(&format!("flood {i}/{n}"), &response);
    }
    Ok(())
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map_or("known", String::as_str);
    let label = args.get(1).map_or("alpha", String::as_str);

    match cmd {
        "known" => cmd_known()?,
        "pkh" => {
            let b58 = unknown_pkh(label)?.to_b58check();
            println!("Unheld pkh (seed \"{label}\"): {b58}");
            println!("Panel should show:            {}", truncated(&b58));
        }
        "pubkey" => cmd_single(label, |pkh| SignerRequest::PublicKey { pkh })?,
        "pop" => cmd_single(label, |pkh| SignerRequest::BlsProveRequest {
            pkh,
            override_pk: None,
        })?,
        "sign" => cmd_single(label, |pkh| SignerRequest::Sign {
            pkh: (pkh, 0),
            data: create_block_data(100, 0),
            signature: None,
        })?,
        "flood" => {
            let n = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
            cmd_flood(label, n)?;
        }
        other => {
            eprintln!("unknown command: {other}");
            eprintln!(
                "commands: known | pkh <seed> | pubkey <seed> | pop <seed> | sign <seed> | flood <seed> <n>"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}
