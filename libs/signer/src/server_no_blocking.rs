// Alternative handle_sign without spawn_blocking for testing
// Copy this into server.rs to test performance difference

async fn handle_sign(&self, pkh: PublicKeyHash, data: Vec<u8>) -> Result<SignerResponse> {
    #[cfg(feature = "perf-trace")]
    let request_start = std::time::Instant::now();

    // 1. Check magic byte
    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    if let Some(ref allowed) = self.allowed_magic_bytes {
        magic_bytes::check_magic_byte(&data, Some(allowed))?;
    }

    #[cfg(feature = "perf-trace")]
    eprintln!("[PERF] Magic byte check: {:?}", t.elapsed());

    // 2. Check high watermark
    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    if let Some(ref watermark) = self.watermark {
        let wm = watermark.write().await;
        wm.check_and_update(self.chain_id, &pkh, &data)?;
    }

    #[cfg(feature = "perf-trace")]
    eprintln!("[PERF] Watermark check: {:?}", t.elapsed());

    // 3. Get key and sign
    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    let keys = self.keys.read().await;
    let signer = keys.get_signer(&pkh)?;

    // Create handler with same magic byte restrictions
    let handler = if let Some(ref allowed) = self.allowed_magic_bytes {
        SignerHandler::new(signer.clone(), Some(allowed.clone()))
    } else {
        SignerHandler::new(signer.clone(), None)
    };

    #[cfg(feature = "perf-trace")]
    eprintln!("[PERF] Get signer: {:?}", t.elapsed());

    // Sign directly without spawn_blocking
    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    let signature = handler.sign(&data, None, None)?;

    #[cfg(feature = "perf-trace")]
    eprintln!("[PERF] Direct sign (no spawn_blocking): {:?}", t.elapsed());

    // 4. Update watermark with signature
    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    if let Some(ref watermark) = self.watermark {
        let wm = watermark.write().await;
        wm.update_signature(self.chain_id, &pkh, &data, &signature)?;
    }

    #[cfg(feature = "perf-trace")]
    eprintln!("[PERF] Update watermark signature: {:?}", t.elapsed());

    #[cfg(feature = "perf-trace")]
    eprintln!("[PERF] ===== TOTAL SIGN REQUEST: {:?} =====\n", request_start.elapsed());

    Ok(SignerResponse::Signature(signature))
}
