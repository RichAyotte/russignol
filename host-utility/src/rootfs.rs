//! Rootfs-region hashing for the flash manifest.
//!
//! The flash manifest records the SHA-256 of the image's rootfs partition
//! (MBR partition 2) so the device can re-hash `/dev/mmcblk0p2` on first boot
//! and detect accidental corruption. The hash is teed off the byte stream the
//! flash writes to the card, and the region is taken from that stream's own
//! MBR — the same table the kernel reads on the device — so both sides hash
//! the same byte range by construction, in the flash's single pass.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::io::Write;

const SECTOR_SIZE: u64 = 512;
const MBR_LEN: usize = 512;

/// Offset of MBR partition entry 2 (the rootfs) in the partition table
const PARTITION_2_ENTRY: usize = 446 + 16;

/// Byte range `[start, end)` of the rootfs partition (MBR entry 2) within an
/// image, parsed from the image's first sector.
///
/// # Errors
///
/// Fails when `mbr` is shorter than a sector, lacks the `0x55AA` boot
/// signature, or partition 2 is absent or has a zero extent.
pub fn rootfs_region(mbr: &[u8]) -> Result<(u64, u64)> {
    if mbr.len() < MBR_LEN {
        bail!("MBR truncated: {} of {MBR_LEN} bytes", mbr.len());
    }
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        bail!("missing MBR boot signature");
    }
    let entry = &mbr[PARTITION_2_ENTRY..PARTITION_2_ENTRY + 16];
    if entry[4] == 0 {
        bail!("no rootfs partition (MBR entry 2 is empty)");
    }
    let lba_start = u64::from(u32::from_le_bytes(
        entry[8..12].try_into().expect("4 bytes"),
    ));
    let sectors = u64::from(u32::from_le_bytes(
        entry[12..16].try_into().expect("4 bytes"),
    ));
    if lba_start == 0 || sectors == 0 {
        bail!("rootfs partition (MBR entry 2) has a zero extent");
    }
    Ok((lba_start * SECTOR_SIZE, (lba_start + sectors) * SECTOR_SIZE))
}

/// A `Write` sink that hashes only the rootfs partition region of an image
/// streamed through it, parsing the region from the MBR as it arrives.
pub struct RootfsRegionHasher {
    pos: u64,
    mbr: Vec<u8>,
    region: Option<(u64, u64)>,
    hasher: Sha256,
}

impl RootfsRegionHasher {
    pub fn new() -> Self {
        Self {
            pos: 0,
            mbr: Vec::with_capacity(MBR_LEN),
            region: None,
            hasher: Sha256::new(),
        }
    }

    /// The rootfs region's SHA-256 hex, once the full image has streamed
    /// through.
    ///
    /// # Errors
    ///
    /// Fails when the stream ended before the rootfs partition's last byte.
    pub fn finish(self) -> Result<String> {
        let (_, end) = self.region.context("image too short to contain an MBR")?;
        if self.pos < end {
            bail!(
                "image ends at byte {} but the rootfs partition extends to byte {end}",
                self.pos
            );
        }
        Ok(hex::encode(self.hasher.finalize()))
    }
}

impl Write for RootfsRegionHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let buf_start = self.pos;
        let buf_end = buf_start + buf.len() as u64;

        if self.mbr.len() < MBR_LEN {
            let take = (MBR_LEN - self.mbr.len()).min(buf.len());
            self.mbr.extend_from_slice(&buf[..take]);
            if self.mbr.len() == MBR_LEN {
                // Abort the stream on an unusable MBR instead of draining it
                let region = rootfs_region(&self.mbr).map_err(std::io::Error::other)?;
                self.region = Some(region);
            }
        }

        // Partitions start at LBA >= 1, so no region byte can precede the
        // parse above — even within this same buffer, handled next.
        if let Some((start, end)) = self.region {
            let lo = buf_start.max(start);
            let hi = buf_end.min(end);
            if lo < hi {
                let range = usize::try_from(lo - buf_start).expect("buffer-sized offset")
                    ..usize::try_from(hi - buf_start).expect("buffer-sized offset");
                self.hasher.update(&buf[range]);
            }
        }

        self.pos = buf_end;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A `Write` tee that forwards every byte to `inner` (the flash pipe) while
/// hashing the rootfs region as it streams past. A hashing failure is
/// recorded, never propagated: the hash only feeds the device's advisory
/// integrity check, so a nonstandard image (e.g. an experimental layout) must
/// still flash.
pub struct RootfsHashingWriter<W: Write> {
    inner: W,
    hasher: Result<RootfsRegionHasher, String>,
}

impl<W: Write> RootfsHashingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Ok(RootfsRegionHasher::new()),
        }
    }

    /// The inner writer and the rootfs region's SHA-256 hex, once the full
    /// image has streamed through.
    ///
    /// # Errors
    ///
    /// The hash side fails when the stream did not carry a complete,
    /// well-formed rootfs partition.
    pub fn finish(self) -> (W, Result<String>) {
        let hash = match self.hasher {
            Ok(hasher) => hasher.finish(),
            Err(e) => Err(anyhow::anyhow!(e)),
        };
        (self.inner, hash)
    }
}

impl<W: Write> Write for RootfsHashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        // Hash only the bytes `inner` accepted; the caller re-sends the rest
        if let Ok(hasher) = &mut self.hasher
            && let Err(e) = hasher.write_all(&buf[..n])
        {
            self.hasher = Err(e.to_string());
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An MBR whose partition 2 starts at `lba_start` and spans `sectors`
    fn mbr_with_partition_2(lba_start: u32, sectors: u32) -> Vec<u8> {
        let mut mbr = vec![0u8; MBR_LEN];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        mbr[PARTITION_2_ENTRY + 4] = 0x83;
        mbr[PARTITION_2_ENTRY + 8..PARTITION_2_ENTRY + 12]
            .copy_from_slice(&lba_start.to_le_bytes());
        mbr[PARTITION_2_ENTRY + 12..PARTITION_2_ENTRY + 16].copy_from_slice(&sectors.to_le_bytes());
        mbr
    }

    #[test]
    fn rootfs_region_parses_partition_2() {
        let mbr = mbr_with_partition_2(96, 64);
        assert_eq!(rootfs_region(&mbr).unwrap(), (96 * 512, 160 * 512));
    }

    #[test]
    fn rootfs_region_rejects_missing_boot_signature() {
        let mut mbr = mbr_with_partition_2(96, 64);
        mbr[510] = 0;
        assert!(rootfs_region(&mbr).is_err());
    }

    #[test]
    fn rootfs_region_rejects_empty_partition_2() {
        let mut mbr = mbr_with_partition_2(96, 64);
        mbr[PARTITION_2_ENTRY + 4] = 0;
        assert!(rootfs_region(&mbr).is_err());
    }

    #[test]
    fn rootfs_region_rejects_zero_extent() {
        assert!(rootfs_region(&mbr_with_partition_2(96, 0)).is_err());
        assert!(rootfs_region(&mbr_with_partition_2(0, 64)).is_err());
    }

    #[test]
    fn rootfs_region_rejects_truncated_mbr() {
        assert!(rootfs_region(&[0u8; 100]).is_err());
    }

    /// Image layout: MBR, one filler sector, a 2-sector rootfs, one trailing
    /// sector. Only the rootfs sectors must be hashed.
    fn synthetic_image() -> (Vec<u8>, String) {
        let mut image = mbr_with_partition_2(2, 2);
        image.extend_from_slice(&[0xAA; 512]); // sector 1: filler
        let rootfs = [0x5A; 1024]; // sectors 2-3: rootfs
        image.extend_from_slice(&rootfs);
        image.extend_from_slice(&[0xBB; 512]); // sector 4: trailing
        let expected = hex::encode(Sha256::digest(rootfs));
        (image, expected)
    }

    #[test]
    fn hashing_writer_tees_bytes_and_hashes_only_the_partition_region() {
        let (image, expected) = synthetic_image();
        let mut tee = RootfsHashingWriter::new(Vec::new());
        tee.write_all(&image).unwrap();

        let (inner, hash) = tee.finish();
        assert_eq!(inner, image);
        assert_eq!(hash.unwrap(), expected);
    }

    /// A writer that accepts at most `max` bytes per call, forcing short
    /// writes
    struct ShortWriter {
        data: Vec<u8>,
        max: usize,
    }

    impl Write for ShortWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.max);
            self.data.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A short write makes the caller re-send the unaccepted tail; the tee
    /// must hash exactly the accepted prefix, or the re-sent bytes land at
    /// shifted positions and corrupt the digest. Chunked feeding keeps the
    /// re-sends inside the region, where the shift is visible.
    #[test]
    fn hashing_writer_hashes_only_the_bytes_the_inner_writer_accepted() {
        let (image, expected) = synthetic_image();
        let mut tee = RootfsHashingWriter::new(ShortWriter {
            data: Vec::new(),
            max: 7,
        });
        for chunk in image.chunks(512) {
            tee.write_all(chunk).unwrap();
        }

        let (inner, hash) = tee.finish();
        assert_eq!(inner.data, image);
        assert_eq!(hash.unwrap(), expected);
    }

    /// An image without a usable MBR still streams through in full — the hash
    /// is advisory, the flash is not.
    #[test]
    fn hashing_writer_forwards_everything_despite_an_invalid_mbr() {
        let image = vec![0u8; 4096];
        let mut tee = RootfsHashingWriter::new(Vec::new());
        tee.write_all(&image).unwrap();

        let (inner, hash) = tee.finish();
        assert_eq!(inner, image);
        assert!(hash.is_err());
    }

    #[test]
    fn hashing_writer_errors_when_the_stream_ends_inside_the_region() {
        let (image, _) = synthetic_image();
        let mut tee = RootfsHashingWriter::new(Vec::new());
        tee.write_all(&image[..512 * 3]).unwrap();

        let (_, hash) = tee.finish();
        assert!(hash.is_err());
    }

    /// The region hasher must produce the same digest regardless of how the
    /// stream is chunked, including chunks spanning the MBR boundary.
    #[test]
    fn region_hasher_is_chunking_invariant() {
        let (image, expected) = synthetic_image();
        for chunk_size in [1, 7, 512, 513, 4096] {
            let mut sink = RootfsRegionHasher::new();
            for chunk in image.chunks(chunk_size) {
                sink.write_all(chunk).unwrap();
            }
            assert_eq!(
                sink.finish().unwrap(),
                expected,
                "chunk size {chunk_size} must not change the digest"
            );
        }
    }
}
