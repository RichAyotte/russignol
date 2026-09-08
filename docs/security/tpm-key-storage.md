# TPM Key Storage Compared to a Dedicated Signer

Why a Tezos baking key is not held in the baker host's TPM, and what a TPM does and does not replace.

Measurements below were taken on an AMD Ryzen 7 7700X firmware TPM (Zen 4, family 19h) with tpm2-tools 5.7 on 2026-09-08. The commands are in [Reproducing the measurements](#reproducing-the-measurements); figures on other silicon will differ, but the structural conclusions do not depend on them.

## Summary

| Property | TPM on the baker host | Russignol |
|----------|----------------------|-----------|
| Can hold a tz4 (BLS12-381) key | No — no TPM implements BLS | Yes |
| Can hold a tz6 key | No — TPM XMSS is a different construction | Yes |
| Can hold a tz3 (P-256) key | Yes | n/a |
| Key present in host RAM while signing | Yes, if sealed; no, if TPM-held | Never on the host |
| Refuses a second signature at a spent level | No | Yes |
| Refuses non-consensus operations | No | Yes |
| Signing latency | ~298 ms (P-256, measured) | ~6 ms (BLS) |
| Shares a kernel with network-facing code | Yes | No |

## Two Different Things a TPM Can Do With a Key

The distinction governs everything below.

**Key held by the TPM.** The private key is generated inside the chip and never leaves it. The host sends a digest and receives a signature. Extraction requires breaking the TPM.

**Key sealed by the TPM.** The TPM is an encrypted container. `TPM2_Unseal` returns the plaintext to the host, which then does the signing itself. The TPM protects the key at rest and not in use.

Only the first is a hardware signer. The second is disk encryption with good key management.

## Algorithm Availability

Measured against this host's fTPM with `tpm2_getcap`:

```
algorithms: rsa sha1 hmac aes mgf1 keyedhash xor sha256 sha384 rsassa rsaes
            rsapss oaep ecdsa ecdh ecdaa ecschnorr kdf1_sp800_56a kdf2
            kdf1_sp800_108 ecc symcipher cmac ctr ofb cbc cfb ecb
curves:     TPM2_ECC_NIST_P256, TPM2_ECC_NIST_P384, TPM2_ECC_BN_P256
```

| Tezos key | Scheme | Held by this fTPM |
|-----------|--------|-------------------|
| tz1 | Ed25519 | No — no curve 25519, no EdDSA |
| tz2 | secp256k1 ECDSA | No |
| tz3 | NIST P-256 ECDSA | **Yes** |
| tz4 | BLS12-381 | No |
| tz6 | XMSS (BLAKE2s, leanVM-b) | No |

So on this hardware only a tz3 consensus key can be TPM-held, and a tz3 consensus key forgoes the aggregated attestations that motivate tz4.

Any key type not in that column can still be **sealed**, which is the weaker mode. A 32-byte tz4 secret seals and unseals correctly; the sealed-data ceiling is 128 bytes (129 is refused), and unsealing costs ~125 ms of TPM time.

### Standards Picture

The TCG Algorithm Registry is a namespace serving all TCG specifications; the TPM 2.0 Library specification defines the subset a TPM implements. They differ, and conflating them is easy:

- **BLS12-381** appears in neither. There is no standards path to a TPM-held tz4 key.
- **Ed25519** has a registry curve identifier (`TPM_ECC_CURVE_25519`, 0x0040).
- **XMSS** is in the TPM 2.0 Library itself: version 184 (2025-03-20) added `TPM_ALG_XMSS` (0x0071) as an asymmetric signing algorithm *with a use counter*, alongside LMS. Version 185 (2025) added ML-DSA, HashML-DSA and ML-KEM.

The use counter is the right architecture — a one-time-signature scheme is only safe when the counter lives with the key — but it is SP 800-208 XMSS, which is not what tz6 uses. See [Statefulness](#tz6-and-statefulness).

No shipping TPM implements any of the post-quantum additions. This fTPM's algorithm list is entirely classical, and tpm2-tss master carries none of the identifiers.

## Signing Performance

P-256 ECDSA on this fTPM, the only Tezos-compatible scheme it can hold:

| Measurement | Value |
|-------------|-------|
| `tpm2_sign`, 20 iterations | 8.819 s and 8.838 s across two runs |
| Per invocation | 441 ms |
| CLI startup and context-load baseline (`tpm2_readpublic` × 20) | 144 ms |
| **TPM-side signing cost** | **~298 ms** |
| Russignol BLS12-381 via BLST, for comparison | ~6 ms |

The workload is roughly three signatures per six-second block. ~0.9 s of TPM time per block fits in wall-clock terms, but it is ~50x the device's latency, contends with everything else on the host that uses the TPM, and interacts badly with dictionary-attack lockout if an auth value is bound to the key.

## What a TPM Does Not Enforce

A TPM signs any digest presented to it. It has no notion of a block level or an operation kind, so it cannot refuse:

- a second signature at a level already signed — a slashing condition;
- a transfer, delegation change, or any other operation that is not consensus.

Russignol enforces both before signing:

- magic-byte allowlist, `libs/signer/src/signing_activity.rs:19` — only 0x11 (block), 0x12 (pre-attestation) and 0x13 (attestation);
- per-key high watermark, persisted with `fdatasync` **before** the signature is released. The analysis of the window that existed before that ordering is [watermark-crash-analysis.md](watermark-crash-analysis.md).

This half of the device's job is independent of key secrecy. A host whose key was never compromised, but which an attacker controls, still asks for signatures and still gets them. Only a separate enforcement domain that can say no changes that.

## Kernel Hardening Does Not Substitute

The hardened image already applies the full hardening set — `xtask/src/image.rs:184` asserts 27 kernel config symbols on every image build, and drift fails the build: `CONFIG_COREDUMP` off, `CONFIG_SWAP` off, `CONFIG_DEVMEM` off, `CONFIG_IO_URING` off, `CONFIG_NAMESPACES` off, `CONFIG_LEGACY_PTYS` off, plus YAMA ptrace scoping, `DMESG_RESTRICT`, lockdown in integrity mode enforced early, forced module signatures, `INIT_ON_ALLOC`/`INIT_ON_FREE`, `INIT_STACK_ALL_ZERO`, hardened usercopy, slab freelist hardening and KASLR.

It is applied *on top of* isolation, not instead of it, for three reasons.

**Those symbols defend a process from other processes, not from itself.** A sealed key is plaintext in the address space of whatever calls into the signing library. Code execution inside that process — a parser bug on a network-facing path, a malicious transitive dependency — reads it directly, and none of the above applies.

**The hardening is portable; the attack surface underneath it is not.** The same symbols on a baker host guard a node parsing hostile p2p traffic plus an RPC surface. On the device they guard one program, with WiFi, Bluetooth and Ethernet compiled out, no getty, no SSH, and one input channel carrying length-prefixed signing requests. Some of the list is only affordable *because* the machine does one thing: `CONFIG_NAMESPACES=n` and `CONFIG_IO_URING=n` are not options on a general-purpose host.

**Hardening does not address enforcement.** See the section above.

## tz6 and Statefulness

XMSS moves the security-critical asset from the key to a counter, which is precisely what a seal cannot hold. From `libs/xmss/src/lib.rs:3`:

> XMSS is stateful: every epoch is a one-time key, and signing two different messages at one epoch discloses the secret key rather than costing a deposit.

The failure mode changes category. For tz4, losing watermark state risks slashing — bounded and economic. For tz6, losing epoch state discloses the key, and a power cut at the wrong instant is sufficient with no attacker present.

A TPM seal protects the seed and does nothing for the counter. TPM 2.0 does have the right primitive for the other half in monotonic NV counters (`TPM_NT_COUNTER`), which are rollback-resistant, but they constrain only an honest caller: unsealing returns the seed in plaintext, so code inside the process signs at any epoch it likes, spent ones included, without consulting the TPM.

The design here concentrates that state deliberately. `libs/xmss/src/lib.rs:6` — the crate refuses to track spent epochs so "there is exactly one place in the system that can get it wrong" — and `SecretKey` is not `Clone` because, at `:105`, "a second live copy is a second thing that can sign." Unsealing is a copy, and every process able to unseal is another holder.

**A TPM implementing `TPM_ALG_XMSS` would still not help.** tz6 uses the leanVM-b construction: BLAKE2s under a 16-byte tweak, target-sum WOTS encoding with 99 chains, 11 compressions per WOTS public key, a 32-level Merkle path (`vendors/leanVM-b/crates/xmss/src/hash.rs:1`). SP 800-208 XMSS is SHA-256 or SHAKE with different WOTS+ chaining and address schemes. A TPM implementing the NIST scheme correctly cannot produce a signature a Tezos node verifies as tz6.

The blast radius is also larger. A tz6 key covers 2^24 epochs, 388 days of signing, takes 41 minutes to generate and rotates annually (`rpi-signer/src/constants.rs:70`, `rpi-signer/src/provision.rs:328`). A burned key is not re-provisioned in a hurry, and re-provisioning needs a person at the device entering a PIN.

## Where a TPM Is Worth Using

Sealing is free and strictly better than a plaintext key file for anything that must live on a general-purpose machine. It defeats a stolen disk, a leaked backup and a copied card, because the blob is encrypted under that TPM's seed and inert elsewhere, and it can be bound to a PCR set or a passphrase.

Reasonable uses alongside this project:

- sealing the baker host's disk-encryption key;
- attesting the baker host's boot state.

It is not key custody for a baking key. Sealing raises the at-rest bar and leaves the at-use bar where it was, and for a baker that exposure recurs every ~6 seconds indefinitely. Keys at rest on the device are protected by AES-256-GCM under a scrypt-derived PIN key (`log_n=18`, r=8, p=4, 256 MB; `libs/crypto/src/lib.rs:76`), and the key is never on the host at all.

## Limit Case

Pushed to its limit, the TPM approach converges on a *dedicated* hardened machine running only a signer daemon with a TPM-sealed key. That is a legitimate architecture, and its remaining deltas against this device are:

- no independent display, so nothing shows an operator what is being signed on a channel the requesting host cannot forge;
- a PIN that arrives over the wire rather than being entered on the device;
- an fTPM whose isolation is a co-processor on the same die as the CPU.

On a workstation that also runs the baker, none of that applies and the shared kernel is the whole problem.

## Reproducing the Measurements

Requires `tpm2-tools` and access to `/dev/tpmrm0`. Nothing here writes to TPM NV storage; all objects are transient.

```sh
# Capabilities
tpm2_getcap properties-fixed | grep -A2 TPM2_PT_MANUFACTURER
tpm2_getcap algorithms
tpm2_getcap ecc-curves

# P-256 signing cost. The second loop is the CLI/context-load baseline;
# subtract it from the first.
tpm2_createprimary -C o -g sha256 -G ecc256 -c prim.ctx
tpm2_create -C prim.ctx -g sha256 -G ecc256:ecdsa-sha256 -u k.pub -r k.priv
tpm2_load -C prim.ctx -u k.pub -r k.priv -c k.ctx
head -c 64 /dev/urandom > msg.bin
time for i in $(seq 1 20); do tpm2_sign -c k.ctx -g sha256 -o sig.bin msg.bin; done
time for i in $(seq 1 20); do tpm2_readpublic -c k.ctx; done

# Sealing a BLS-sized secret, and the 128-byte ceiling
head -c 32 /dev/urandom > sk.bin
tpm2_create -C prim.ctx -i sk.bin -u seal.pub -r seal.priv
tpm2_load -C prim.ctx -u seal.pub -r seal.priv -c seal.ctx
tpm2_unseal -c seal.ctx | xxd -p -c32     # returns the plaintext to the host
head -c 129 /dev/urandom > big.bin
tpm2_create -C prim.ctx -i big.bin -u b.pub -r b.priv   # refused

tpm2_flushcontext -t
```

## Verification Status

The measured figures and every repository citation above were taken directly. The standards claims were not: trustedcomputinggroup.org serves a Cloudflare challenge to automated fetches, so the contents of the TCG Algorithm Registry v2.0 and of TPM 2.0 Library Part 2 v184/v185 are reported at second hand and should be confirmed against the specifications before being relied on. They affect only the [Standards Picture](#standards-picture) section; no conclusion in this document rests on them, because no shipping TPM implements the algorithms in question and tz6's construction differs from the specified one regardless.
