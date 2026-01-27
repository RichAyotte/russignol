# Russignol Key Rotation

## Overview

The `russignol rotate-keys` command enables seamless key rotation for Tezos bakers using Russignol hardware signers. This allows you to rotate from one Russignol device to another with minimal downtime.

**Use cases:**
- Routine key rotation for security hygiene
- Migrating to new hardware
- Replacing a potentially compromised device

## Quick Start

```bash
russignol rotate-keys
```

The command will guide you through the complete workflow interactively.

## Command Options

```
russignol rotate-keys [OPTIONS]

OPTIONS:
    --monitor                  Monitor pending key activation (skip import phase)
    --replace                  Replace pending keys with new ones (restart rotation from scratch)
    --dry-run                  Show what would be done without executing
    --yes                      Skip confirmation prompts
    --verbose                  Show detailed output

Hardware configuration:
    --config MODE              Hardware setup: "two-devices" or "single-pi"

Baker restart options:
    --restart-method METHOD    How to restart baker: "systemd", "script", "manual"
    --baker-service NAME       Systemd service name (default: octez-baker)
    --stop-command CMD         Custom command to stop baker
    --start-command CMD        Custom command to start baker
```

## Workflow Steps

### Step 1: Pre-Rotation Checklist

Verifies all requirements before starting:

| Check | Description |
|-------|-------------|
| Tezos node running and synced | Node must be accessible at configured RPC endpoint |
| Delegate address found | You must be a registered delegate |
| Baker is active | Not deactivated on-chain |
| Sufficient balance | At least ~0.01 XTZ for transaction fees |
| octez-client accessible | Required for key management |
| Current consensus key exists | `russignol-consensus` alias must exist |

### Step 2: Connect New Device

1. Connect your NEW Russignol device (or insert NEW SD card)
2. The utility discovers and validates the new keys

### Step 3: Import New Keys

Keys are imported with `-pending` suffix aliases:
- `russignol-consensus-pending` - new consensus key
- `russignol-companion-pending` - new companion key

### Step 4: Submit On-Chain Transaction

**Important:** This step MUST happen while the NEW device is still connected.

For BLS keys (tz4), octez-client generates a "proof of possession" which requires signing. See [BLS Proof of Possession](#bls-proof-of-possession) below for details.

Transactions submitted:
```
set consensus key for <delegate> to russignol-consensus-pending
set companion key for <delegate> to russignol-companion-pending
```

### Step 5: Reconnect Old Device

After transaction submission, reconnect your OLD device to resume baking during the pending period (~2-3 days on mainnet, depending on when in the cycle you submit).

### Step 6: Monitor Activation

The utility calculates the optimal swap window based on your baking rights and displays:
- Activation cycle number
- Estimated time until activation
- Recommended swap window (gaps between your round 0 baking slots)

### Step 7: Execute Swap Sequence (at cycle boundary)

When the new keys activate:

1. **Stop baker daemon**
2. **Swap to NEW device** (disconnect OLD, connect NEW, enter PIN)
3. **Verify new device connectivity**
4. **Promote aliases:**
   - `russignol-consensus` → `russignol-consensus-old` (backup)
   - `russignol-consensus-pending` → `russignol-consensus`
5. **Start baker daemon**
6. **Verify baker is signing**
7. **Cleanup backup aliases**

## BLS Proof of Possession

### What It Is

For BLS keys (tz4 addresses), Tezos requires a "proof of possession" (PoP) when setting a consensus key. This cryptographic proof:
- Demonstrates you control the private key
- Prevents rogue key attacks in BLS aggregate signatures
- Is a signature over a specific message using the key being registered

### Why the Signer Must Be Connected

When you run `set consensus key for <delegate> to <bls_alias>`:

1. octez-client looks up the alias → retrieves cached public key ✓
2. Detects BLS key → needs to generate PoP
3. Calls the signer to produce a signature
4. If wrong signer is connected → "Key not found" error

**This is why Step 4 (Submit Transaction) must happen BEFORE Step 5 (Reconnect Old Device).**

### Error Message

If you see this error:
```
Error:
  Unregistered error:
    { "kind": "generic",
      "error": "Key not found: tz4ABC123..." }
```

It means the connected signer doesn't have the key you're trying to register. Ensure the NEW device is connected when submitting the transaction.

## Alias Management

### Alias States During Rotation

| Phase | `russignol-consensus` | `-pending` | `-old` |
|-------|----------------------|------------|--------|
| Before rotation | OLD key | — | — |
| After Step 3 | OLD key | NEW key | — |
| After Step 7.4 | NEW key | — | OLD key |
| After Step 7.7 | NEW key | — | — |

### Rollback Capability

The `-old` aliases are kept as backups until verification passes:
- If baker fails to start → aliases can be restored
- If verification succeeds → backup aliases are removed

## Timing and Downtime

### Key Activation

- New keys go to "pending" state on-chain
- Activate after `consensus_rights_delay` cycles (~2-3 days)
- Cycle length: ~1 day on mainnet (14,400 blocks × 6 seconds)

### Expected Downtime

| Phase | Duration | Impact |
|-------|----------|--------|
| NEW device for tx submission | ~10-60 seconds | OLD device offline (missed attestations) |
| Swap sequence at cycle boundary | ~10-60 seconds | May miss 1-6 attestations |

**Cost estimate:** ~0.01-0.06 XTZ in missed attestation rewards

### Optimal Swap Window

The utility queries your baking rights and recommends swapping during gaps between your round 0 (priority) baking slots. This minimizes the risk of missing block rewards (~10-20 XTZ per block).

## Hardware Configurations

### Two Pi Devices (Recommended)

```
OLD device: Pi #1 with current keys
NEW device: Pi #2 with new keys

Workflow: Swap USB cables between devices
```

### Single Pi, Two SD Cards

```
SINGLE Pi Zero 2W
OLD SD card: Current keys
NEW SD card: New keys

Workflow: Power down, swap SD cards, power up
```

Note: Single-Pi mode requires additional downtime during SD card swaps.

## Monitor Mode

Check activation status of a pending rotation:

```bash
russignol rotate-keys --monitor
```

This displays:
- Current pending keys
- Activation cycle and time estimate
- Recommended swap window

## Related Documentation

- [Configuration System](CONFIGURATION.md) - Setting up client directories and RPC endpoints
- [Tezos Consensus Keys](https://tezos.gitlab.io/alpha/consensus_key.html) - Official protocol documentation
