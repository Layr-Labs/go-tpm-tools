## Overview

The launcher currently encrypts the secondary persistent storage disk using LUKS with a hardcoded placeholder key (`"test-key-123"` in `launcher/internal/storage/encrypted_volume.go`). This feature replaces the placeholder with a real key derived from the BIP39 mnemonic retrieved from KMS.

The derivation uses BIP39 to convert the mnemonic to a seed, then applies HMAC-SHA256 with a domain separation tag (DST) to produce a purpose-specific 256-bit key. The DST ensures the storage key can never collide with keys derived for other purposes (EVM addresses, Solana addresses) from the same mnemonic, even if those systems use different derivation schemes.

Because the mnemonic is deterministic per app (derived via `HMAC(appID)` on the KMS), the same VM will always derive the same storage key, allowing it to reopen the LUKS volume across reboots.

### Key references

- Current storage setup: `launcher/internal/storage/encrypted_volume.go`
- Mnemonic source: `launcher/kmsclient/kmsclient.go` → `GetMnemonicFromKMS()` (fetched from KMS on demand)
- Integration point: `container_runner.go`, where `SetupSecondaryEncryptedVolume` is called with a `MnemonicProvider`

---

## Implementation Plan

### Architecture Decision: BIP39 seed + HMAC-SHA256 with domain separator

Rather than repurposing the BIP32/BIP44 HD wallet derivation path (designed for cryptocurrency key hierarchies), use a simpler and more appropriate scheme:

1. **BIP39**: mnemonic → 64-byte seed (standard PBKDF2)
2. **HMAC-SHA256**: seed + DST → 32-byte storage key

The domain separation tag `"EIGENX_STORAGE_KEY_DERIVATION_V1"` is used as the HMAC key, following the same pattern as the KMS's own `"COMPUTE_APP_KEY_DERIVATION_V1"` domain separator. This makes the derivation purpose explicit and auditable, and guarantees the output cannot collide with keys derived for other purposes from the same mnemonic.

No new external dependencies are needed — only Go's standard `crypto/hmac`, `crypto/sha256`, and `golang.org/x/crypto/pbkdf2` (already in `launcher/go.mod`).

### Step-by-Step Implementation

#### Step 1: Add key derivation function

**New file**: `launcher/internal/storage/key_derivation.go`

```go
const storageKeyDST = "EIGENX_STORAGE_KEY_DERIVATION_V1"

func DeriveStorageKey(mnemonic string) ([]byte, error) {
    if mnemonic == "" {
        return nil, fmt.Errorf("mnemonic must not be empty")
    }

    // BIP39: mnemonic → 64-byte seed via PBKDF2(mnemonic, "mnemonic", 2048, SHA-512)
    seed := pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New)
    defer zeroBytes(seed)

    // Derive storage key: HMAC-SHA256 with domain separation tag.
    // The DST ensures this key is independent of any BIP32/BIP44 derived key
    // (EVM, Solana) from the same mnemonic.
    h := hmac.New(sha256.New, []byte(storageKeyDST))
    h.Write(seed)
    return h.Sum(nil), nil // 32 bytes = 256-bit key
}
```

Zero the seed after use. The HMAC output does not need zeroing here because it is returned to the caller (who is responsible for zeroing it).

#### Step 2: Modify SetupSecondaryEncryptedVolume to accept a MnemonicProvider

**File**: `launcher/internal/storage/encrypted_volume.go`

Instead of accepting a pre-derived key, the function takes a `MnemonicProvider` callback that is only called when a secondary device is found. This avoids unnecessary KMS calls when no disk is attached and sidesteps the chicken-and-egg problem (KMS needs PCR allowlisting, which requires running a workload first).

```go
type MnemonicProvider func() (string, error)

func SetupSecondaryEncryptedVolume(logger logging.Logger, mnemonicProvider MnemonicProvider) error {
    devicePath := findSecondaryDevice()
    if devicePath == "" {
        // No secondary device — fall back to boot disk, no KMS call needed.
        // ...
        return nil
    }

    // Secondary device found — now fetch mnemonic and derive key.
    mnemonic, err := mnemonicProvider()
    if err != nil {
        return fmt.Errorf("failed to fetch mnemonic for disk encryption: %w", err)
    }
    storageKeyBytes, err := DeriveStorageKey(mnemonic)
    if err != nil {
        return fmt.Errorf("failed to derive storage key from mnemonic: %w", err)
    }
    encryptionKey := hex.EncodeToString(storageKeyBytes)
    ZeroBytes(storageKeyBytes)

    // ... luksFormat/luksOpen with encryptionKey
}
```

Remove the `defaultKey` constant entirely. `luksFormat` and `luksOpen` accept a key parameter.

#### Step 3: Integrate into ContainerRunner.Run()

**File**: `launcher/container_runner.go`

Pass a closure that captures the KMS config and attestation agent. The storage package doesn't know about KMS — it just calls the function when it needs a mnemonic:

```go
mnemonicProvider := func() (string, error) {
    if r.launchSpec.KMSServerURL == "" {
        return "", fmt.Errorf("KMS server URL is required for storage encryption")
    }
    r.logger.Info("Fetching mnemonic from KMS")
    mnemonic, err := kmsclient.GetMnemonicFromKMS(ctx, r.launchSpec, r.attestAgent)
    if err != nil {
        return "", fmt.Errorf("failed to fetch mnemonic from KMS: %v", err)
    }
    r.logger.Info("Successfully retrieved mnemonic from KMS")
    return mnemonic, nil
}

r.logger.Info("Setting up encrypted volume")
if err := storage.SetupSecondaryEncryptedVolume(r.logger, mnemonicProvider); err != nil {
    return fmt.Errorf("failed to set up encrypted volume: %v", err)
}
```

This keeps the `storage` and `kmsclient` packages decoupled — the storage package only knows "call this to get a mnemonic", not how it's obtained.

#### Step 4: Write tests

**New file**: `launcher/internal/storage/key_derivation_test.go`

- **TestDeriveStorageKey_Deterministic** — verify the same mnemonic always produces the same key
- **TestDeriveStorageKey_DifferentMnemonics** — verify different mnemonics produce different keys
- **TestDeriveStorageKey_KeyLength** — verify the output is exactly 32 bytes
- **TestDeriveStorageKey_EmptyMnemonic** — verify empty mnemonic is rejected

Use a known BIP39 test mnemonic (e.g. `"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"`) and hardcode the expected key to detect accidental changes to the derivation logic.

### Security Considerations

- **Domain separation** — `"EIGENX_STORAGE_KEY_DERIVATION_V1"` as the HMAC key guarantees the storage key is cryptographically independent from any BIP32/BIP44 derived key (EVM, Solana), even though they share the same mnemonic
- **Versioned DST** — the `_V1` suffix allows rotating to a new derivation scheme in the future without ambiguity
- **Deterministic across reboots** — the same mnemonic always produces the same key, so the VM can reopen the LUKS volume after reboot without storing the key on disk
- **Sensitive buffers zeroed** — the BIP39 seed is zeroed after use; the caller zeros the returned key bytes after passing them to LUKS
- **Key never logged** — only success/failure messages are emitted; the key value is never included in logs
- **No fallback to placeholder** — the hardcoded `defaultKey` is removed; if no mnemonic is available, the launcher fails explicitly
- **Lazy KMS fetch** — the mnemonic is only fetched from KMS when a secondary device is detected, avoiding unnecessary KMS calls and the chicken-and-egg problem (KMS needs PCR allowlisting, which requires running a workload first)
- **Mnemonic not stored on struct** — the mnemonic is a local variable inside the provider closure, not persisted on `ContainerRunner`

### Build and Test Verification

From the repository root:

```
docker run --rm -v "$(pwd):/src" -v ~/go/pkg/mod:/go/pkg/mod -w /src/launcher golang:1.24 go test -v ./internal/storage/...
```

---

## Implementation Details

### Files Changed

| File | Change |
|------|--------|
| `launcher/internal/storage/key_derivation.go` | **New** — `DeriveStorageKey()`, `ZeroBytes()`, BIP39 validation |
| `launcher/internal/storage/key_derivation_test.go` | **New** — 6 unit tests for key derivation |
| `launcher/internal/storage/encrypted_volume.go` | Removed `defaultKey`; `SetupSecondaryEncryptedVolume` takes a `MnemonicProvider` callback; key derivation happens inside, only when secondary device found |
| `launcher/container_runner.go` | Passes a `MnemonicProvider` closure (wrapping KMS fetch) to `SetupSecondaryEncryptedVolume` |

### Key Derivation (`launcher/internal/storage/key_derivation.go`)

`DeriveStorageKey(mnemonic string) ([]byte, error)` performs two steps:

1. **BIP39 seed**: `pbkdf2.Key(mnemonic, "mnemonic", 2048, 64, SHA-512)` → 64-byte seed
2. **HMAC-SHA256**: `HMAC(key="EIGENX_STORAGE_KEY_DERIVATION_V1", data=seed)` → 32-byte key

The seed is zeroed via `defer ZeroBytes(seed)` after the HMAC is computed. The returned 32-byte key is the caller's responsibility to zero.

`ZeroBytes()` is exported so that `container_runner.go` can zero the key bytes after hex-encoding them for LUKS.

### Encrypted Volume (`launcher/internal/storage/encrypted_volume.go`)

Removed `defaultKey = "test-key-123"` constant. `SetupSecondaryEncryptedVolume` now takes a `MnemonicProvider func() (string, error)` instead of a pre-derived key string. The function:

1. Detects if a secondary device exists
2. If no device — creates a plain directory on boot disk, returns without calling the provider
3. If device found — calls `mnemonicProvider()` to fetch the mnemonic, derives the key via `DeriveStorageKey`, hex-encodes it, and passes it to `luksFormat`/`luksOpen`

This ensures the KMS is only contacted when encryption is actually needed.

`luksFormat(device, key string)` and `luksOpen(device, name, key string)` accept a key parameter and feed it via stdin to `cryptsetup`.

### ContainerRunner Integration (`launcher/container_runner.go`)

The runner passes a closure to `SetupSecondaryEncryptedVolume` that captures the KMS config and attestation agent:

```go
mnemonicProvider := func() (string, error) {
    return kmsclient.GetMnemonicFromKMS(ctx, r.launchSpec, r.attestAgent)
}
storage.SetupSecondaryEncryptedVolume(r.logger, mnemonicProvider)
```

This keeps the `storage` and `kmsclient` packages decoupled — the storage package doesn't import or know about KMS, attestation, or launch specs. The mnemonic is never stored on the `ContainerRunner` struct.

### Test Details (`launcher/internal/storage/key_derivation_test.go`)

| Test | What it verifies |
|------|------------------|
| `TestDeriveStorageKey_Deterministic` | Same mnemonic produces identical key across two calls |
| `TestDeriveStorageKey_Stable` | Output matches a pinned expected value, detecting accidental derivation changes |
| `TestDeriveStorageKey_DifferentMnemonics` | Different mnemonics produce different keys |
| `TestDeriveStorageKey_KeyLength` | Output is exactly 32 bytes |
| `TestDeriveStorageKey_EmptyMnemonic` | Empty string is rejected with an error |
| `TestDeriveStorageKey_InvalidMnemonic` | Invalid BIP39 mnemonics (bad words, bad checksum) are rejected |

All tests pass:

```
docker run --rm -v "$(pwd):/src" -v ~/go/pkg/mod:/go/pkg/mod -w /src/launcher golang:1.24 go test -v ./internal/storage/...
```
