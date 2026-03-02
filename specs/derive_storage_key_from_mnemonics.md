## Overview

The launcher currently encrypts the secondary persistent storage disk using LUKS with a hardcoded placeholder key (`"test-key-123"` in `launcher/internal/storage/encrypted_volume.go`). This feature replaces the placeholder with a real key derived from the BIP39 mnemonic retrieved from KMS.

The derivation uses BIP39 to convert the mnemonic to a seed, then applies HMAC-SHA256 with a domain separation tag (DST) to produce a purpose-specific 256-bit key. The DST ensures the storage key can never collide with keys derived for other purposes (EVM addresses, Solana addresses) from the same mnemonic, even if those systems use different derivation schemes.

Because the mnemonic is deterministic per app (derived via `HMAC(appID)` on the KMS), the same VM will always derive the same storage key, allowing it to reopen the LUKS volume across reboots.

### Key references

- Current storage setup: `launcher/internal/storage/encrypted_volume.go`
- Mnemonic source: `launcher/container_runner.go` → `ContainerRunner.mnemonic` (fetched from KMS)
- Integration point: `container_runner.go` line 668, where `SetupSecondaryEncryptedVolume` is called

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

#### Step 2: Modify storage functions to accept a key parameter

**File**: `launcher/internal/storage/encrypted_volume.go`

Change `SetupSecondaryEncryptedVolume`, `luksFormat`, and `luksOpen` to accept a key parameter instead of using `defaultKey`:

```go
func SetupSecondaryEncryptedVolume(logger logging.Logger, encryptionKey string) error {
    // ... same logic, but pass encryptionKey to luksFormat/luksOpen
}

func luksFormat(device string, key string) error {
    cmd := exec.Command("cryptsetup", "luksFormat", "--pbkdf", "pbkdf2", device, "-")
    cmd.Stdin = strings.NewReader(key)
    // ...
}

func luksOpen(device, name string, key string) error {
    cmd := exec.Command("cryptsetup", "luksOpen", device, name, "-")
    cmd.Stdin = strings.NewReader(key)
    // ...
}
```

Remove the `defaultKey` constant entirely — no fallback to the placeholder key.

#### Step 3: Integrate into ContainerRunner.Run()

**File**: `launcher/container_runner.go`

At line 668, where `SetupSecondaryEncryptedVolume` is already called, derive the key from the mnemonic and pass it in:

```go
// Derive storage encryption key from the KMS mnemonic.
var storageKey string
if r.mnemonic != "" {
    keyBytes, err := storage.DeriveStorageKey(r.mnemonic)
    if err != nil {
        return fmt.Errorf("failed to derive storage key from mnemonic: %v", err)
    }
    storageKey = hex.EncodeToString(keyBytes)
    storage.ZeroBytes(keyBytes)
} else {
    return fmt.Errorf("mnemonic is required for storage encryption but not available")
}

r.logger.Info("Setting up encrypted volume")
if err := storage.SetupSecondaryEncryptedVolume(r.logger, storageKey); err != nil {
    return fmt.Errorf("failed to set up encrypted volume: %v", err)
}
```

The hex-encoded 32-byte key (64 hex characters) is passed as the LUKS passphrase.

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
| `launcher/internal/storage/key_derivation.go` | **New** — `DeriveStorageKey()` and exported `ZeroBytes()` |
| `launcher/internal/storage/key_derivation_test.go` | **New** — 5 unit tests for key derivation |
| `launcher/internal/storage/encrypted_volume.go` | Removed `defaultKey` constant; `SetupSecondaryEncryptedVolume`, `luksFormat`, `luksOpen` now accept a key parameter |
| `launcher/container_runner.go` | Derives storage key from `r.mnemonic` before calling `SetupSecondaryEncryptedVolume` |

### Key Derivation (`launcher/internal/storage/key_derivation.go`)

`DeriveStorageKey(mnemonic string) ([]byte, error)` performs two steps:

1. **BIP39 seed**: `pbkdf2.Key(mnemonic, "mnemonic", 2048, 64, SHA-512)` → 64-byte seed
2. **HMAC-SHA256**: `HMAC(key="EIGENX_STORAGE_KEY_DERIVATION_V1", data=seed)` → 32-byte key

The seed is zeroed via `defer ZeroBytes(seed)` after the HMAC is computed. The returned 32-byte key is the caller's responsibility to zero.

`ZeroBytes()` is exported so that `container_runner.go` can zero the key bytes after hex-encoding them for LUKS.

### Encrypted Volume (`launcher/internal/storage/encrypted_volume.go`)

Removed `defaultKey = "test-key-123"` constant. The three functions that used it now accept a key parameter:

- `SetupSecondaryEncryptedVolume(logger, encryptionKey string)` — passes key down to `luksFormat` and `luksOpen`
- `luksFormat(device, key string)` — feeds key via stdin to `cryptsetup luksFormat`
- `luksOpen(device, name, key string)` — feeds key via stdin to `cryptsetup luksOpen`

The boot disk fallback path (no secondary device) is unchanged — it creates a plain directory and does not use LUKS.

### ContainerRunner Integration (`launcher/container_runner.go`)

Before calling `SetupSecondaryEncryptedVolume`, the runner now:

1. Checks that `r.mnemonic` is not empty (fails if missing)
2. Calls `storage.DeriveStorageKey(r.mnemonic)` to get the 32-byte key
3. Hex-encodes it (64 characters) as the LUKS passphrase
4. Zeros the raw key bytes
5. Passes the hex string to `SetupSecondaryEncryptedVolume`

### Test Details (`launcher/internal/storage/key_derivation_test.go`)

| Test | What it verifies |
|------|------------------|
| `TestDeriveStorageKey_Deterministic` | Same mnemonic produces identical key across two calls |
| `TestDeriveStorageKey_Stable` | Output matches a pinned expected value, detecting accidental derivation changes |
| `TestDeriveStorageKey_DifferentMnemonics` | Different mnemonics produce different keys |
| `TestDeriveStorageKey_KeyLength` | Output is exactly 32 bytes |
| `TestDeriveStorageKey_EmptyMnemonic` | Empty string is rejected with an error |

All tests pass:

```
docker run --rm -v "$(pwd):/src" -v ~/go/pkg/mod:/go/pkg/mod -w /src/launcher golang:1.24 go test -v ./internal/storage/...
```
