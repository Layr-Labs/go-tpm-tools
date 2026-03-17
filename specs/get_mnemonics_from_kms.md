## Overview

The launcher needs to retrieve a BIP39 mnemonic from the EigenX KMS before starting the container workload. This mnemonic is used to derive a disk encryption key for the secondary persistent storage disk (see `derive_storage_key_from_mnemonics.md`).

The flow works as follows: after the TEE server starts, the launcher sends an attestation to the KMS via the `/env/v3` protocol. The KMS verifies the attestation, derives a deterministic mnemonic for the app (via `HMAC(appID)`), and returns it along with any other environment variables — all encrypted with an ephemeral RSA key. The launcher decrypts the response and stores the mnemonic for later use.

The implementation imports `eigenx-kms/pkg/envclient` (which already implements the full V3 protocol) and provides a custom `AttestationProvider` that calls `attestAgent.BoundAttestationEvidence()` directly in-process, rather than going through the teeserver Unix socket.

### Key references

- KMS client usage: `eigenx-kms/cmd/kms-client/main.go:53-60`
- KMS protocol details: `eigenx-kms/kms.md`
- Envclient implementation: `eigenx-kms/pkg/envclient/envclient.go`
- Insertion point: `go-tpm-tools/launcher/container_runner.go`, after `go teeServer.Serve()` (~line 626)

---

## Implementation Plan

### Architecture Decision: Import envclient with custom AttestationProvider

**Decided**: Import `github.com/Layr-Labs/eigenx-kms/pkg/envclient` and pass it a custom `AttestationProvider` that wraps the in-process `attestAgent`.

The envclient defines an `AttestationProvider` interface (`GetAttestation(ctx, challenge) ([]byte, error)`). We implement this interface using `attestAgent.BoundAttestationEvidence()` directly, then pass it to `envclient.NewEnvClient()`. This gives us:
- Zero code duplication for the KMS protocol (request building, signature verification, JWE decryption)
- Automatic sync with KMS protocol changes
- In-process attestation (no Unix socket round-trip)

### Configuration: New LaunchSpec Fields

The launcher needs to know:
1. **KMS server URL** — Where to send the `/env/v3` request
2. **KMS signing public key** — To verify the KMS response signature (PEM bytes or file path)
3. **User API URL** — For v3 attestation upload (optional, can be deferred)

These will be provided via GCE instance metadata, consistent with existing config patterns (e.g. `tee-image-reference`, `tee-env-*`). All values are stored as plain strings in metadata attributes. The signing key PEM is base64-encoded to avoid newline issues in metadata values. PEM keys are small (~300 bytes), well within the 256KB metadata attribute limit.

| Metadata Key | LaunchSpec Field | Description |
|---|---|---|
| `tee-kms-server-url` | `KMSServerURL string` | URL of the KMS server (e.g. `https://kms.eigenx.io`) |
| `tee-kms-signing-public-key` | `KMSSigningPublicKey string` | Base64-encoded KMS signing public key PEM |
| `tee-kms-user-api-url` | `KMSUserAPIURL string` | User API URL (optional) |

If `KMSServerURL` is empty, the KMS fetch is skipped entirely (backward-compatible with existing deployments).

### Attestation Strategy: In-process vs. Socket

The `BoundEvidenceProvider` in eigenx-kms connects to the teeserver Unix socket (`/run/container_launcher/teeserver.sock`) to get attestation. However, the launcher process already holds the `attestAgent` object and can call `attestAgent.BoundAttestationEvidence()` directly. This is:
- More efficient (no HTTP + Unix socket round-trip)
- Simpler (no dependency on the teeserver being ready to accept connections)
- Available immediately after CEL measurement (the attestation agent is initialized in `NewRunner`)

We will implement a custom `AttestationProvider` that wraps the in-process `attestAgent` and pass it to `envclient.NewEnvClient()`. The provider implements the envclient's `AttestationProvider` interface by calling `attestAgent.BoundAttestationEvidence()` and serializing the result to protobuf bytes — the same format the teeserver's `/v1/bound_evidence` endpoint returns.

### Step-by-Step Implementation

#### Step 1: Add KMS config fields to LaunchSpec

**File**: `launcher/spec/launch_spec.go`

- Add new metadata key constants: `kmsServerURL`, `kmsSigningPublicKey`, `kmsUserAPIURL`
- Add new fields to `LaunchSpec` struct: `KMSServerURL`, `KMSSigningPublicKey`, `KMSUserAPIURL`
- Parse them in `UnmarshalJSON()`

#### Step 2: Implement in-process AttestationProvider and KMS fetch wrapper

**New file**: `launcher/kmsclient/kmsclient.go`

This is a thin wrapper that:
1. Implements `envclient.AttestationProvider` using the in-process `attestAgent`
2. Provides a `GetMnemonicFromKMS()` function that wires everything together

```go
// InProcessAttestationProvider implements envclient.AttestationProvider
// by calling attestAgent.BoundAttestationEvidence() directly.
type InProcessAttestationProvider struct {
    attestAgent agent.AttestationAgent
}

func (p *InProcessAttestationProvider) GetAttestation(ctx context.Context, challenge []byte) ([]byte, error) {
    if len(challenge) == 0 {
        return nil, fmt.Errorf("challenge must not be empty")
    }

    attestation, err := p.attestAgent.BoundAttestationEvidence(agent.BoundAttestationOpts{
        Challenge: challenge,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to generate bound attestation evidence: %w", err)
    }

    attestBytes, err := proto.Marshal(attestation)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal attestation to protobuf: %w", err)
    }

    return attestBytes, nil
}
```

Then use `envclient.NewEnvClient(logger, provider, kmsSigningPublicKey, serverURL, userAPIURL)` and call `envClient.GetEnv(ctx)` — all KMS protocol logic (RSA key gen, request building, signature verification, JWE decryption, retries) is handled by the imported envclient.

New dependency in `launcher/go.mod`:
- `github.com/Layr-Labs/eigenx-kms` (brings in transitive deps including `lestrrat-go/jwx/v3`, `go-ethereum`, `solana-go`, etc.)

#### Step 3: Integrate into ContainerRunner.Run()

**File**: `launcher/container_runner.go`

After `go teeServer.Serve()` (line 626) and before container task creation (line 653), add:

```go
// Fetch environment variables from KMS (includes mnemonic for disk encryption).
if r.launchSpec.KMSServerURL != "" {
    r.logger.Info("Fetching environment from KMS")
    kmsSigningPublicKeyBytes, err := base64.StdEncoding.DecodeString(r.launchSpec.KMSSigningPublicKey)
    if err != nil {
        return fmt.Errorf("failed to decode KMS signing key: %v", err)
    }
    provider := kmsclient.NewInProcessAttestationProvider(r.attestAgent)
    envClient := envclient.NewEnvClient(r.logger, provider, kmsSigningPublicKeyBytes, r.launchSpec.KMSServerURL, r.launchSpec.KMSUserAPIURL)
    envJSONBytes, err := envClient.GetEnv(ctx)
    if err != nil {
        return fmt.Errorf("failed to fetch env from KMS: %v", err)
    }
    kmsEnv := make(map[string]string)
    if err := json.Unmarshal(envJSONBytes, &kmsEnv); err != nil {
        return fmt.Errorf("failed to unmarshal KMS env: %v", err)
    }
    mnemonic, ok := kmsEnv["MNEMONIC"]
    if !ok {
        return fmt.Errorf("KMS response missing MNEMONIC")
    }
    r.mnemonic = mnemonic
    r.logger.Info("Successfully retrieved mnemonic from KMS")
}
```

**Decided**: Store the mnemonic on the `ContainerRunner` struct (`r.mnemonic string`) for use by the disk encryption feature (see `derive_storage_key_from_mnemonics.md`).

#### Step 4: Write tests

**New file**: `launcher/kmsclient/kmsclient_test.go`

- Unit test for `InProcessAttestationProvider` — verify it calls `attestAgent.BoundAttestationEvidence()` with the correct challenge and returns serialized protobuf bytes
- Integration test with a mock attestation agent

**File**: `launcher/container_runner_test.go` (if exists)
- Test that the KMS fetch is skipped when `KMSServerURL` is empty
- Test that the KMS fetch is attempted when `KMSServerURL` is set


### Dependency Impact

New dependency in `launcher/go.mod`:
- `github.com/Layr-Labs/eigenx-kms` — brings in transitive deps: `go-ethereum`, `solana-go`, `lestrrat-go/jwx/v3`, `cenkalti/backoff/v5`, etc.

### Resolved Decisions

| Question | Decision |
|---|---|
| **KMS signing key delivery** | Base64-encoded in GCE metadata (plain string attributes) |
| **JWE library** | Use `lestrrat-go/jwx/v3` to reduce implementation complexity |
| **Mnemonic storage** | Store on `ContainerRunner` struct (`r.mnemonic`) |
| **Error handling** | Fatal — KMS fetch failure blocks container start (required for disk encryption) |
| **Retry policy** | Exponential backoff: 500ms initial, 5s max interval, 2min total elapsed |
| **Attestation mode** | Self-verification only (bound evidence via `/env/v3`). GCA/ITA will not be supported. |
| **Import vs. re-implement** | Import `eigenx-kms/pkg/envclient` with custom in-process `AttestationProvider` |

---

## Implementation Details

### Files Changed

| File | Change |
|------|--------|
| `launcher/spec/launch_spec.go` | Added 3 metadata key constants, 3 LaunchSpec fields, parsing in `UnmarshalJSON`, censoring in `LogFriendly` |
| `launcher/kmsclient/kmsclient.go` | **New** — `InProcessAttestationProvider` and `GetMnemonicFromKMS` wrapper |
| `launcher/kmsclient/kmsclient_test.go` | **New** — Unit tests for the attestation provider and helper functions |
| `launcher/container_runner.go` | Added `mnemonic` field to `ContainerRunner`, KMS fetch call in `Run()`, converted struct literal to named fields |
| `launcher/go.mod` / `launcher/go.sum` | Added `eigenx-kms` dependency from GitHub (commit `401bde3`) |

### LaunchSpec Changes (`launcher/spec/launch_spec.go`)

Three new metadata key constants follow the existing `tee-` prefix convention:

```go
kmsServerURLKey  = "tee-kms-server-url"
kmsSigningPublicKeyKey = "tee-kms-signing-public-key"
kmsUserAPIURLKey = "tee-kms-user-api-url"
```

Corresponding struct fields on `LaunchSpec`:

```go
KMSServerURL  string // URL of the KMS server (e.g. "https://kms.eigenx.io")
KMSSigningPublicKey string // Base64-encoded KMS signing public key PEM (public, but integrity matters)
KMSUserAPIURL string // User API URL for v3 attestation upload (optional)
```

Parsed in `UnmarshalJSON` via direct map lookup (no validation — empty `KMSServerURL` means the feature is skipped).

### kmsclient Package (`launcher/kmsclient/kmsclient.go`)

**`InProcessAttestationProvider`** — Implements `envclient.AttestationProvider`. `GetAttestation` rejects empty challenges, calls `attestAgent.BoundAttestationEvidence(challenge)`, and marshals the returned `*pb.Attestation` to protobuf bytes via `proto.Marshal`. This produces the same wire format as the teeserver's `/v1/bound_evidence` endpoint.

**`GetMnemonicFromKMS`** — Convenience function that:
1. Base64-decodes the signing key from `launchSpec.KMSSigningPublicKey`.
2. Creates an `InProcessAttestationProvider` wrapping the attestation agent.
3. Passes `slog.Default()` as the logger (the launcher sets this to write to the serial console in `logging.go`).
4. Calls `envclient.NewEnvClient(...).GetEnv(ctx)` — the envclient handles RSA key generation, request building, exponential backoff retries, signature verification, and JWE decryption.
5. Unmarshals the JSON response and extracts the `"MNEMONIC"` key.
6. Zeros the decoded signing key bytes and raw env JSON bytes via `defer zeroBytes()`.

### ContainerRunner Integration (`launcher/container_runner.go`)

Added `mnemonic string` field to `ContainerRunner`. In `Run()`, after `go teeServer.Serve()` and before container task creation:

```go
if r.launchSpec.KMSServerURL != "" {
    r.logger.Info("Fetching mnemonic from KMS")
    mnemonic, err := kmsclient.GetMnemonicFromKMS(ctx, r.launchSpec, r.attestAgent)
    if err != nil {
        return fmt.Errorf("failed to fetch mnemonic from KMS: %v", err)
    }
    r.mnemonic = mnemonic
    r.logger.Info("Successfully retrieved mnemonic from KMS")
}
```

KMS fetch failure is fatal and blocks container start. The `ContainerRunner` struct literal in `NewRunner` was converted from positional to named fields to accommodate the new field.

### Safety Measures

- **Mnemonic never logged** — only success/failure messages are emitted.
- **Sensitive buffers zeroed** — decoded signing key bytes and raw env JSON are zeroed via `defer zeroBytes()` after use.
- **Empty challenge rejected** — `GetAttestation` returns an error if the challenge is nil or empty, preventing a meaningless attestation request.
- **Empty/missing MNEMONIC** treated as an error — both missing key and empty value are checked.

---

## Test Details

### Unit Tests (`launcher/kmsclient/kmsclient_test.go`)

Uses a `fakeAttestationAgent` mock (same pattern as `launcher/teeserver/tee_server_test.go`) with injectable `boundAttestationEvidenceFunc`.

| Test | What it verifies |
|------|------------------|
| `TestInProcessAttestationProvider` | Challenge bytes are passed through to `BoundAttestationEvidence` unchanged. Returned protobuf bytes can be unmarshaled back to an `Attestation` with matching fields (`AkPub`, `EventLog`, `CanonicalEventLog`, `AkCert`). |
| `TestInProcessAttestationProvider_EmptyChallenge` | Both `nil` and `[]byte{}` challenges are rejected with an error before calling the attestation agent. |
| `TestInProcessAttestationProvider_AgentError` | Errors from `BoundAttestationEvidence` (e.g. "TPM device unavailable") propagate through `GetAttestation` with wrapping. |
| `TestZeroBytes` | `zeroBytes()` overwrites all bytes in a slice to zero. |

### Build and Test Verification

Native macOS build fails because `launcher/spec/launch_spec.go` imports `containerd/v2/pkg/cap` (Linux-only build constraints). This is a pre-existing issue unrelated to the KMS changes. Use Docker to build and run tests:

From the repository root:

```
docker run --rm -v "$(pwd):/src" -v ~/go/pkg/mod:/go/pkg/mod -w /src/launcher golang:1.24 go build ./...
docker run --rm -v "$(pwd):/src" -v ~/go/pkg/mod:/go/pkg/mod -w /src/launcher golang:1.24 go vet ./...
docker run --rm -v "$(pwd):/src" -v ~/go/pkg/mod:/go/pkg/mod -w /src/launcher golang:1.24 go test -v ./kmsclient/...
```

The `-v ~/go/pkg/mod:/go/pkg/mod` flag mounts the host's Go module cache into the container, avoiding repeated dependency downloads.

### Deployment Testing (Real GCE VM)

To test the full flow end-to-end in a real Confidential VM, set the KMS metadata attributes when creating the instance:

```
gcloud compute instances create test-vm \
    --metadata \
        tee-image-reference=<workload-image>,\
        tee-kms-server-url=https://kms.eigenx.io,\
        tee-kms-signing-public-key=<base64-encoded-pem>,\
        tee-kms-user-api-url=https://api.eigenx.io
```

This requires:
- A running KMS server with the `/env/v3` endpoint
- The KMS server's signing public key (base64-encoded PEM)
- An app registered on-chain (Sepolia) with the KMS server so it can derive the mnemonic
- The VM running in a Confidential Computing environment (SEV-SNP or TDX) so the TPM attestation is valid
