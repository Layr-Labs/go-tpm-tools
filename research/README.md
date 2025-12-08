# Custom Confidential Space Images

## Problem

Out-of-the-box, Google Confidential Space (GCS) simplifies attestation by abstracting the complexity of multiple CVMs (e.g., TDX, SEV-SNP), acting as the verifier, and issuing a standard OIDC token. However, this convenience comes at the cost of flexibility. We are currently blocked on the Google roadmap for features like instance-level rate limiting, Docker Compose, and persistent disk encryption.

To obtain the necessary flexibility, we must modify the base image (Launcher + Container-Optimized OS). However, modifying the base image breaks compatibility with hosted attestation services (Google Cloud Attestation and Intel Trust Authority) because they validate against Google's Reference Integrity Measurements (RIM).

Attempting to use a custom image with GCA results in validation failure:
```
googleapi: Error 400: unable to validate with image RIMS: failed to get golden values:
kernel command line "..." is not in the golden values
```

Similarly, Intel Trust Authority (ITA) fails because its "Confidential Space Adapter" enforces a strict policy against Google's RIMs. We can use a custom ITA policy to allowlist our measurements, but this bypasses the adapter's parsing logic, meaning the resulting token lacks the rich container claims (args, env vars) found in standard Confidential Space tokens:
```
{"error":"claims policy apply failed ... GCPCS policy failed to meet requirements"}
```

## Proposed Solution

The proposed architecture consists of three parts:

1.  **Custom Base Images:** We customize the Confidential Space stack - modifying both the Launcher and the underlying Container-Optimized OS (COS) - while continuing to pull in upstream security patches and updates.
2.  **Self-Managed Allowlist:** We maintain a smart contract of valid measurements for these images.
3.  **Direct Verification:** The KMS (Relying Party) verifies the workload directly using **Raw TDX Attestation**. The verification logic should be published as open-source libraries (Go initially) that any relying party can consume.

Instead of requesting a signed JWT from Google, the code running in the user workload queries a `/v1/raw-attestation` endpoint to retrieve the raw TDX quote (hardware proof), Canonical Event Log (container measurements), CCEL (firmware event log), and AK certificates (platform identity). The workload then sends this evidence to the KMS, which performs verification before releasing any secrets:

1. Verify TDX quote signature against Intel CA.
2. Verify ReportData bindings (RSA key hash, AK public key hash).
3. Verify AK certificate chain against Google GCE EK root CA.
4. Replay event logs to extract platform state and container claims.
5. Verify platform meets security requirements (production mode, Secure Boot, etc.).
6. Verify firmware (MRTD) and OS image (RTMR1) against on-chain allowlist.
7. Verify GCE project against policy and container digest against on-chain release registry.

### Measurement Validation

Each TDX measurement register is validated differently:

| Register | What it measures | Validation |
|----------|------------------|------------|
| **MRTD** | Firmware binary (before boot) | On-chain allowlist (sync from Google's endorsed hashes every 2-4 weeks) |
| **RTMR0** | Firmware config (during boot) | Replay CCEL → verify firmware config |
| **RTMR1** | OS/kernel (our base image) | On-chain allowlist with support level |
| **RTMR2** | Container (args, env, image) | Replay CEL → validate against on-chain release |

### Parity with Managed Attestation

By verifying the raw attestation evidence directly, we rely on the same cryptographic roots of trust as the managed services:

- **Hardware Root of Trust:** The **TDX Quote** is signed by Intel's root CA, proving the integrity of the hardware and the base image measurements (MRTD, RTMRs).
- **Platform Root of Trust:** The **AK Certificate** is signed by Google's GCE EK root CA, proving the instance is a genuine GCE VM and providing claims like Project ID, Zone, and Instance ID.
- **Binding:** The AK public key is cryptographically bound to the TDX quote (via ReportData), ensuring the GCE claims and the Container claims (reconstructed from the Event Log) belong to the same physical entity.

This allows the Relying Party to validate the same hardware, platform, and workload identity signals required for policy enforcement.

### Runtime Attestations

Since we verify raw quotes directly rather than relying on hosted attestation services, we are no longer bound by Google or Intel Trust Authority rate limits. This enables runtime attestations - verifying quotes on-demand during operation, not just at startup.

## Responsibility Shift

This approach fundamentally changes the trust model. Previously, Google determined trustworthiness via their RIM database. Now, **we** determine trustworthiness via our allowlist.

We gain full control over the software stack but inherit additional maintenance responsibilities:
- **Build & Patch:** We must build and patch the base image rather than relying on Google updates (although we can incorporate patches as they appear in the upstream codebase).
- **Allowlist Management:** We must maintain the database of valid image measurements.
- **Verification Logic:** Instead of simply checking a Google JWT signature, we must implement and maintain the full TDX verification protocol (checking Intel/Google root CAs, replaying event logs, etc).

## Demo

The following demo implements end-to-end verification where a KMS verifies raw attestations against an on-chain allowlist.

```mermaid
sequenceDiagram
    participant W as Workload
    participant L as Launcher
    participant K as KMS
    participant B as Blockchain

    W->>L: Request raw attestation
    L-->>W: Quote + event logs + AK cert
    W->>K: Post attestation + RSA pubkey

    Note over K: Verify signatures & bindings
    Note over K: Replay event logs → extract claims
    Note over K: Verify platform security requirements

    K->>B: Check MRTD, RTMR1, container digest
    B-->>K: allowed

    K-->>W: Return encrypted secret
```

### Running the Demo

Requires the `data-axiom-440223-j1` GCP project.

#### Quick Start

Use the pre-built custom image `confidential-space-debug-cavan-test-image-1764789757` which is already registered in the deployed allowlist.

```bash
# Setup configuration
cp research/config.env.example research/config.env

# Edit config.env to set DOCKER_REPO to a Docker repository you control
# (e.g., docker.io/yourusername)

# Run the demo
./research/scripts/run.sh
```

#### Building Your Own Image

If you modify the source code to build your own custom image (different from the provided one), you must deploy your own allowlist contract and register the new measurements.

```bash
# Deploy contract
export PRIVATE_KEY="0x..."
./research/scripts/setup.sh deploy --rpc-url https://sepolia.infura.io/v3/YOUR_KEY

# Sync endorsed MRTDs from Google's firmware bucket
./research/scripts/setup.sh sync-mrtd

# Add your custom image measurement
./research/scripts/setup.sh add-image --rtmr1 0x... --level LATEST

# Run the demo
./research/scripts/run.sh
```

### Proof of Concept Implementation

These files are a rough demonstration to illustrate the architecture:

- `launcher/agent/agent.go`: `GetRawAttestation()` implementation.
- `research/kms/verifier.go`: Verification logic (handling Intel and Google root CAs).
- `research/contracts/src/BaseImageAllowlist.sol`: Smart contract replacing the RIM database.

### Building Custom Images

We can modify the Launcher code directly. For deeper OS-level customizations, we use Google's [COS Customizer](https://cos.googlesource.com/cos/tools). This tool simplifies tasks like installing GPU drivers, sealing the OEM partition (`dm-verity`), and disabling auto-updates to ensure measurement stability.

## Future: SEV-SNP Support

This approach could be extended to support AMD SEV-SNP for smaller machine types. However, this would require more work than switching platforms while using the out-of-the-box Confidential Space image.
