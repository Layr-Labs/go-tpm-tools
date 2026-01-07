# Roadmap: Custom Base Image Support

## Overview

Modifying the Confidential Space image breaks compatibility with Google's hosted attestation, which validates against their reference measurement database. To run custom images, we need to:

1. Verify attestations directly (TDX/SEV-SNP quotes, TPM quotes, certificate chains)
2. Maintain our own reference measurement registry (smart contract allowlist)
3. Build images verifiably (link source code to final PCR values)

We still validate firmware against Google's golden measurements to ensure it's a legitimate CVM running on Google Cloud.

---

## Release 1: Parity with Stock Confidential Space

**Goal**: Custom base image support with equivalent security guarantees.

| Component | Purpose |
|-----------|---------|
| Direct Attestation Verification | Verify TDX/SEV-SNP quotes, TPM quotes, and AK certificate chains ourselves |
| Reference Measurement Registry | Smart contract allowlist for valid image PCRs (platform-agnostic) |
| Firmware Validation | Check measurements against Google's signed endorsements |
| Verifiable Build Pipeline | Audit trail from source to PCR values |

**Result**: A custom image that passes attestation with the same trust guarantees as stock Confidential Space - just using our registry instead of Google's.

---

## Future Releases

| Feature | Description |
|---------|-------------|
| Docker Compose | Multi-container workload support |
