# teeverify

Verifies TEE attestations from Confidential Space workloads. For third parties (KMS, services, CLI tools) that need to verify attestations.

## What it verifies

- TEE quote signature (Intel TDX or AMD SEV-SNP)
- TPM quote signature and AK certificate chain
- Binding: ReportData == ComputeBoundNonce(challenge, SHA256(AK_pub_DER), extraData), proving freshness and TEE/TPM from same VM
- TPM quote ExtraData == ComputeTPMNonce(challenge, extraData)

## What you must verify (policy)

After cryptographic verification, apply your own policy:
- Debug mode (reject debug VMs for production secrets)
- TCB versions (minimum firmware)
- PCR values (image allowlist)
- MRTD/Measurement (firmware endorsements)

## Usage

```go
// Parse and detect platform.
att, err := teeverify.ParseAttestation(attestationBytes)

// Verify TPM layer (AK cert chain, PCR quotes, event log, nonce).
tpmResult, err := att.VerifyTPM(challenge, extraData)

// Verify TEE layer (quote signature, binding to TPM AK).
// Not available for Shielded VM.
teeResult, err := att.VerifyBoundTEE(challenge, extraData)

// Extract claims from each layer.
tpmClaims, err := tpmResult.ExtractTPMClaims(teeverify.ExtractOptions{
    PCRIndices: []uint32{4, 8, 9},
})
teeClaims, err := teeResult.ExtractTEEClaims()
container, err := att.ExtractContainerClaims()

// Apply policy.
if teeClaims.TDX != nil && teeClaims.TDX.Attributes.Debug {
    return errors.New("debug mode not allowed")
}
```

## Supported Platforms

- Intel TDX
- AMD SEV-SNP
- GCP Shielded VM (TPM-only, no TEE hardware attestation)
