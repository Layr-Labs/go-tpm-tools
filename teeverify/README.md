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
// Verify attestation received from the TEE workload.
// challenge is the same value passed when requesting the attestation.
// extraData is the optional application-specific data bound into both nonces.
verified, err := teeverify.VerifyBoundAttestation(attestationBytes, challenge, extraData)
if err != nil {
    return err
}

// Access extra data bound into the attestation
extra := verified.ExtraData

// Extract claims
claims, err := verified.ExtractClaims(teeverify.ExtractOptions{
    PCRIndices: []uint32{4, 8, 9},
})
if err != nil {
    return err
}

// Apply policy
if claims.TDX != nil && claims.TDX.Attributes.Debug {
    return errors.New("debug mode not allowed")
}
```

## Supported Platforms

- Intel TDX
- AMD SEV-SNP
- GCP Shielded VM (TPM-only, no TEE hardware attestation)
