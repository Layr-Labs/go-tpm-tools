# teeverify

Verifies TEE attestations from Confidential Space workloads. For third parties (KMS, services, CLI tools) that need to verify attestations.

## What it verifies

- TEE quote signature (Intel TDX or AMD SEV-SNP)
- TPM quote signature and AK certificate chain
- Nonce binding (ReportData[0:32])
- AK binding (ReportData[32:64] proves TEE and TPM are from same VM)

## What you must verify (policy)

After cryptographic verification, apply your own policy:
- Debug mode (reject debug VMs for production secrets)
- TCB versions (minimum firmware)
- PCR values (image allowlist)
- MRTD/Measurement (firmware endorsements)

## Usage

```go
// Verify attestation received from the TEE workload
verified, err := teeverify.VerifyAttestation(attestationBytes, nonce)
if err != nil {
    return err
}

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
