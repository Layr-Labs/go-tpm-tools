# rpverifier

Relying Party Verifier for GCP Confidential Space attestations.

## What is this?

This package verifies TEE attestations from workloads running in [GCP Confidential Space](https://cloud.google.com/confidential-computing/confidential-space/docs). It's for **relying parties** (servers that receive and verify attestations), not for code running inside the TEE.

## What it verifies

`VerifyAttestation()` performs cryptographic verification:
- TEE quote signature (Intel TDX or AMD SEV-SNP root of trust)
- TPM quote signature and AK certificate chain
- AK binding (proves TPM and TEE quote came from the same VM)
- Report data matches expected nonce

## What you handle (policy)

After verification, you decide whether to trust the workload:
- Debug mode (reject production secrets to debug VMs)
- TCB versions (minimum firmware versions)
- PCR values (base image allowlist)
- MRTD/Measurement (firmware endorsements)

## Usage

```go
// 1. Verify attestation (cryptographic)
verified, err := rpverifier.VerifyAttestation(attestationBytes, expectedNonce)
if err != nil {
    return err // signature invalid, AK binding failed, etc.
}

// 2. Extract claims
claims, err := verified.ExtractClaims(rpverifier.ExtractOptions{
    PCRIndices: []uint32{4, 8, 9},
})
if err != nil {
    return err
}

// 3. Apply your policy
if claims.TDX != nil && claims.TDX.Attributes.Debug {
    return errors.New("debug mode not allowed")
}
// ... check PCRs, TCB, etc.
```

## Platforms

- Intel TDX
- AMD SEV-SNP
