# CVM Attestation Verification Spec

## Overview

This spec describes verification of raw attestations from Google Confidential Space VMs. Both TDX and SEV-SNP follow the same trust model and verification flow, using `server.VerifyAttestation()` for TPM-based validation.

## Trust Chain

```
Hardware Root (Intel/AMD) ──► Platform Root (Google GCE) ──► Workload
     │                              │                           │
     │                              │                           │
Quote signature              AK certificate              Container claims
verifies firmware            proves GCE VM               from event logs
```

## Unified Verification Flow

Both TDX and SEV-SNP use the same verification approach via `server.VerifyAttestation()`:

```go
// Unified verification for both platforms
machineState, err := server.VerifyAttestation(&attestation, server.VerifyOpts{
    Nonce:             tpmNonce,
    TrustedRootCerts:  append(server.GceEKRoots, server.GcpCASEKRoots...),
    IntermediateCerts: server.GcpCASEKIntermediates,
    Loader:            server.GRUB,
})

// Returns: MachineState with:
// - SecureBoot state
// - GCE instance info
// - Container claims (COS state)
// - TdxAttestation or SevSnpAttestation (TEE quote)
// PCR values extracted separately from attestation.Quotes
```

### Step 1: Parse Attestation
- Unmarshal `pb.Attestation` protobuf
- Detect platform: `TdxAttestation` or `SevSnpAttestation`

### Step 2: ReportData Verification
```
ReportData[0:32]  = User-provided data (e.g., SHA256 of RSA pubkey)
ReportData[32:64] = SHA256(AK_pubkey_DER)   ── binds AK to hardware
```
- Launcher: `launcher/agent/agent.go` - `GetAttestation()` adds AK hash
- Verifier: `research/verifier/verifier.go` - `verifyAKBinding()` checks it

### Step 3: TPM/AK Validation
`server.VerifyAttestation()` handles:
- TPM quote signature verification using AK
- Event log replay against PCRs
- AK certificate chain verification (Google GCE EK root)
- Extract SecureBoot, GRUB files, kernel cmdline, GCE info

### Step 4: Security Policy
- **TDX**: Reject if `TD_ATTRIBUTES.DEBUG = 1`
- **SEV-SNP**: Reject if `Policy.Debug = true`
- **Secure Boot**: From `machineState.GetSecureBoot().GetEnabled()`

### Step 5: TEE Quote Verification
- **TDX**: Quote signature verified against Intel's root CA (via attestation)
- **SEV-SNP**: Report signature verified via `verify.SnpAttestation()` against AMD's root CA

### Step 6: Firmware Endorsement
- **TDX**: Fetch `gs://gce_tcb_integrity/ovmf_x64_csm/tdx/{MRTD}.binarypb`
- **SEV-SNP**: Fetch `gs://gce_tcb_integrity/ovmf_x64_csm/sevsnp/{MEASUREMENT}.binarypb`
- Verify RSA-PSS signature against Google TCB root CA

### Step 7: TCB Version Check
- **TDX**: Pack `TeeTcbSvn[0:3]` as `(major << 16 | minor << 8 | microcode)`
- **SEV-SNP**: Use `CurrentTcb` directly (uint64)
- Check against on-chain policy minimum

### Step 8: Base Image Allowlist
- Extract **PCR 4**, **PCR 8**, and **PCR 9** from verified TPM quote
- **Platform-agnostic**: Same values for TDX and SEV-SNP with identical images
- Check against on-chain allowlist: `isImageAllowed(pcr4, pcr8, pcr9)`

| PCR | What it measures | Used for |
|-----|------------------|----------|
| **PCR 4** | EFI boot applications (shim + GRUB) | Boot chain identity |
| **PCR 8** | Kernel command line (includes dm-verity root hash) | Launcher identity |
| **PCR 9** | Files read by GRUB (kernel, initramfs) | Base image identity |

### Step 9: Container Claims
- From `machineState.GetCos().GetContainer()`
- Extract: ImageReference, ImageDigest, Args, EnvVars

---

## Platform-Specific Details

### TDX
- TEE quote: `attestation.GetTdxAttestation()`
- Measurements: MRTD, RTMRs from `TdQuoteBody`
- TCB: `TeeTcbSvn` (16 bytes, pack first 3 for comparison)

### SEV-SNP
- TEE report: `attestation.GetSevSnpAttestation()`
- Measurements: MEASUREMENT, HostData from `Report`
- TCB: `CurrentTcb` (uint64)
- Additional verification: `verify.SnpAttestation()` for AMD signature

---

## Measurement Summary

| What | TDX | SEV-SNP |
|------|-----|---------|
| **Firmware** | MRTD (48 bytes) | MEASUREMENT (48 bytes) |
| **Firmware validation** | Google endorsement | Google endorsement |
| **Base image** | PCR 4 + PCR 8 + PCR 9 from vTPM | PCR 4 + PCR 8 + PCR 9 from vTPM |
| **Base image validation** | On-chain allowlist | On-chain allowlist |
| **Container** | CEL → machineState.Cos | CEL → machineState.Cos |
| **TCB** | TeeTcbSvn[0:3] packed | CurrentTcb |

**Key insight:** PCR 4, PCR 8, and PCR 9 are **platform-agnostic** - the vTPM produces identical values for TDX and SEV-SNP when running the same image. This simplifies allowlist management.

---

## On-Chain Contract

```solidity
// CVM enum only used for TCB (different formats per platform)
enum CVM { TDX, SEV_SNP }

// TCB minimum (rarely used - for critical vulns)
checkTcb(CVM cvm, uint64 tcb) → bool

// Base image allowlist (platform-agnostic - single entry per image)
isImageAllowed(bytes32 pcr4, bytes32 pcr8, bytes32 pcr9) → bool
// PCR 4 = boot chain identity (shim + GRUB)
// PCR 8 = launcher identity (kernel cmdline with dm-verity hash)
// PCR 9 = base image identity (kernel + initramfs)

// Support levels: NONE, EXPERIMENTAL, USABLE, STABLE, LATEST
```

---

## Dependencies

| Library | Purpose |
|---------|---------|
| `go-tdx-guest` | TDX quote parsing |
| `go-sev-guest` | SEV-SNP report parsing and AMD CA verification |
| `go-tpm-tools` | TPM quote verification, CEL parsing, AK cert validation, event log parsing |
