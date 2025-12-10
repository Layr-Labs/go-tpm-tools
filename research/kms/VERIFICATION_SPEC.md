# CVM Attestation Verification Spec

## Overview

This spec describes verification of raw attestations from Google Confidential Space VMs. Both TDX and SEV-SNP follow the same trust model but use different hardware primitives.

## Trust Chain

```
Hardware Root (Intel/AMD) ──► Platform Root (Google GCE) ──► Workload
     │                              │                           │
     │                              │                           │
Quote signature              AK certificate              Container claims
verifies firmware            proves GCE VM               from event logs
```

## TDX Verification

### High-Level API

```go
// go-tdx-guest/rtmr.ParseCcelWithTdQuote() handles steps 1-3 in one call:
fwState, err := rtmr.ParseCcelWithTdQuote(ccelData, acpiTable, quote, opts)
// Returns: SecureBoot, GrubState, LinuxKernel, RawEvents
```

### Step 1: Quote + CCEL Verification
`ParseCcelWithTdQuote()` does:
- Verify quote signature against Intel's root CA
- Validate quote fields (ReportData, etc.)
- Parse CCEL and replay events against RTMRs
- Return `FirmwareLogState` with SecureBoot, GRUB files, kernel cmdline

### Step 2: Binding Verification
```
ReportData[0:32]  = User-provided data (e.g., SHA256 of RSA pubkey)
ReportData[32:64] = SHA256(AK_pubkey_DER)   ── binds AK to hardware
```
- Launcher: `launcher/agent/agent.go` - `GetAttestation()` adds AK hash
- Verifier: `research/verifier/verifier.go` - `verifyAKBinding()` checks it

### Step 3: Security Policy
- **Debug mode**: Reject if `TD_ATTRIBUTES.DEBUG = 1`
- **Secure Boot**: From `fwState.SecureBoot.Enabled`

### Step 4: Firmware Endorsement (MRTD)
- Fetch from `gs://gce_tcb_integrity/ovmf_x64_csm/tdx/{MRTD}.binarypb`
- Verify RSA-PSS signature against Google TCB root CA

### Step 5: TCB Version Check
- Pack `TeeTcbSvn[0:3]` as `(major << 16 | minor << 8 | microcode)`
- Check against policy minimum

### Step 6: Base Image Allowlist
- Extract **grub.cfg digest** from `fwState.RawEvents` (EV_IPL in RTMR[2])
- Check against allowlist

**Why grub.cfg digest?**
- RTMR[1] = EFI state, does NOT contain kernel/launcher
- RTMR[2] = GRUB files + container events (changes per container)
- grub.cfg contains dm-verity hash → changes when launcher changes

### Step 7: GCE Identity (manual)
- Verify AK cert chain: `server.VerifyAKCert()`
- Extract info: `server.GetGCEInstanceInfo()`

### Step 8: Container Claims
- Replay CEL against RTMR[2]: `server.ParseCosCELRTMR()`
- Extract: ImageReference, ImageDigest, Args, EnvVars

---

## SEV-SNP Verification

### High-Level APIs

```go
// Step 1: go-sev-guest handles report verification
verify.SnpAttestation(attestation, verify.DefaultOptions())
validate.SnpAttestation(attestation, validateOpts)

// Step 6-9: go-tpm-tools handles TPM quote + event log
machineState, err := server.VerifyAttestation(tpmAttestation, verifyOpts)
// Returns: MachineState with SecureBoot, GrubState, GCE info

// Container claims (separate call)
cosState, err := server.ParseCosCELPCR(cel, pcrBank)
```

### Step 1: SNP Report Verification
`verify.SnpAttestation()` does:
- Verify report signature against AMD's root CA
- Fetch and verify certificate chain

### Step 2: Binding Verification
```
ReportData[0:32]  = User-provided data (e.g., SHA256 of RSA pubkey)
ReportData[32:64] = SHA256(AK_pubkey_DER)   ── binds AK to hardware
```
- Launcher: `launcher/agent/agent.go` - `GetAttestation()` adds AK hash
- Verifier: `research/verifier/verifier.go` - `verifyAKBinding()` checks it

### Step 3: Security Policy
- **Debug mode**: Reject if `Policy.Debug = true`

### Step 4: Firmware Endorsement (MEASUREMENT)
- Fetch from `gs://gce_tcb_integrity/ovmf_x64_csm/sevsnp/{MEASUREMENT}.binarypb`
- Verify RSA-PSS signature against Google TCB root CA

### Step 5: TCB Version Check
- Use `CurrentTcb` directly (uint64)
- Check against policy minimum

### Step 6: TPM Quote + Event Log
`server.VerifyAttestation()` does:
- Verify TPM quote signature using AK
- Replay BIOS event log against PCRs
- Extract SecureBoot, GRUB state, GCE info

### Step 7: Base Image Allowlist
- Extract **PCR 9** from verified quote
- Check against allowlist

**Why PCR 9?**
- PCR 9 = GRUB-measured files (kernel, initrd)
- Equivalent to grub.cfg digest for TDX

### Step 8: Container Claims
- Replay CEL against PCR 13: `server.ParseCosCELPCR()`
- Extract: ImageReference, ImageDigest, Args, EnvVars

---

## Measurement Summary

| What | TDX | SEV-SNP |
|------|-----|---------|
| **Firmware** | MRTD (48 bytes) | MEASUREMENT (48 bytes) |
| **Firmware validation** | Google endorsement | Google endorsement |
| **Base image** | grub.cfg digest from CCEL | PCR 9 from TPM quote |
| **Base image validation** | On-chain allowlist | On-chain allowlist |
| **Container** | CEL → RTMR[2] | CEL → PCR 13 |
| **TCB** | TeeTcbSvn[0:3] packed | CurrentTcb |

---

## On-Chain Contract

```solidity
// CVM enum: 0=TDX, 1=SEV_SNP

// TCB minimum (rarely used - for critical vulns)
checkTcb(CVM cvm, uint64 tcb) → bool

// Base image allowlist
isImageAllowed(CVM cvm, bytes measurement) → bool
// TDX: grub.cfg digest (48 bytes SHA384)
// SEV-SNP: PCR 9 (32 bytes SHA256)

// Support levels: NONE, EXPERIMENTAL, USABLE, STABLE, LATEST
```

---

## Dependencies

| Library | Purpose |
|---------|---------|
| `go-tdx-guest` | TDX quote parsing and Intel CA verification |
| `go-sev-guest` | SEV-SNP report parsing and AMD CA verification |
| `go-tpm-tools` | TPM quote verification, CEL parsing, AK cert validation |
| `go-eventlog` | CCEL/TCG event log parsing |
