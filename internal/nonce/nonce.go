// Package nonce provides utilities for computing TPM and TEE nonces used in attestation.
package nonce

import (
	"crypto/sha256"
	"crypto/sha512"
)

// WorkloadAttestationLabel is the domain separator used in nonce computation.
const WorkloadAttestationLabel = "WORKLOAD_ATTESTATION"

// Platform tag constants for anti-downgrade protection in the TPM nonce.
const (
	PlatformTagIntelTDX      = "INTEL_TDX"
	PlatformTagAMDSevSnp     = "AMD_SEV_SNP"
	PlatformTagGCPShieldedVM = "GCP_SHIELDED_VM"
)

// ComputeTPMNonce derives a 32-byte nonce for TPM quotes:
//
//	SHA256(label || platformTag || SHA256(challenge) || SHA256(extraData)?)
//
// The platformTag commits the detected platform into the TPM nonce, preventing
// anti-downgrade attacks where a TEE quote is stripped to appear as Shielded VM.
// If extraData is nil or empty, the SHA256(extraData) term is omitted.
func ComputeTPMNonce(challenge []byte, platformTag string, extraData []byte) []byte {
	h := sha256.New()
	h.Write([]byte(WorkloadAttestationLabel))
	h.Write([]byte(platformTag))
	challengeDigest := sha256.Sum256(challenge)
	h.Write(challengeDigest[:])
	if len(extraData) > 0 {
		extraDigest := sha256.Sum256(extraData)
		h.Write(extraDigest[:])
	}
	return h.Sum(nil)
}

// ComputeBoundNonce derives a 64-byte nonce for TEE ReportData:
//
//	SHA512(label || SHA512(challenge) || SHA512(akPubDER) || SHA512(extraData)?)
//
// If extraData is nil or empty, the SHA512(extraData) term is omitted.
// akPubDER is the AK public key in PKIX DER format.
func ComputeBoundNonce(challenge, akPubDER, extraData []byte) []byte {
	h := sha512.New()
	challengeDigest := sha512.Sum512(challenge)
	akDigest := sha512.Sum512(akPubDER)
	h.Write([]byte(WorkloadAttestationLabel))
	h.Write(challengeDigest[:])
	h.Write(akDigest[:])
	if len(extraData) > 0 {
		extraDigest := sha512.Sum512(extraData)
		h.Write(extraDigest[:])
	}
	return h.Sum(nil)
}
