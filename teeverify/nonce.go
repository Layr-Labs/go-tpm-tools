package teeverify

import (
	"crypto/sha256"
	"crypto/sha512"
)

// WorkloadAttestationLabel is the domain separator used in nonce computation.
const WorkloadAttestationLabel = "WORKLOAD_ATTESTATION"

// ComputeTPMNonce derives a 32-byte nonce for TPM quotes:
//
//	SHA256(label || SHA256(challenge) || SHA256(extraData)?)
//
// If extraData is nil or empty, the SHA256(extraData) term is omitted.
func ComputeTPMNonce(challenge, extraData []byte) []byte {
	h := sha256.New()
	challengeDigest := sha256.Sum256(challenge)
	h.Write([]byte(WorkloadAttestationLabel))
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
