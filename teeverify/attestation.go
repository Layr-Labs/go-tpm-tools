// Package teeverify provides TEE attestation verification for TDX and SEV-SNP.
// This package is for third parties who need to verify raw TEE attestations
// without using external services (like Google Cloud Attestation or Intel Trust Authority).
package teeverify

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	attestpb "github.com/Layr-Labs/go-tpm-tools/proto/attest"
	"github.com/Layr-Labs/go-tpm-tools/server"
	sevverify "github.com/google/go-sev-guest/verify"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

const (
	reportDataBindingSize  = 32 // SHA256(nonce + AK_pub_DER)
	reportDataUserDataSize = 32 // Optional user data
	reportDataSize         = reportDataBindingSize + reportDataUserDataSize
)

// VerifyAttestation cryptographically verifies an attestation.
// This verifies:
// - TEE quote signature (Intel TDX or AMD SEV-SNP root of trust)
// - TPM quote signature and AK certificate chain
// - Binding: ReportData[0:32] == SHA256(nonce + AK_public_key_DER)
//
// The binding hash proves that the TEE and TPM are from the same VM (via AK public key).
// The nonce must match the value used during attestation creation.
//
// This does NOT make policy decisions (debug mode, TCB versions, allowlists).
// Policy checks should be performed by the caller after extracting claims.
func VerifyAttestation(attestationBytes []byte, nonce []byte) (*VerifiedAttestation, error) {
	var attestation attestpb.Attestation
	if err := proto.Unmarshal(attestationBytes, &attestation); err != nil {
		return nil, fmt.Errorf("failed to parse attestation proto: %w", err)
	}

	platform := detectPlatform(&attestation)
	if platform == PlatformUnknown {
		return nil, fmt.Errorf("no TEE attestation found")
	}

	userData, err := verifyBinding(&attestation, nonce, platform)
	if err != nil {
		return nil, err
	}

	switch platform {
	case PlatformTDX:
		if err := verifyTDXSignature(&attestation); err != nil {
			return nil, fmt.Errorf("TDX verification failed: %w", err)
		}
	case PlatformSevSnp:
		if err := verifySevSnpSignature(&attestation); err != nil {
			return nil, fmt.Errorf("SEV-SNP verification failed: %w", err)
		}
	}

	// Extract TPM nonce from quote's extraData
	quotes := attestation.GetQuotes()
	if len(quotes) == 0 {
		return nil, fmt.Errorf("no TPM quotes in attestation")
	}
	quoteInfo, err := tpm2.DecodeAttestationData(quotes[0].GetQuote())
	if err != nil {
		return nil, fmt.Errorf("failed to decode TPM quote: %w", err)
	}
	tpmNonce := quoteInfo.ExtraData

	// Verify TPM nonce matches the provided nonce
	if !bytes.Equal(tpmNonce, nonce) {
		return nil, fmt.Errorf("TPM nonce mismatch: quote contains different nonce than provided")
	}

	// Create a new slice to avoid mutating the original slices
	allRoots := make([]*x509.Certificate, 0, len(server.GceEKRoots)+len(server.GcpCASEKRoots))
	allRoots = append(allRoots, server.GceEKRoots...)
	allRoots = append(allRoots, server.GcpCASEKRoots...)
	machineState, err := server.VerifyAttestation(&attestation, server.VerifyOpts{
		Nonce:             tpmNonce,
		TrustedRootCerts:  allRoots,
		IntermediateCerts: server.GcpCASEKIntermediates,
		Loader:            server.GRUB,
	})
	if err != nil {
		return nil, fmt.Errorf("TPM attestation verification failed: %w", err)
	}

	return &VerifiedAttestation{
		Platform:     platform,
		UserData:     userData,
		attestation:  &attestation,
		machineState: machineState,
	}, nil
}

func detectPlatform(attestation *attestpb.Attestation) Platform {
	if attestation.GetTdxAttestation() != nil {
		return PlatformTDX
	}
	if attestation.GetSevSnpAttestation() != nil {
		return PlatformSevSnp
	}
	return PlatformUnknown
}

func getReportData(attestation *attestpb.Attestation, platform Platform) []byte {
	switch platform {
	case PlatformTDX:
		return attestation.GetTdxAttestation().GetTdQuoteBody().GetReportData()
	case PlatformSevSnp:
		return attestation.GetSevSnpAttestation().GetReport().GetReportData()
	}
	return nil
}

// verifyBinding verifies ReportData[0:32] == SHA256(nonce + AK_public_key_DER).
// This proves both freshness (via nonce) and binds the TEE hardware quote to the TPM's AK,
// proving that the TPM claims (event log, PCRs) came from the same VM as the TEE attestation.
// Returns the user data from ReportData[32:64].
func verifyBinding(attestation *attestpb.Attestation, nonce []byte, platform Platform) ([]byte, error) {
	reportData := getReportData(attestation, platform)

	if len(reportData) < reportDataSize {
		return nil, fmt.Errorf("report data too short: got %d bytes, need at least %d", len(reportData), reportDataSize)
	}

	akCertDER := attestation.GetAkCert()
	if len(akCertDER) == 0 {
		return nil, fmt.Errorf("no AK certificate in attestation")
	}

	akCert, err := x509.ParseCertificate(akCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AK certificate: %w", err)
	}

	// Verify AK certificate is within its validity window
	now := time.Now()
	if now.Before(akCert.NotBefore) {
		return nil, fmt.Errorf("AK certificate not yet valid (notBefore: %v)", akCert.NotBefore)
	}
	if now.After(akCert.NotAfter) {
		return nil, fmt.Errorf("AK certificate expired (notAfter: %v)", akCert.NotAfter)
	}

	akPubDER, err := x509.MarshalPKIXPublicKey(akCert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AK public key: %w", err)
	}

	// Verify consistency: if attestation contains ak_pub field, it must match the certificate
	// Note: ak_pub is in TPM2B_PUBLIC format (TPMT_PUBLIC), not PKIX DER
	if akPub := attestation.GetAkPub(); len(akPub) > 0 {
		akPubArea, err := tpm2.DecodePublic(akPub)
		if err != nil {
			return nil, fmt.Errorf("failed to decode ak_pub: %w", err)
		}
		akPubFromTPM, err := akPubArea.Key()
		if err != nil {
			return nil, fmt.Errorf("failed to get public key from ak_pub: %w", err)
		}
		if !pubKeysEqual(akCert.PublicKey, akPubFromTPM) {
			return nil, fmt.Errorf("AK certificate public key does not match attestation ak_pub field")
		}
	}

	// Compute expected binding hash: SHA256(nonce + AK_public_key_DER)
	expectedHash := sha256.Sum256(append(nonce, akPubDER...))
	if !bytes.Equal(reportData[:reportDataBindingSize], expectedHash[:]) {
		return nil, fmt.Errorf("binding mismatch: ReportData[0:32] does not match SHA256(nonce + AK_public_key)")
	}

	// Extract user data from ReportData[32:64]
	userData := make([]byte, reportDataUserDataSize)
	copy(userData, reportData[reportDataBindingSize:reportDataSize])

	return userData, nil
}

func verifyTDXSignature(attestation *attestpb.Attestation) error {
	quote := attestation.GetTdxAttestation()
	opts := &tdxverify.Options{
		CheckRevocations: true, // Check Intel CRLs for revoked certificates
		GetCollateral:    true, // Fetch TCB Info from Intel PCS to verify TCB status
		Getter:           tdxGetter,
		Now:              time.Now(),
	}
	if err := tdxverify.TdxQuote(quote, opts); err != nil {
		return fmt.Errorf("TDX quote signature verification failed: %w", err)
	}
	return nil
}

func verifySevSnpSignature(attestation *attestpb.Attestation) error {
	snpAttestation := attestation.GetSevSnpAttestation()
	opts := &sevverify.Options{
		CheckRevocations: true, // Check AMD CRLs for revoked VCEK/ASK certificates
		Getter:           sevsnpGetter,
		Now:              time.Now(),
	}
	if err := sevverify.SnpAttestation(snpAttestation, opts); err != nil {
		return fmt.Errorf("SEV-SNP report signature verification failed: %w", err)
	}
	return nil
}

// pubKeysEqual returns whether two public keys are equal.
func pubKeysEqual(k1, k2 crypto.PublicKey) bool {
	type publicKey interface {
		Equal(crypto.PublicKey) bool
	}
	if key, ok := k1.(publicKey); ok {
		return key.Equal(k2)
	}
	return false
}
