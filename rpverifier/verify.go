// Package rpverifier provides TEE attestation verification for TDX and SEV-SNP.
// This package is for relying parties who need to verify raw TEE attestations
// without using external services (like Google Cloud Attestation or Intel Trust Authority).
package rpverifier

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	sevverify "github.com/google/go-sev-guest/verify"
	tdxverify "github.com/google/go-tdx-guest/verify"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// VerifyAttestation cryptographically verifies an attestation.
// This verifies:
// - TEE quote signature (Intel TDX or AMD SEV-SNP root of trust)
// - TPM quote signature and AK certificate chain
// - Nonce: ReportData[0:32] == nonce parameter
// - AK binding: ReportData[32:64] == SHA256(AK public key)
//
// This does NOT make policy decisions (debug mode, TCB versions, allowlists).
// Policy checks should be performed by the caller after extracting claims.
func VerifyAttestation(attestationBytes []byte, nonce [32]byte) (*VerifiedAttestation, error) {
	var attestation attestpb.Attestation
	if err := proto.Unmarshal(attestationBytes, &attestation); err != nil {
		return nil, fmt.Errorf("failed to parse attestation proto: %w", err)
	}

	platform := detectPlatform(&attestation)
	if platform == PlatformUnknown {
		return nil, fmt.Errorf("no TEE attestation found")
	}

	if err := verifyReportData(&attestation, nonce, platform); err != nil {
		return nil, err
	}

	if err := verifyAKBinding(&attestation, platform); err != nil {
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
	var tpmNonce []byte
	if quotes := attestation.GetQuotes(); len(quotes) > 0 {
		quoteInfo, err := tpm2.DecodeAttestationData(quotes[0].GetQuote())
		if err == nil {
			tpmNonce = quoteInfo.ExtraData
		}
	}

	// Use server.VerifyAttestation() for TPM/AK validation
	allRoots := append(server.GceEKRoots, server.GcpCASEKRoots...)
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

func verifyReportData(attestation *attestpb.Attestation, nonce [32]byte, platform Platform) error {
	reportData := getReportData(attestation, platform)
	if len(reportData) < 32 || !bytes.Equal(reportData[:32], nonce[:]) {
		return fmt.Errorf("nonce mismatch in TEE ReportData[0:32]")
	}
	return nil
}

// verifyAKBinding verifies that ReportData[32:64] == SHA256(AK_public_key_DER).
// This binds the TEE hardware quote to the TPM's AK, proving that the TPM claims
// (event log, PCRs) came from the same VM as the TEE attestation.
func verifyAKBinding(attestation *attestpb.Attestation, platform Platform) error {
	reportData := getReportData(attestation, platform)

	if len(reportData) < 64 {
		return fmt.Errorf("report data too short for AK binding verification")
	}

	akCertDER := attestation.GetAkCert()
	if len(akCertDER) == 0 {
		return fmt.Errorf("no AK certificate in attestation")
	}

	akCert, err := x509.ParseCertificate(akCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse AK certificate: %w", err)
	}

	akPubDER, err := x509.MarshalPKIXPublicKey(akCert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal AK public key: %w", err)
	}

	expectedHash := sha256.Sum256(akPubDER)
	if !bytes.Equal(reportData[32:64], expectedHash[:]) {
		return fmt.Errorf("AK binding mismatch: ReportData[32:64] does not match SHA256(AK_public_key)")
	}

	return nil
}

func verifyTDXSignature(attestation *attestpb.Attestation) error {
	quote := attestation.GetTdxAttestation()
	if err := tdxverify.TdxQuote(quote, tdxverify.DefaultOptions()); err != nil {
		return fmt.Errorf("TDX quote signature verification failed: %w", err)
	}
	return nil
}

func verifySevSnpSignature(attestation *attestpb.Attestation) error {
	snpAttestation := attestation.GetSevSnpAttestation()
	if err := sevverify.SnpAttestation(snpAttestation, sevverify.DefaultOptions()); err != nil {
		return fmt.Errorf("SEV-SNP report signature verification failed: %w", err)
	}
	return nil
}
