// Package teeverify provides TEE attestation verification for TDX and SEV-SNP.
// This package is for third parties who need to verify raw TEE attestations
// without using external services (like Google Cloud Attestation or Intel Trust Authority).
package teeverify

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/Layr-Labs/go-tpm-tools/internal/nonce"
	attestpb "github.com/Layr-Labs/go-tpm-tools/proto/attest"
	tpmpb "github.com/Layr-Labs/go-tpm-tools/proto/tpm"
	"github.com/Layr-Labs/go-tpm-tools/server"
	"github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	sevverify "github.com/google/go-sev-guest/verify"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// teeReportDataSize is the size of the ReportData field in both TDX and SEV-SNP hardware specs.
const teeReportDataSize = 64

// ParseAttestation deserializes an attestation proto and detects the platform.
// Use VerifyTPM and VerifyBoundTEE on the returned Attestation to verify independently.
func ParseAttestation(attestationBytes []byte) (*Attestation, error) {
	var attestation attestpb.Attestation
	if err := proto.Unmarshal(attestationBytes, &attestation); err != nil {
		return nil, fmt.Errorf("failed to parse attestation proto: %w", err)
	}

	platform := detectPlatform(&attestation)
	if platform == PlatformUnknown {
		return nil, fmt.Errorf("unknown platform: no TEE or Shielded VM attestation found")
	}

	return &Attestation{
		platform:    platform,
		attestation: &attestation,
	}, nil
}

// VerifyTPM verifies the TPM layer: AK cert chain, PCR quotes, event log, and
// TPM nonce (which includes the platform tag for anti-downgrade protection).
// Works for all platforms (TDX, SEV-SNP, Shielded VM).
func (a *Attestation) VerifyTPM(challenge, extraData []byte) (*VerifiedTPMAttestation, error) {
	// Compute expected TPM nonce with platform tag.
	tpmNonce := nonce.ComputeTPMNonce(challenge, a.platform.PlatformTag(), extraData)

	// Verify TPM quote ExtraData matches the computed TPM nonce.
	quotes := a.attestation.GetQuotes()
	if len(quotes) == 0 {
		return nil, fmt.Errorf("no TPM quotes in attestation")
	}
	quoteInfo, err := tpm2.DecodeAttestationData(quotes[0].GetQuote())
	if err != nil {
		return nil, fmt.Errorf("failed to decode TPM quote: %w", err)
	}
	if !bytes.Equal(quoteInfo.ExtraData, tpmNonce) {
		return nil, fmt.Errorf("TPM nonce mismatch: quote contains different nonce than expected")
	}

	// Verify TPM attestation (AK cert chain, PCR quotes, event log).
	allRoots := make([]*x509.Certificate, 0, len(server.GceEKRoots)+len(server.GcpCASEKRoots))
	allRoots = append(allRoots, server.GceEKRoots...)
	allRoots = append(allRoots, server.GcpCASEKRoots...)
	machineState, err := server.VerifyAttestation(a.attestation, server.VerifyOpts{
		Nonce:             tpmNonce,
		TrustedRootCerts:  allRoots,
		IntermediateCerts: server.GcpCASEKIntermediates,
		Loader:            server.GRUB,
	})
	if err != nil {
		return nil, fmt.Errorf("TPM attestation verification failed: %w", err)
	}

	return &VerifiedTPMAttestation{
		Platform:     a.platform,
		ExtraData:    extraData,
		attestation:  a.attestation,
		machineState: machineState,
	}, nil
}

// VerifyBoundTEE verifies the TEE layer: TEE quote signature and binding to TPM's AK.
// Only valid for TDX and SEV-SNP. Returns an error for Shielded VM.
func (a *Attestation) VerifyBoundTEE(challenge, extraData []byte) (*VerifiedTEEAttestation, error) {
	if a.platform != PlatformIntelTDX && a.platform != PlatformAMDSevSnp {
		return nil, fmt.Errorf("TEE verification not available for platform %s", a.platform.PlatformTag())
	}

	// Extract AK public key DER for binding verification.
	akPubDER, err := extractAKPubDER(a.attestation)
	if err != nil {
		return nil, err
	}

	// Verify binding: ReportData == ComputeBoundNonce(challenge, akPubDER, extraData).
	boundNonce := nonce.ComputeBoundNonce(challenge, akPubDER, extraData)
	if err := verifyBinding(a.attestation, boundNonce, a.platform); err != nil {
		return nil, err
	}

	// Verify TEE quote signature.
	switch a.platform {
	case PlatformIntelTDX:
		if err := verifyTDXQuote(a.attestation); err != nil {
			return nil, fmt.Errorf("TDX verification failed: %w", err)
		}
	case PlatformAMDSevSnp:
		if err := verifySevSnpAttestation(a.attestation); err != nil {
			return nil, fmt.Errorf("SEV-SNP verification failed: %w", err)
		}
	}

	return &VerifiedTEEAttestation{
		Platform:    a.platform,
		ExtraData:   extraData,
		attestation: a.attestation,
	}, nil
}

// ExtractContainerClaims parses the canonical event log (COS CEL) to extract
// container claims (image, args, env vars, etc.).
//
// On TDX, the CEL is replayed against hardware RTMRs (SHA-384).
// On SEV-SNP and Shielded VM, it is replayed against vTPM PCRs (SHA-256).
func (a *Attestation) ExtractContainerClaims() (*ContainerInfo, error) {
	cel := a.attestation.GetCanonicalEventLog()
	if len(cel) == 0 {
		return nil, fmt.Errorf("no canonical event log in attestation")
	}

	var cosState *attestpb.AttestedCosState
	if a.platform == PlatformIntelTDX {
		rtmrBank, err := extractRTMRBank(a.attestation)
		if err != nil {
			return nil, fmt.Errorf("failed to extract RTMR bank: %w", err)
		}
		cosState, err = server.ParseCosCELRTMR(cel, rtmrBank)
		if err != nil {
			return nil, fmt.Errorf("failed to parse TDX canonical event log: %w", err)
		}
	} else {
		pcrBank, err := extractPCRBank(a.attestation, tpmpb.HashAlgo_SHA256)
		if err != nil {
			return nil, fmt.Errorf("failed to extract PCR bank: %w", err)
		}
		cosState, err = server.ParseCosCELPCR(cel, *pcrBank)
		if err != nil {
			return nil, fmt.Errorf("failed to parse canonical event log: %w", err)
		}
	}

	c := cosState.GetContainer()
	if c == nil {
		return nil, fmt.Errorf("canonical event log contains no container events")
	}

	return &ContainerInfo{
		ImageReference: c.GetImageReference(),
		ImageDigest:    c.GetImageDigest(),
		ImageID:        c.GetImageId(),
		RestartPolicy:  c.GetRestartPolicy().String(),
		Args:           c.GetArgs(),
		EnvVars:        c.GetEnvVars(),
	}, nil
}

func detectPlatform(attestation *attestpb.Attestation) Platform {
	if attestation.GetTdxAttestation() != nil {
		return PlatformIntelTDX
	}
	if attestation.GetSevSnpAttestation() != nil {
		return PlatformAMDSevSnp
	}
	if len(attestation.GetQuotes()) > 0 && len(attestation.GetAkCert()) > 0 {
		return PlatformGCPShieldedVM
	}
	return PlatformUnknown
}

func getReportData(attestation *attestpb.Attestation, platform Platform) []byte {
	switch platform {
	case PlatformIntelTDX:
		return attestation.GetTdxAttestation().GetTdQuoteBody().GetReportData()
	case PlatformAMDSevSnp:
		return attestation.GetSevSnpAttestation().GetReport().GetReportData()
	}
	return nil
}

// extractAKPubDER extracts and validates the AK public key in PKIX DER format
// from the attestation. It parses the AK certificate, validates its expiry,
// marshals the public key to PKIX DER, and verifies the ak_pub field matches.
func extractAKPubDER(attestation *attestpb.Attestation) ([]byte, error) {
	akCertDER := attestation.GetAkCert()
	if len(akCertDER) == 0 {
		return nil, fmt.Errorf("no AK certificate in attestation")
	}

	akCert, err := x509.ParseCertificate(akCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AK certificate: %w", err)
	}

	// Verify AK certificate is within its validity window.
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

	// Verify ak_pub field exists and matches the certificate.
	// Note: ak_pub is in TPM2B_PUBLIC format (TPMT_PUBLIC), not PKIX DER.
	akPub := attestation.GetAkPub()
	if len(akPub) == 0 {
		return nil, fmt.Errorf("no AK public key in attestation")
	}
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

	return akPubDER, nil
}

// verifyBinding verifies ReportData == expectedBoundNonce (full 64 bytes).
// This proves both freshness (via challenge) and binds the TEE hardware quote to
// the TPM's AK, proving that the TPM claims (event log, PCRs) came from the same
// VM as the TEE attestation.
func verifyBinding(attestation *attestpb.Attestation, expectedBoundNonce []byte, platform Platform) error {
	reportData := getReportData(attestation, platform)

	if len(reportData) != teeReportDataSize {
		return fmt.Errorf("report data length mismatch: got %d bytes, want %d", len(reportData), teeReportDataSize)
	}

	if !bytes.Equal(reportData, expectedBoundNonce) {
		return fmt.Errorf("binding mismatch: ReportData does not match expected bound nonce")
	}

	return nil
}

func verifyTDXQuote(attestation *attestpb.Attestation) error {
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

func verifySevSnpAttestation(attestation *attestpb.Attestation) error {
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

// extractRTMRBank builds an RTMRBank from the RTMR0–3 values in the TDX quote body.
func extractRTMRBank(attestation *attestpb.Attestation) (register.RTMRBank, error) {
	rtmrs := attestation.GetTdxAttestation().GetTdQuoteBody().GetRtmrs()
	if len(rtmrs) != 4 {
		return register.RTMRBank{}, fmt.Errorf("expected 4 RTMRs, got %d", len(rtmrs))
	}
	bank := register.RTMRBank{}
	for i, digest := range rtmrs {
		bank.RTMRs = append(bank.RTMRs, register.RTMR{Index: i, Digest: digest})
	}
	return bank, nil
}

// extractPCRBank finds the quote matching the given hash algorithm and returns the PCR bank.
func extractPCRBank(attestation *attestpb.Attestation, hashAlgo tpmpb.HashAlgo) (*register.PCRBank, error) {
	for _, quote := range attestation.GetQuotes() {
		pcrs := quote.GetPcrs()
		if pcrs.GetHash() == hashAlgo {
			pcrBank := &register.PCRBank{TCGHashAlgo: state.HashAlgo(pcrs.Hash)}
			digestAlg, err := pcrBank.TCGHashAlgo.CryptoHash()
			if err != nil {
				return nil, fmt.Errorf("invalid digest algorithm: %w", err)
			}
			for pcrIndex, digest := range pcrs.GetPcrs() {
				pcrBank.PCRs = append(pcrBank.PCRs, register.PCR{
					Index:     int(pcrIndex),
					Digest:    digest,
					DigestAlg: digestAlg,
				})
			}
			return pcrBank, nil
		}
	}
	return nil, fmt.Errorf("no PCRs found matching hash %s", hashAlgo.String())
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
