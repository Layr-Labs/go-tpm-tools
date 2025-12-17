// Package verifier provides CVM attestation verification for TDX and SEV-SNP.
package verifier

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	sabi "github.com/google/go-sev-guest/abi"
	sevverify "github.com/google/go-sev-guest/verify"
	tdxverify "github.com/google/go-tdx-guest/verify"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// Platform represents the CVM technology type.
type Platform int

const (
	PlatformUnknown Platform = iota
	PlatformTDX
	PlatformSevSnp
)

// Claims contains all verified claims from the attestation.
type Claims struct {
	Platform  Platform       `json:"platform"`
	Container *ContainerInfo `json:"container"`
	GCE       *GCEInfo       `json:"gce,omitempty"`
	TDX       *TDXClaims     `json:"tdx,omitempty"`
	SevSnp    *SevSnpClaims  `json:"sevsnp,omitempty"`

	// PCR values from vTPM (platform-agnostic, same for TDX and SEV-SNP)
	// Used for base image allowlist validation
	PCR8 [32]byte `json:"pcr8"` // Kernel cmdline (includes dm-verity hash = launcher identity)
	PCR9 [32]byte `json:"pcr9"` // GRUB-read files (kernel + initramfs = base image)
}

// TDXClaims contains TDX-specific verified claims.
type TDXClaims struct {
	MRTD       [48]byte     `json:"mrtd"`
	RTMR0      [48]byte     `json:"rtmr0"`
	RTMR1      [48]byte     `json:"rtmr1"`
	TeeTcbSvn  [16]byte     `json:"tee_tcb_svn"`
	Attributes TDAttributes `json:"attributes"`
}

// SevSnpClaims contains SEV-SNP-specific verified claims.
type SevSnpClaims struct {
	Measurement  [48]byte     `json:"measurement"`
	HostData     [32]byte     `json:"host_data"`
	CurrentTcb   uint64       `json:"current_tcb"`
	ReportedTcb  uint64       `json:"reported_tcb"`
	CommittedTcb uint64       `json:"committed_tcb"`
	GuestSvn     uint32       `json:"guest_svn"`
	Policy       SevSnpPolicy `json:"policy"`
}

// SevSnpPolicy contains SEV-SNP guest policy flags.
type SevSnpPolicy struct {
	Debug                bool  `json:"debug"`
	MigrateMA            bool  `json:"migrate_ma"`
	SMT                  bool  `json:"smt"`
	ABIMinor             uint8 `json:"abi_minor"`
	ABIMajor             uint8 `json:"abi_major"`
	SingleSocket         bool  `json:"single_socket"`
	CipherTextHidingDRAM bool  `json:"ciphertext_hiding_dram"`
}

// ContainerInfo contains verified container claims.
type ContainerInfo struct {
	ImageReference string            `json:"image_reference"`
	ImageDigest    string            `json:"image_digest"`
	ImageID        string            `json:"image_id"`
	RestartPolicy  string            `json:"restart_policy"`
	Args           []string          `json:"args,omitempty"`
	EnvVars        map[string]string `json:"env_vars,omitempty"`
}

// GCEInfo contains GCE instance metadata.
type GCEInfo struct {
	ProjectID     string `json:"project_id"`
	ProjectNumber uint64 `json:"project_number"`
	Zone          string `json:"zone"`
	InstanceID    uint64 `json:"instance_id"`
	InstanceName  string `json:"instance_name"`
}

// TDAttributes contains TD attribute flags.
type TDAttributes struct {
	Debug         bool `json:"debug"`
	SeptVEDisable bool `json:"sept_ve_disable"`
	PKS           bool `json:"pks"`
	KL            bool `json:"kl"`
	PerfMon       bool `json:"perf_mon"`
}

// Verify verifies an attestation and returns verified claims.
// Uses server.VerifyAttestation() for TPM/AK validation, then platform-specific TEE verification.
// expectedReportData is checked against the first 32 bytes of TEE ReportData.
func Verify(attestationBytes, expectedReportData []byte) (*Claims, error) {
	var attestation attestpb.Attestation
	if err := proto.Unmarshal(attestationBytes, &attestation); err != nil {
		return nil, fmt.Errorf("failed to parse attestation proto: %w", err)
	}

	platform := detectPlatform(&attestation)
	if platform == PlatformUnknown {
		return nil, fmt.Errorf("no TEE attestation found")
	}

	if err := verifyReportData(&attestation, expectedReportData, platform); err != nil {
		return nil, err
	}

	// Verify AK binding: ReportData[32:64] == SHA256(AK_public_key)
	if err := verifyAKBinding(&attestation, platform); err != nil {
		return nil, err
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

	claims := &Claims{Platform: platform}

	// Extract PCR 8 and PCR 9 from verified TPM quote (platform-agnostic)
	pcr8, pcr9, err := extractPCRs(&attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to extract PCRs: %w", err)
	}
	claims.PCR8 = pcr8
	claims.PCR9 = pcr9

	// Extract GCE instance info
	if p := machineState.GetPlatform(); p != nil {
		if info := p.GetInstanceInfo(); info != nil {
			claims.GCE = &GCEInfo{
				ProjectID:     info.GetProjectId(),
				ProjectNumber: info.GetProjectNumber(),
				Zone:          info.GetZone(),
				InstanceID:    info.GetInstanceId(),
				InstanceName:  info.GetInstanceName(),
			}
		}
	}

	// Extract container info
	if cos := machineState.GetCos(); cos != nil {
		if c := cos.GetContainer(); c != nil {
			claims.Container = &ContainerInfo{
				ImageReference: c.GetImageReference(),
				ImageDigest:    c.GetImageDigest(),
				ImageID:        c.GetImageId(),
				RestartPolicy:  c.GetRestartPolicy().String(),
				Args:           c.GetArgs(),
				EnvVars:        c.GetEnvVars(),
			}
		}
	}

	switch platform {
	case PlatformTDX:
		tdxClaims, err := verifyTDXAttestation(&attestation)
		if err != nil {
			return nil, fmt.Errorf("TDX verification failed: %w", err)
		}
		claims.TDX = tdxClaims
	case PlatformSevSnp:
		sevClaims, err := verifySevSnpAttestation(&attestation)
		if err != nil {
			return nil, fmt.Errorf("SEV-SNP report verification failed: %w", err)
		}
		claims.SevSnp = sevClaims
	}

	return claims, nil
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

func verifyReportData(attestation *attestpb.Attestation, expectedReportData []byte, platform Platform) error {
	var reportData []byte
	switch platform {
	case PlatformTDX:
		reportData = attestation.GetTdxAttestation().GetTdQuoteBody().GetReportData()
	case PlatformSevSnp:
		reportData = attestation.GetSevSnpAttestation().GetReport().GetReportData()
	}
	if len(reportData) < 32 || !bytes.Equal(reportData[0:32], expectedReportData) {
		return fmt.Errorf("report data mismatch in TEE quote")
	}
	return nil
}

// verifyAKBinding verifies that ReportData[32:64] == SHA256(AK_public_key_DER).
// This binds the TEE hardware quote to the TPM's AK, proving that the TPM claims
// (event log, PCRs) came from the same VM as the TEE attestation.
func verifyAKBinding(attestation *attestpb.Attestation, platform Platform) error {
	var reportData []byte
	switch platform {
	case PlatformTDX:
		reportData = attestation.GetTdxAttestation().GetTdQuoteBody().GetReportData()
	case PlatformSevSnp:
		reportData = attestation.GetSevSnpAttestation().GetReport().GetReportData()
	}

	if len(reportData) < 64 {
		return fmt.Errorf("report data too short for AK binding verification")
	}

	// Get AK public key from attestation
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

// extractPCRs extracts PCR 8 and PCR 9 from the TPM quote.
// These values are platform-agnostic (same for TDX and SEV-SNP with identical images).
// - PCR 8: Kernel command line (includes dm-verity root hash = launcher identity)
// - PCR 9: Files read by GRUB (kernel + initramfs = base image)
func extractPCRs(attestation *attestpb.Attestation) ([32]byte, [32]byte, error) {
	var pcr8, pcr9 [32]byte

	// Find the SHA-256 quote (hash algorithm 0x000B)
	var sha256PCRs *tpmpb.PCRs
	for _, quote := range attestation.GetQuotes() {
		if quote.GetPcrs().GetHash() == tpmpb.HashAlgo_SHA256 {
			sha256PCRs = quote.GetPcrs()
			break
		}
	}

	if sha256PCRs == nil {
		return pcr8, pcr9, fmt.Errorf("no SHA-256 PCR bank found in attestation")
	}

	pcrs := sha256PCRs.GetPcrs()

	// Extract PCR 8
	if val, ok := pcrs[8]; ok && len(val) == 32 {
		copy(pcr8[:], val)
	} else {
		return pcr8, pcr9, fmt.Errorf("PCR 8 not found or invalid length")
	}

	// Extract PCR 9
	if val, ok := pcrs[9]; ok && len(val) == 32 {
		copy(pcr9[:], val)
	} else {
		return pcr8, pcr9, fmt.Errorf("PCR 9 not found or invalid length")
	}

	return pcr8, pcr9, nil
}

// verifyTDXAttestation verifies the TDX quote and extracts claims.
func verifyTDXAttestation(attestation *attestpb.Attestation) (*TDXClaims, error) {
	quote := attestation.GetTdxAttestation()

	// Verify TDX quote signature
	if err := tdxverify.TdxQuote(quote, tdxverify.DefaultOptions()); err != nil {
		return nil, fmt.Errorf("TDX quote signature verification failed: %w", err)
	}

	// Check debug mode from TD attributes
	tdAttrs := quote.GetTdQuoteBody().GetTdAttributes()
	if len(tdAttrs) < 2 || tdAttrs[0]&0x01 != 0 {
		return nil, fmt.Errorf("TD is in DEBUG mode - rejecting")
	}

	claims := &TDXClaims{
		Attributes: TDAttributes{
			Debug:         tdAttrs[0]&0x01 != 0,
			SeptVEDisable: tdAttrs[0]&0x10 != 0,
			PKS:           tdAttrs[0]&0x40 != 0,
			KL:            tdAttrs[0]&0x80 != 0,
			PerfMon:       tdAttrs[1]&0x01 != 0,
		},
	}

	// Extract TEE TCB SVN
	if tcb := quote.GetTdQuoteBody().GetTeeTcbSvn(); len(tcb) >= 16 {
		copy(claims.TeeTcbSvn[:], tcb[:16])
	}

	// Extract MRTD
	if mrtd := quote.GetTdQuoteBody().GetMrTd(); len(mrtd) >= 48 {
		copy(claims.MRTD[:], mrtd[:48])
	}

	// Extract RTMRs
	if rtmrs := quote.GetTdQuoteBody().GetRtmrs(); len(rtmrs) >= 2 {
		if len(rtmrs[0]) >= 48 {
			copy(claims.RTMR0[:], rtmrs[0][:48])
		}
		if len(rtmrs[1]) >= 48 {
			copy(claims.RTMR1[:], rtmrs[1][:48])
		}
	}

	return claims, nil
}

// verifySevSnpAttestation verifies the SEV-SNP report signature and extracts claims.
func verifySevSnpAttestation(attestation *attestpb.Attestation) (*SevSnpClaims, error) {
	snpAttestation := attestation.GetSevSnpAttestation()
	if err := sevverify.SnpAttestation(snpAttestation, sevverify.DefaultOptions()); err != nil {
		return nil, fmt.Errorf("report signature verification failed: %w", err)
	}
	report := snpAttestation.GetReport()
	guestPolicy, err := sabi.ParseSnpPolicy(report.GetPolicy())
	if err != nil {
		return nil, fmt.Errorf("failed to parse guest policy: %w", err)
	}
	if guestPolicy.Debug {
		return nil, fmt.Errorf("guest is in DEBUG mode - rejecting")
	}

	claims := &SevSnpClaims{
		CurrentTcb:   report.GetCurrentTcb(),
		ReportedTcb:  report.GetReportedTcb(),
		CommittedTcb: report.GetCommittedTcb(),
		GuestSvn:     report.GetGuestSvn(),
		Policy: SevSnpPolicy{
			Debug:                guestPolicy.Debug,
			MigrateMA:            guestPolicy.MigrateMA,
			SMT:                  guestPolicy.SMT,
			ABIMinor:             guestPolicy.ABIMinor,
			ABIMajor:             guestPolicy.ABIMajor,
			SingleSocket:         guestPolicy.SingleSocket,
			CipherTextHidingDRAM: guestPolicy.CipherTextHidingDRAM,
		},
	}
	if m := report.GetMeasurement(); len(m) >= 48 {
		copy(claims.Measurement[:], m[:48])
	}
	if h := report.GetHostData(); len(h) >= 32 {
		copy(claims.HostData[:], h[:32])
	}
	return claims, nil
}
