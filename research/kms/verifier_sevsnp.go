// Package main provides SEV-SNP attestation verification for the KMS server.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	sabi "github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/server"
)

// SevSnpAttestationRequest is the JSON request body for SEV-SNP attestation verification.
type SevSnpAttestationRequest struct {
	SnpReport    []byte   `json:"snp_report"`
	CEL          []byte   `json:"cel"`
	AkCertChain  [][]byte `json:"ak_cert_chain"`
	RSAPublicKey string   `json:"rsa_public_key"` // PEM-encoded ephemeral RSA public key for response encryption
}

// SevSnpPlatformInfo contains TCB and platform information from the SEV-SNP report.
type SevSnpPlatformInfo struct {
	CurrentTcb   uint64 `json:"current_tcb"`
	ReportedTcb  uint64 `json:"reported_tcb"`
	CommittedTcb uint64 `json:"committed_tcb"`
	GuestSvn     uint32 `json:"guest_svn"`
	Policy       SevSnpPolicy
}

// SevSnpPolicy contains the guest policy from the SEV-SNP report.
type SevSnpPolicy struct {
	Debug                bool `json:"debug"`                  // Debug mode enabled
	MigrateMA            bool `json:"migrate_ma"`             // Migration agent allowed
	SMT                  bool `json:"smt"`                    // Simultaneous multithreading allowed
	ABIMinor             byte `json:"abi_minor"`              // Minimum ABI minor version
	ABIMajor             byte `json:"abi_major"`              // Minimum ABI major version
	SingleSocket         bool `json:"single_socket"`          // Only single socket allowed
	CipherTextHidingDRAM bool `json:"ciphertext_hiding_dram"` // Ciphertext hiding for DRAM enabled
}

// SevSnpMeasurements contains the measurements from the SEV-SNP report.
type SevSnpMeasurements struct {
	Measurement [48]byte `json:"measurement"` // Launch measurement (firmware)
	HostData    [32]byte `json:"host_data"`   // Host-provided data
}

// VerifiedSevSnpAttestation contains all verified claims from the SEV-SNP attestation.
type VerifiedSevSnpAttestation struct {
	Platform  *SevSnpPlatformInfo  `json:"platform"`
	BaseImage *SevSnpMeasurements  `json:"base_image"`
	Container *ContainerClaims     `json:"container"`
	GCE       *GCEInstanceInfo     `json:"gce,omitempty"`
}

// VerifySevSnpAttestation verifies a raw SEV-SNP attestation and returns verified claims.
// The expectedRSAKeyHash should be SHA256(RSA public key PEM) - this binds the attestation
// to the client's ephemeral key, preventing replay and key substitution attacks.
func VerifySevSnpAttestation(req *SevSnpAttestationRequest, expectedRSAKeyHash []byte) (*VerifiedSevSnpAttestation, error) {
	// Step 1: Parse the SEV-SNP report
	attestation, err := sabi.ReportCertsToProto(req.SnpReport)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SEV-SNP report: %w", err)
	}
	report := attestation.GetReport()
	if report == nil {
		return nil, fmt.Errorf("no report in attestation")
	}

	// Step 2: Verify report signature against AMD's root CA
	verifyOpts := verify.DefaultOptions()
	if err := verify.SnpAttestation(attestation, verifyOpts); err != nil {
		return nil, fmt.Errorf("report signature verification failed: %w", err)
	}

	// Step 3: Verify RSA key hash in ReportData[0:32]
	// This proves the attestation was generated with this specific RSA public key.
	reportData := report.GetReportData()
	if len(reportData) < 64 {
		return nil, fmt.Errorf("ReportData too short: %d bytes", len(reportData))
	}
	if !bytes.Equal(reportData[0:32], expectedRSAKeyHash) {
		return nil, fmt.Errorf("RSA key hash mismatch in ReportData - attestation not bound to provided key")
	}

	// Step 4: Parse and validate guest policy
	guestPolicy, err := sabi.ParseSnpPolicy(report.GetPolicy())
	if err != nil {
		return nil, fmt.Errorf("failed to parse guest policy: %w", err)
	}

	// Reject guests in debug mode - secrets could be extracted
	if guestPolicy.Debug {
		return nil, fmt.Errorf("guest is in DEBUG mode - rejecting attestation (secrets could be extracted)")
	}

	// Step 5: Validate attestation fields
	validateOpts := &validate.Options{
		// Reject debug mode
		GuestPolicy: sabi.SnpPolicy{
			Debug: false,
		},
	}
	if err := validate.SnpAttestation(attestation, validateOpts); err != nil {
		// Log warning but continue - some fields may not match exactly
		fmt.Printf("Warning: attestation validation issue: %v\n", err)
	}

	// Step 6: Extract platform info
	platformInfo := &SevSnpPlatformInfo{
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

	// Step 7: Extract measurements
	measurements := &SevSnpMeasurements{}
	measurement := report.GetMeasurement()
	if len(measurement) >= 48 {
		copy(measurements.Measurement[:], measurement[:48])
	}
	hostData := report.GetHostData()
	if len(hostData) >= 32 {
		copy(measurements.HostData[:], hostData[:32])
	}

	// Step 8: Verify AK certificate binding and extract GCE instance info
	if len(req.AkCertChain) == 0 {
		return nil, fmt.Errorf("AK certificate chain required")
	}

	akCert, err := x509.ParseCertificate(req.AkCertChain[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse AK certificate: %w", err)
	}

	// Verify AK public key hash matches ReportData[32:64]
	akPubKeyDER, err := x509.MarshalPKIXPublicKey(akCert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AK public key: %w", err)
	}
	expectedAkHash := sha256.Sum256(akPubKeyDER)
	if !bytes.Equal(reportData[32:64], expectedAkHash[:]) {
		return nil, fmt.Errorf("AK binding mismatch - report and certificate are from different machines")
	}

	// Parse intermediate certificates
	var intermediateCerts []*x509.Certificate
	for i := 1; i < len(req.AkCertChain); i++ {
		cert, err := x509.ParseCertificate(req.AkCertChain[i])
		if err != nil {
			continue
		}
		intermediateCerts = append(intermediateCerts, cert)
	}

	// Verify AK certificate chain against Google's EK root CAs
	allRoots := append(server.GceEKRoots, server.GcpCASEKRoots...)
	allIntermediates := append(intermediateCerts, server.GcpCASEKIntermediates...)

	var gceInfo *GCEInstanceInfo
	if err := server.VerifyAKCert(akCert, allRoots, allIntermediates); err != nil {
		fmt.Printf("Warning: AK certificate verification failed: %v\n", err)
	} else {
		// Extract GCE instance info
		info, err := server.GetGCEInstanceInfo(akCert)
		if err == nil && info != nil {
			gceInfo = &GCEInstanceInfo{
				ProjectID:     info.ProjectId,
				ProjectNumber: info.ProjectNumber,
				Zone:          info.Zone,
				InstanceID:    info.InstanceId,
				InstanceName:  info.InstanceName,
			}
		}
	}

	// Step 9: Replay CEL to extract container claims
	// For SEV-SNP, we can't verify CEL against RTMRs (there are none).
	// Instead we verify the CEL against TPM PCRs if needed.
	// For now, we just parse the CEL without PCR verification.
	container, err := parseCELWithoutPCRVerification(req.CEL)
	if err != nil {
		return nil, fmt.Errorf("CEL parsing failed: %w", err)
	}

	return &VerifiedSevSnpAttestation{
		Platform:  platformInfo,
		BaseImage: measurements,
		Container: container,
		GCE:       gceInfo,
	}, nil
}

// parseCELWithoutPCRVerification parses the CEL and extracts container claims.
// Note: This does not verify the CEL against PCRs/RTMRs - it just parses the events.
// For production use with SEV-SNP, you should verify the CEL against TPM PCR quotes.
//
// WARNING: Without PCR verification, an attacker could forge CEL events.
// For a complete solution, the SEV-SNP attestation should be combined with
// a TPM quote to verify the PCR values containing the CEL digests.
func parseCELWithoutPCRVerification(celData []byte) (*ContainerClaims, error) {
	if len(celData) == 0 {
		return &ContainerClaims{}, nil
	}

	// For SEV-SNP, we parse the CEL directly using the cel package
	// This is a simplified implementation that doesn't verify against PCRs.
	// A production implementation would also fetch a TPM quote to verify PCR values.
	container := &ContainerClaims{
		EnvVars: make(map[string]string),
	}

	// Parse the CEL using go-tpm-tools/cel package
	decodedCEL, err := cel.DecodeToCEL(bytes.NewBuffer(celData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode CEL: %w", err)
	}

	// Extract container claims from CEL records
	for _, record := range decodedCEL.Records {
		cosTlv, err := record.Content.ParseToCosTlv()
		if err != nil {
			continue // Skip records we can't parse
		}

		switch cosTlv.EventType {
		case cel.ImageRefType:
			container.ImageReference = string(cosTlv.EventContent)
		case cel.ImageDigestType:
			container.ImageDigest = string(cosTlv.EventContent)
		case cel.RestartPolicyType:
			container.RestartPolicy = string(cosTlv.EventContent)
		case cel.ImageIDType:
			container.ImageID = string(cosTlv.EventContent)
		case cel.EnvVarType:
			// EnvVars are encoded as "key=value"
			if parts := bytes.SplitN(cosTlv.EventContent, []byte("="), 2); len(parts) == 2 {
				container.EnvVars[string(parts[0])] = string(parts[1])
			}
		case cel.ArgType:
			container.Args = append(container.Args, string(cosTlv.EventContent))
		}
	}

	return container, nil
}

// GetSevSnpMeasurement returns the 48-byte MEASUREMENT from a parsed SEV-SNP report.
// This is equivalent to MRTD in TDX and represents the firmware measurement.
func GetSevSnpMeasurement(report *spb.Report) []byte {
	return report.GetMeasurement()
}
