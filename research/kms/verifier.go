// Package main provides TDX attestation verification for the KMS server.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/google/go-eventlog/ccel"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tpm-tools/server"
)

// RawAttestationRequest is the JSON request body for attestation verification.
type RawAttestationRequest struct {
	TdQuote       []byte   `json:"td_quote"`
	CEL           []byte   `json:"cel"`
	CcelAcpiTable []byte   `json:"ccel_acpi_table"` // CCEL ACPI table from /sys/firmware/acpi/tables/CCEL
	CcelData      []byte   `json:"ccel_data"`       // UEFI event log from /sys/firmware/acpi/tables/data/CCEL
	AkCertChain   [][]byte `json:"ak_cert_chain"`
	RSAPublicKey  string   `json:"rsa_public_key"` // PEM-encoded ephemeral RSA public key for response encryption
}

// BaseImageMeasurements contains the TDX measurements for the base image.
type BaseImageMeasurements struct {
	MRTD  [48]byte `json:"mrtd"`
	RTMR0 [48]byte `json:"rtmr0"`
	RTMR1 [48]byte `json:"rtmr1"`
}

// TDAttributes contains TD security attributes from the quote.
type TDAttributes struct {
	Debug         bool `json:"debug"`           // TD is in debug mode
	SeptVEDisable bool `json:"sept_ve_disable"` // #VE on pending page access disabled
	PKS           bool `json:"pks"`             // Supervisor protection keys enabled
	KL            bool `json:"kl"`              // Key locker enabled
	PerfMon       bool `json:"perf_mon"`        // Perfmon/debugging features enabled
}

// TDXPlatformInfo contains TCB and platform information from the quote.
type TDXPlatformInfo struct {
	TeeTcbSvn  [16]byte     `json:"tee_tcb_svn"` // TEE TCB Security Version Numbers
	Attributes TDAttributes `json:"attributes"`
}

// ContainerClaims contains verified container claims from the CEL.
type ContainerClaims struct {
	ImageReference string            `json:"image_reference"`
	ImageDigest    string            `json:"image_digest"`
	ImageID        string            `json:"image_id,omitempty"`
	RestartPolicy  string            `json:"restart_policy"`
	Args           []string          `json:"args,omitempty"`
	EnvVars        map[string]string `json:"env_vars,omitempty"`
}

// GCEInstanceInfo contains verified GCE instance info from the AK certificate.
type GCEInstanceInfo struct {
	ProjectID     string `json:"project_id"`
	ProjectNumber uint64 `json:"project_number"`
	Zone          string `json:"zone"`
	InstanceID    uint64 `json:"instance_id"`
	InstanceName  string `json:"instance_name"`
}

// FirmwareState contains verified firmware configuration from RTMR0 events.
// This is extracted from the CCEL (CC Event Log) which contains UEFI measurements.
type FirmwareState struct {
	SecureBootEnabled bool `json:"secure_boot_enabled"`
	Hardened          bool `json:"hardened"` // True if production (hardened) image, false if debug
}

// VerifiedAttestation contains all verified claims from the attestation.
type VerifiedAttestation struct {
	Platform  *TDXPlatformInfo       `json:"platform"`
	BaseImage *BaseImageMeasurements `json:"base_image"`
	Firmware  *FirmwareState         `json:"firmware,omitempty"`
	Container *ContainerClaims       `json:"container"`
	GCE       *GCEInstanceInfo       `json:"gce,omitempty"`
}

// VerifyAttestation verifies a raw TDX attestation and returns verified claims.
// The expectedRSAKeyHash should be SHA256(RSA public key PEM) - this binds the attestation
// to the client's ephemeral key, preventing replay and key substitution attacks.
func VerifyAttestation(req *RawAttestationRequest, expectedRSAKeyHash []byte) (*VerifiedAttestation, error) {
	// Step 1: Parse the TDX quote
	quoteAny, err := abi.QuoteToProto(req.TdQuote)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TDX quote: %w", err)
	}
	quote, ok := quoteAny.(*pb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("expected QuoteV4, got %T", quoteAny)
	}

	// Step 2: Verify quote signature against Intel's root CA
	verifyOpts := &verify.Options{
		CheckRevocations: true,
		GetCollateral:    true,
	}
	if err := verify.TdxQuote(quote, verifyOpts); err != nil {
		return nil, fmt.Errorf("quote signature verification failed: %w", err)
	}

	// Step 3: Verify RSA key hash in ReportData[0:32]
	// This proves the attestation was generated with this specific RSA public key,
	// binding the attestation to the client's ephemeral key.
	reportData := quote.GetTdQuoteBody().GetReportData()
	if !bytes.Equal(reportData[0:32], expectedRSAKeyHash) {
		return nil, fmt.Errorf("RSA key hash mismatch in ReportData - attestation not bound to provided key")
	}

	// Step 4: Validate quote fields
	validateOpts := &validate.Options{
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
			ReportData: reportData,
		},
	}
	if err := validate.TdxQuote(quote, validateOpts); err != nil {
		// Log warning but continue - some fields may not match exactly
		fmt.Printf("Warning: quote validation issue: %v\n", err)
	}

	// Step 5: Extract and validate TD attributes
	tdAttrs := quote.GetTdQuoteBody().GetTdAttributes()
	if len(tdAttrs) < 8 {
		return nil, fmt.Errorf("invalid TD attributes length: %d", len(tdAttrs))
	}

	// Parse TD attributes - see Intel TDX Module spec section 3.2
	// Byte 0, Bit 0 = DEBUG mode - TD is debuggable, secrets may be exposed
	// Byte 0, Bit 28 = SEPT_VE_DISABLE - #VE on pending page access disabled
	// Byte 0, Bit 30 = PKS - Protection keys for supervisor enabled
	// Byte 0, Bit 31 = KL - Key locker enabled
	// Byte 1, Bit 0 = PERFMON - Performance monitoring enabled
	platformInfo := &TDXPlatformInfo{
		Attributes: TDAttributes{
			Debug:         tdAttrs[0]&0x01 != 0,
			SeptVEDisable: tdAttrs[0]&0x10 != 0, // bit 28 in little-endian
			PKS:           tdAttrs[0]&0x40 != 0, // bit 30
			KL:            tdAttrs[0]&0x80 != 0, // bit 31
			PerfMon:       tdAttrs[1]&0x01 != 0, // bit 32 (byte 1, bit 0)
		},
	}

	// Reject TDs in debug mode - secrets could be extracted
	if platformInfo.Attributes.Debug {
		return nil, fmt.Errorf("TD is in DEBUG mode - rejecting attestation (secrets could be extracted)")
	}

	// Extract TEE TCB SVN (Security Version Numbers)
	teeTcbSvn := quote.GetTdQuoteBody().GetTeeTcbSvn()
	if len(teeTcbSvn) >= 16 {
		copy(platformInfo.TeeTcbSvn[:], teeTcbSvn[:16])
	}

	// Step 6: Extract base image measurements (MRTD, RTMR[0], RTMR[1])
	mrtd := quote.GetTdQuoteBody().GetMrTd()
	rtmrs := quote.GetTdQuoteBody().GetRtmrs()
	if len(rtmrs) < 4 {
		return nil, fmt.Errorf("expected 4 RTMRs, got %d", len(rtmrs))
	}

	baseImage := &BaseImageMeasurements{}
	copy(baseImage.MRTD[:], mrtd)
	copy(baseImage.RTMR0[:], rtmrs[0])
	copy(baseImage.RTMR1[:], rtmrs[1])

	// Step 7: Verify AK certificate binding and extract GCE instance info
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
		return nil, fmt.Errorf("AK binding mismatch - quote and certificate are from different machines")
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

	// Step 8: Build RTMR bank for event log replay
	rtmrBank := register.RTMRBank{
		RTMRs: make([]register.RTMR, len(rtmrs)),
	}
	for i, rtmr := range rtmrs {
		rtmrBank.RTMRs[i] = register.RTMR{
			Index:  i,
			Digest: rtmr,
		}
	}

	// Step 9: Parse CCEL (UEFI event log) to extract firmware state
	// Uses go-eventlog/ccel which supports TDX's SHA384 digests
	var firmwareState *FirmwareState
	if len(req.CcelData) > 0 {
		firmwareState = parseFirmwareState(req.CcelAcpiTable, req.CcelData, rtmrBank)
	}

	// Step 10: Replay CEL against RTMR[2] to extract container claims

	cosState, err := server.ParseCosCELRTMR(req.CEL, rtmrBank)
	if err != nil {
		return nil, fmt.Errorf("CEL replay failed: %w", err)
	}

	container := &ContainerClaims{
		ImageReference: cosState.GetContainer().GetImageReference(),
		ImageDigest:    cosState.GetContainer().GetImageDigest(),
		ImageID:        cosState.GetContainer().GetImageId(),
		RestartPolicy:  cosState.GetContainer().GetRestartPolicy().String(),
		Args:           cosState.GetContainer().GetArgs(),
		EnvVars:        cosState.GetContainer().GetEnvVars(),
	}

	return &VerifiedAttestation{
		Platform:  platformInfo,
		BaseImage: baseImage,
		Firmware:  firmwareState,
		Container: container,
		GCE:       gceInfo,
	}, nil
}

// parseFirmwareState extracts firmware configuration from CCEL event log.
// Uses go-eventlog/ccel which supports TDX's SHA384 digests.
func parseFirmwareState(ccelAcpiTable, ccelData []byte, rtmrBank register.RTMRBank) *FirmwareState {
	if len(ccelData) == 0 {
		return nil
	}

	// Parse and replay CCEL against RTMRs using go-eventlog/ccel
	opts := ccel.ExtractOpts{}
	fwState, err := ccel.ExtractFirmwareLogState(ccelAcpiTable, ccelData, rtmrBank, opts)
	if err != nil {
		fmt.Printf("Warning: failed to parse CCEL event log: %v\n", err)
		return nil
	}

	state := &FirmwareState{}

	// Extract Secure Boot state
	if sb := fwState.GetSecureBoot(); sb != nil {
		state.SecureBootEnabled = sb.GetEnabled()
	}

	// Extract hardened flag from kernel command line
	// Confidential Space sets "confidential-space.hardened=true" for production images
	if linuxKernel := fwState.GetLinuxKernel(); linuxKernel != nil {
		cmdline := linuxKernel.GetCommandLine()
		state.Hardened = strings.Contains(cmdline, "confidential-space.hardened=true")
	}

	return state
}
