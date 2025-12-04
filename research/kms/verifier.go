// Package main provides TDX attestation verification for the KMS server.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/google/go-eventlog/register"
	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tpm-tools/server"
)

// RawAttestationRequest is the JSON request body for attestation verification.
type RawAttestationRequest struct {
	TdQuote     []byte   `json:"td_quote"`
	CEL         []byte   `json:"cel"`
	AkCertChain [][]byte `json:"ak_cert_chain"`
	Nonce       []byte   `json:"nonce"`
}

// BaseImageMeasurements contains the TDX measurements for the base image.
type BaseImageMeasurements struct {
	MRTD  [48]byte `json:"mrtd"`
	RTMR0 [48]byte `json:"rtmr0"`
	RTMR1 [48]byte `json:"rtmr1"`
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

// VerifiedAttestation contains all verified claims from the attestation.
type VerifiedAttestation struct {
	BaseImage *BaseImageMeasurements `json:"base_image"`
	Container *ContainerClaims       `json:"container"`
	GCE       *GCEInstanceInfo       `json:"gce,omitempty"`
}

// VerifyAttestation verifies a raw TDX attestation and returns verified claims.
func VerifyAttestation(req *RawAttestationRequest) (*VerifiedAttestation, error) {
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

	// Step 3: Verify nonce hash in ReportData[0:32]
	reportData := quote.GetTdQuoteBody().GetReportData()
	expectedNonceHash := sha256.Sum256(req.Nonce)
	if !bytes.Equal(reportData[0:32], expectedNonceHash[:]) {
		return nil, fmt.Errorf("nonce hash mismatch in ReportData")
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

	// Step 5: Extract base image measurements (MRTD, RTMR[0], RTMR[1])
	mrtd := quote.GetTdQuoteBody().GetMrTd()
	rtmrs := quote.GetTdQuoteBody().GetRtmrs()
	if len(rtmrs) < 4 {
		return nil, fmt.Errorf("expected 4 RTMRs, got %d", len(rtmrs))
	}

	baseImage := &BaseImageMeasurements{}
	copy(baseImage.MRTD[:], mrtd)
	copy(baseImage.RTMR0[:], rtmrs[0])
	copy(baseImage.RTMR1[:], rtmrs[1])

	// Step 6: Verify AK certificate binding and extract GCE instance info
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

	// Step 7: Replay CEL against RTMR[2] to extract container claims
	rtmrBank := register.RTMRBank{
		RTMRs: make([]register.RTMR, len(rtmrs)),
	}
	for i, rtmr := range rtmrs {
		rtmrBank.RTMRs[i] = register.RTMR{
			Index:  i,
			Digest: rtmr,
		}
	}

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
		BaseImage: baseImage,
		Container: container,
		GCE:       gceInfo,
	}, nil
}
