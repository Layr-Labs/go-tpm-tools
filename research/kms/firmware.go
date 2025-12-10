// Package main provides firmware endorsement verification against Google's TCB bucket.
package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	tcbv "github.com/google/gce-tcb-verifier/verify"
	"google.golang.org/protobuf/proto"
)

const (
	// GCSTCBBucket is the bucket containing Google's firmware endorsements.
	GCSTCBBucket = "gce_tcb_integrity"

	// TDXEndorsementPrefix is the path prefix for TDX endorsements.
	TDXEndorsementPrefix = "ovmf_x64_csm/tdx/"

	// SevSnpEndorsementPrefix is the path prefix for SEV-SNP endorsements.
	SevSnpEndorsementPrefix = "ovmf_x64_csm/sevsnp/"

	// GCERootCertURL is the URL for Google's TCB root certificate.
	GCERootCertURL = "https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt"
)

// Technology represents the CVM technology type.
type Technology int

const (
	// TDX is Intel Trust Domain Extensions.
	TDX Technology = iota
	// SevSnp is AMD Secure Encrypted Virtualization - Secure Nested Paging.
	SevSnp
)

// FirmwareVerifier verifies MRTD values against Google's signed endorsements.
type FirmwareVerifier struct {
	gcsClient    *storage.Client
	rootsOfTrust *x509.CertPool
}

// NewFirmwareVerifier creates a new firmware verifier.
func NewFirmwareVerifier(ctx context.Context) (*FirmwareVerifier, error) {
	// Create GCS client
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}

	// Fetch Google's TCB root certificate
	roots, err := fetchRootsOfTrust()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch roots of trust: %w", err)
	}

	return &FirmwareVerifier{
		gcsClient:    client,
		rootsOfTrust: roots,
	}, nil
}

// Close closes the GCS client.
func (v *FirmwareVerifier) Close() error {
	return v.gcsClient.Close()
}

// FirmwareEndorsement contains verified firmware information.
type FirmwareEndorsement struct {
	SVN        uint32    // Security Version Number
	Timestamp  time.Time // Build timestamp
	ClSpec     uint64    // Changelist number
	UEFIDigest []byte    // SHA-384 of UEFI binary
}

// VerifyMRTD verifies that an MRTD value is endorsed by Google (TDX).
// It fetches the endorsement from GCS and verifies the signature chain.
func (v *FirmwareVerifier) VerifyMRTD(ctx context.Context, mrtd []byte) (*FirmwareEndorsement, error) {
	return v.VerifyMeasurement(ctx, TDX, mrtd)
}

// VerifySevSnpMeasurement verifies that a SEV-SNP MEASUREMENT is endorsed by Google.
// It fetches the endorsement from GCS and verifies the signature chain.
func (v *FirmwareVerifier) VerifySevSnpMeasurement(ctx context.Context, measurement []byte) (*FirmwareEndorsement, error) {
	return v.VerifyMeasurement(ctx, SevSnp, measurement)
}

// VerifyMeasurement verifies that a firmware measurement is endorsed by Google.
// For TDX, measurement is the MRTD (48 bytes).
// For SEV-SNP, measurement is the MEASUREMENT field (48 bytes).
func (v *FirmwareVerifier) VerifyMeasurement(ctx context.Context, tech Technology, measurement []byte) (*FirmwareEndorsement, error) {
	if len(measurement) != 48 {
		return nil, fmt.Errorf("measurement must be 48 bytes (SHA-384), got %d", len(measurement))
	}

	// Select endorsement prefix based on technology
	var prefix string
	var techName string
	switch tech {
	case TDX:
		prefix = TDXEndorsementPrefix
		techName = "TDX MRTD"
	case SevSnp:
		prefix = SevSnpEndorsementPrefix
		techName = "SEV-SNP MEASUREMENT"
	default:
		return nil, fmt.Errorf("unsupported technology: %d", tech)
	}

	// Convert measurement to hex for the GCS object name
	measurementHex := hex.EncodeToString(measurement)
	objectName := prefix + measurementHex + ".binarypb"

	// Fetch endorsement from GCS
	endorsementBytes, err := v.fetchFromGCS(ctx, objectName)
	if err != nil {
		// If the endorsement doesn't exist, the measurement is not endorsed
		if strings.Contains(err.Error(), "object doesn't exist") {
			return nil, fmt.Errorf("%s %s not found in Google's endorsements - firmware not endorsed", techName, measurementHex)
		}
		return nil, fmt.Errorf("failed to fetch endorsement: %w", err)
	}

	// Verify the endorsement signature and extract info
	return v.verifyEndorsement(endorsementBytes, measurement, tech)
}

// fetchFromGCS fetches an object from the TCB integrity bucket.
func (v *FirmwareVerifier) fetchFromGCS(ctx context.Context, objectName string) ([]byte, error) {
	bucket := v.gcsClient.Bucket(GCSTCBBucket)
	obj := bucket.Object(objectName)

	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

// verifyEndorsement verifies the endorsement signature and returns firmware info.
func (v *FirmwareVerifier) verifyEndorsement(endorsementBytes, expectedMeasurement []byte, tech Technology) (*FirmwareEndorsement, error) {
	// Parse the VMLaunchEndorsement protobuf
	endorsement := &epb.VMLaunchEndorsement{}
	if err := proto.Unmarshal(endorsementBytes, endorsement); err != nil {
		return nil, fmt.Errorf("failed to parse endorsement: %w", err)
	}

	// Verify the endorsement signature using gce-tcb-verifier
	opts := &tcbv.Options{
		RootsOfTrust: v.rootsOfTrust,
		Now:          time.Now(),
	}
	if err := tcbv.EndorsementProto(endorsement, opts); err != nil {
		return nil, fmt.Errorf("endorsement signature verification failed: %w", err)
	}

	// Parse the golden measurement to extract info
	golden := &epb.VMGoldenMeasurement{}
	if err := proto.Unmarshal(endorsement.GetSerializedUefiGolden(), golden); err != nil {
		return nil, fmt.Errorf("failed to parse golden measurement: %w", err)
	}

	// Extract technology-specific measurements and SVN
	switch tech {
	case TDX:
		return v.extractTdxEndorsement(golden, expectedMeasurement)
	case SevSnp:
		return v.extractSevSnpEndorsement(golden, expectedMeasurement)
	default:
		return nil, fmt.Errorf("unsupported technology: %d", tech)
	}
}

// extractTdxEndorsement extracts endorsement info for TDX.
func (v *FirmwareVerifier) extractTdxEndorsement(golden *epb.VMGoldenMeasurement, expectedMRTD []byte) (*FirmwareEndorsement, error) {
	tdx := golden.GetTdx()
	if tdx == nil {
		return nil, fmt.Errorf("endorsement does not contain TDX measurements")
	}

	// Check that the MRTD matches one of the endorsed measurements
	found := false
	for _, measurement := range tdx.GetMeasurements() {
		if bytesEqual(measurement.GetMrtd(), expectedMRTD) {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("MRTD does not match any measurement in endorsement")
	}

	result := &FirmwareEndorsement{
		SVN:        tdx.GetSvn(),
		UEFIDigest: golden.GetDigest(),
		ClSpec:     golden.GetClSpec(),
	}

	if ts := golden.GetTimestamp(); ts != nil {
		result.Timestamp = ts.AsTime()
	}

	return result, nil
}

// extractSevSnpEndorsement extracts endorsement info for SEV-SNP.
func (v *FirmwareVerifier) extractSevSnpEndorsement(golden *epb.VMGoldenMeasurement, expectedMeasurement []byte) (*FirmwareEndorsement, error) {
	sevsnp := golden.GetSevSnp()
	if sevsnp == nil {
		return nil, fmt.Errorf("endorsement does not contain SEV-SNP measurements")
	}

	// SEV-SNP measurements are keyed by VMSA count (number of vCPUs)
	// The measurement should be present in the map
	found := false
	for _, measurement := range sevsnp.GetMeasurements() {
		if bytesEqual(measurement, expectedMeasurement) {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("MEASUREMENT does not match any measurement in endorsement")
	}

	result := &FirmwareEndorsement{
		SVN:        sevsnp.GetSvn(),
		UEFIDigest: golden.GetDigest(),
		ClSpec:     golden.GetClSpec(),
	}

	if ts := golden.GetTimestamp(); ts != nil {
		result.Timestamp = ts.AsTime()
	}

	return result, nil
}

// fetchRootsOfTrust fetches Google's TCB root certificate.
func fetchRootsOfTrust() (*x509.CertPool, error) {
	resp, err := http.Get(GCERootCertURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch root certificate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch root certificate: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read root certificate: %w", err)
	}

	roots := x509.NewCertPool()
	// Try PEM first, then DER
	if !roots.AppendCertsFromPEM(data) {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse root certificate as PEM or DER: %w", err)
		}
		roots.AddCert(cert)
	}

	return roots, nil
}

// bytesEqual compares two byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
