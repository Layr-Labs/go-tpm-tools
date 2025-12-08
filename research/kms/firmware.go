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

	// GCERootCertURL is the URL for Google's TCB root certificate.
	GCERootCertURL = "https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt"
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

// VerifyMRTD verifies that an MRTD value is endorsed by Google.
// It fetches the endorsement from GCS and verifies the signature chain.
func (v *FirmwareVerifier) VerifyMRTD(ctx context.Context, mrtd []byte) (*FirmwareEndorsement, error) {
	if len(mrtd) != 48 {
		return nil, fmt.Errorf("MRTD must be 48 bytes (SHA-384), got %d", len(mrtd))
	}

	// Convert MRTD to hex for the GCS object name
	mrtdHex := hex.EncodeToString(mrtd)
	objectName := TDXEndorsementPrefix + mrtdHex + ".binarypb"

	// Fetch endorsement from GCS
	endorsementBytes, err := v.fetchFromGCS(ctx, objectName)
	if err != nil {
		// If the endorsement doesn't exist, the MRTD is not endorsed
		if strings.Contains(err.Error(), "object doesn't exist") {
			return nil, fmt.Errorf("MRTD %s not found in Google's endorsements - firmware not endorsed", mrtdHex)
		}
		return nil, fmt.Errorf("failed to fetch endorsement: %w", err)
	}

	// Verify the endorsement signature and extract info
	return v.verifyEndorsement(endorsementBytes, mrtd)
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
func (v *FirmwareVerifier) verifyEndorsement(endorsementBytes, expectedMRTD []byte) (*FirmwareEndorsement, error) {
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

	// Verify this is a TDX endorsement
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
