// Package attest provides firmware endorsement verification against Google's TCB bucket.
package attest

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/gce-tcb-verifier/extract/extractsev"
	"github.com/google/gce-tcb-verifier/extract/extracttdx"
	"github.com/google/gce-tcb-verifier/gcetcbendorsement"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/sev"
	tcbv "github.com/google/gce-tcb-verifier/verify"
	"google.golang.org/protobuf/proto"
)

// Package-level cached state for firmware verification.
var (
	rootsMu     sync.Mutex
	cachedRoots *x509.CertPool
	httpClient  = &http.Client{Timeout: 30 * time.Second}
)

// FirmwareEndorsement contains verified firmware information.
type FirmwareEndorsement struct {
	SVN        uint32    // Security Version Number
	Timestamp  time.Time // Build timestamp
	ClSpec     uint64    // Changelist number
	UEFIDigest []byte    // SHA-384 of UEFI binary
}

// VerifyMRTD verifies that a TDX MRTD value is endorsed by Google.
func VerifyMRTD(ctx context.Context, mrtd []byte) (*FirmwareEndorsement, error) {
	roots, err := getRootsOfTrust()
	if err != nil {
		return nil, err
	}
	return verifyMeasurement(ctx, PlatformIntelTDX, mrtd, roots)
}

// VerifySevSnpMeasurement verifies that a SEV-SNP MEASUREMENT is endorsed by Google.
func VerifySevSnpMeasurement(ctx context.Context, measurement []byte) (*FirmwareEndorsement, error) {
	roots, err := getRootsOfTrust()
	if err != nil {
		return nil, err
	}
	return verifyMeasurement(ctx, PlatformAMDSevSnp, measurement, roots)
}

// getRootsOfTrust returns the cached roots of trust, fetching them if necessary.
func getRootsOfTrust() (*x509.CertPool, error) {
	rootsMu.Lock()
	defer rootsMu.Unlock()
	if cachedRoots != nil {
		return cachedRoots, nil
	}
	roots, err := fetchRootsOfTrust()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch roots of trust: %w", err)
	}
	cachedRoots = roots
	return cachedRoots, nil
}

// verifyMeasurement verifies that a firmware measurement is endorsed by Google.
func verifyMeasurement(ctx context.Context, platform Platform, measurement []byte, roots *x509.CertPool) (*FirmwareEndorsement, error) {
	if len(measurement) != 48 {
		return nil, fmt.Errorf("measurement must be 48 bytes (SHA-384), got %d", len(measurement))
	}

	// Get the object name using gce-tcb-verifier helpers
	var objectName string
	var techName string
	switch platform {
	case PlatformIntelTDX:
		objectName = extracttdx.GCETcbObjectName(measurement)
		techName = "TDX MRTD"
	case PlatformAMDSevSnp:
		objectName = extractsev.GCETcbObjectName(sev.GCEUefiFamilyID, measurement)
		techName = "SEV-SNP MEASUREMENT"
	default:
		return nil, fmt.Errorf("unsupported platform: %d", platform)
	}

	// Fetch endorsement via HTTP using gce-tcb-verifier URL helper
	url := tcbv.GCETcbURL(objectName)
	endorsementBytes, err := fetchFromURL(ctx, url)
	if err != nil {
		measurementHex := hex.EncodeToString(measurement)
		return nil, fmt.Errorf("%s %s not found in Google's endorsements - firmware not endorsed: %w", techName, measurementHex, err)
	}

	// Verify the endorsement signature and extract info
	return verifyEndorsement(endorsementBytes, measurement, platform, roots)
}

// fetchFromURL fetches data from a URL.
func fetchFromURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// verifyEndorsement verifies the endorsement signature and returns firmware info.
func verifyEndorsement(endorsementBytes, expectedMeasurement []byte, platform Platform, roots *x509.CertPool) (*FirmwareEndorsement, error) {
	endorsement := &epb.VMLaunchEndorsement{}
	if err := proto.Unmarshal(endorsementBytes, endorsement); err != nil {
		return nil, fmt.Errorf("failed to parse endorsement: %w", err)
	}

	opts := &tcbv.Options{
		RootsOfTrust: roots,
		Now:          time.Now(),
	}
	if err := tcbv.EndorsementProto(endorsement, opts); err != nil {
		return nil, fmt.Errorf("endorsement signature verification failed: %w", err)
	}

	golden := &epb.VMGoldenMeasurement{}
	if err := proto.Unmarshal(endorsement.GetSerializedUefiGolden(), golden); err != nil {
		return nil, fmt.Errorf("failed to parse golden measurement: %w", err)
	}

	switch platform {
	case PlatformIntelTDX:
		return extractTdxEndorsement(golden, expectedMeasurement)
	case PlatformAMDSevSnp:
		return extractSevSnpEndorsement(golden, expectedMeasurement)
	default:
		return nil, fmt.Errorf("unsupported platform: %d", platform)
	}
}

// extractTdxEndorsement extracts endorsement info for TDX.
func extractTdxEndorsement(golden *epb.VMGoldenMeasurement, expectedMRTD []byte) (*FirmwareEndorsement, error) {
	tdx := golden.GetTdx()
	if tdx == nil {
		return nil, fmt.Errorf("endorsement does not contain TDX measurements")
	}

	found := false
	for _, measurement := range tdx.GetMeasurements() {
		if bytes.Equal(measurement.GetMrtd(), expectedMRTD) {
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
func extractSevSnpEndorsement(golden *epb.VMGoldenMeasurement, expectedMeasurement []byte) (*FirmwareEndorsement, error) {
	sevsnp := golden.GetSevSnp()
	if sevsnp == nil {
		return nil, fmt.Errorf("endorsement does not contain SEV-SNP measurements")
	}

	found := false
	for _, measurement := range sevsnp.GetMeasurements() {
		if bytes.Equal(measurement, expectedMeasurement) {
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
	resp, err := http.Get(gcetcbendorsement.DefaultRootURL)
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
	if !roots.AppendCertsFromPEM(data) {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse root certificate as PEM or DER: %w", err)
		}
		roots.AddCert(cert)
	}

	return roots, nil
}
