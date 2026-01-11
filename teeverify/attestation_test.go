package teeverify

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// testVector contains a test attestation with its expected inputs
type testVector struct {
	Attestation []byte // decoded pb.Attestation
	Nonce       []byte // decoded nonce
	UserData    []byte // decoded user data
}

// testCase contains a named test case with TDX and SEV-SNP attestations
type testCase struct {
	Name     string
	Hardened bool
	TDX      testVector
	SevSnp   testVector
}

type testCaseJSON struct {
	Name     string         `json:"name"`
	Hardened bool           `json:"hardened"`
	TDX      testVectorJSON `json:"tdx"`
	SevSnp   testVectorJSON `json:"sevsnp"`
}

type testVectorJSON struct {
	Attestation string `json:"attestation"` // base64-encoded
	Nonce       string `json:"nonce"`       // hex-encoded
	UserData    string `json:"user_data"`   // hex-encoded
}

// loadTestCases loads all test cases from testdata/attestations.json
func loadTestCases(t *testing.T) []testCase {
	t.Helper()

	data, err := os.ReadFile("testdata/attestations.json")
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	var casesJSON []testCaseJSON
	if err := json.Unmarshal(data, &casesJSON); err != nil {
		t.Fatalf("failed to parse test data: %v", err)
	}

	cases := make([]testCase, len(casesJSON))
	for i, cj := range casesJSON {
		cases[i].Name = cj.Name
		cases[i].Hardened = cj.Hardened

		// Decode TDX
		cases[i].TDX.Attestation, err = base64.StdEncoding.DecodeString(cj.TDX.Attestation)
		if err != nil {
			t.Fatalf("case %q: failed to decode TDX attestation: %v", cj.Name, err)
		}
		cases[i].TDX.Nonce, err = hex.DecodeString(cj.TDX.Nonce)
		if err != nil {
			t.Fatalf("case %q: failed to decode TDX nonce: %v", cj.Name, err)
		}
		cases[i].TDX.UserData, err = hex.DecodeString(cj.TDX.UserData)
		if err != nil {
			t.Fatalf("case %q: failed to decode TDX user data: %v", cj.Name, err)
		}

		// Decode SEV-SNP
		cases[i].SevSnp.Attestation, err = base64.StdEncoding.DecodeString(cj.SevSnp.Attestation)
		if err != nil {
			t.Fatalf("case %q: failed to decode SEV-SNP attestation: %v", cj.Name, err)
		}
		cases[i].SevSnp.Nonce, err = hex.DecodeString(cj.SevSnp.Nonce)
		if err != nil {
			t.Fatalf("case %q: failed to decode SEV-SNP nonce: %v", cj.Name, err)
		}
		cases[i].SevSnp.UserData, err = hex.DecodeString(cj.SevSnp.UserData)
		if err != nil {
			t.Fatalf("case %q: failed to decode SEV-SNP user data: %v", cj.Name, err)
		}
	}

	return cases
}

// =============================================================================
// TDX Verification Tests
// =============================================================================

func TestVerifyTDXAttestation(t *testing.T) {
	for _, tc := range loadTestCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			verified, err := VerifyAttestation(tc.TDX.Attestation, tc.TDX.Nonce)
			if err != nil {
				t.Fatalf("VerifyAttestation failed: %v", err)
			}

			if verified.Platform != PlatformTDX {
				t.Errorf("expected platform TDX, got %v", verified.Platform)
			}

			if !userDataEqual(verified.UserData, tc.TDX.UserData) {
				t.Errorf("UserData mismatch:\n  got:  %x\n  want: %x", verified.UserData, tc.TDX.UserData)
			}
		})
	}
}

func TestVerifyTDXAttestation_WrongNonce(t *testing.T) {
	cases := loadTestCases(t)
	if len(cases) == 0 {
		t.Fatal("no test cases found")
	}
	tdx := cases[0].TDX

	// Use wrong nonce (all zeros)
	wrongNonce := make([]byte, 32)

	_, err := VerifyAttestation(tdx.Attestation, wrongNonce)
	if err == nil {
		t.Fatal("expected error with wrong nonce, got nil")
	}

	// Should fail on binding mismatch
	if !contains(err.Error(), "binding mismatch") && !contains(err.Error(), "mismatch") {
		t.Errorf("expected binding mismatch error, got: %v", err)
	}
}

func TestVerifyTDXAttestation_EmptyNonce(t *testing.T) {
	cases := loadTestCases(t)
	if len(cases) == 0 {
		t.Fatal("no test cases found")
	}
	tdx := cases[0].TDX

	_, err := VerifyAttestation(tdx.Attestation, nil)
	if err == nil {
		t.Fatal("expected error with empty nonce, got nil")
	}
}

// =============================================================================
// SEV-SNP Verification Tests
// =============================================================================

func TestVerifySevSnpAttestation(t *testing.T) {
	for _, tc := range loadTestCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			verified, err := VerifyAttestation(tc.SevSnp.Attestation, tc.SevSnp.Nonce)
			if err != nil {
				t.Fatalf("VerifyAttestation failed: %v", err)
			}

			if verified.Platform != PlatformSevSnp {
				t.Errorf("expected platform SEV-SNP, got %v", verified.Platform)
			}

			if !userDataEqual(verified.UserData, tc.SevSnp.UserData) {
				t.Errorf("UserData mismatch:\n  got:  %x\n  want: %x", verified.UserData, tc.SevSnp.UserData)
			}
		})
	}
}

func TestVerifySevSnpAttestation_WrongNonce(t *testing.T) {
	cases := loadTestCases(t)
	if len(cases) == 0 {
		t.Fatal("no test cases found")
	}
	sevsnp := cases[0].SevSnp

	// Use wrong nonce (all zeros)
	wrongNonce := make([]byte, 32)

	_, err := VerifyAttestation(sevsnp.Attestation, wrongNonce)
	if err == nil {
		t.Fatal("expected error with wrong nonce, got nil")
	}

	if !contains(err.Error(), "binding mismatch") && !contains(err.Error(), "mismatch") {
		t.Errorf("expected binding mismatch error, got: %v", err)
	}
}

// =============================================================================
// TDX Claim Extraction Tests
// =============================================================================

func TestExtractTDXClaims(t *testing.T) {
	for _, tc := range loadTestCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			verified, err := VerifyAttestation(tc.TDX.Attestation, tc.TDX.Nonce)
			if err != nil {
				t.Fatalf("VerifyAttestation failed: %v", err)
			}

			claims, err := verified.ExtractClaims(ExtractOptions{
				PCRIndices: []uint32{0, 4, 8, 9},
			})
			if err != nil {
				t.Fatalf("ExtractClaims failed: %v", err)
			}

			// Verify platform
			if claims.Platform != PlatformTDX {
				t.Errorf("expected platform TDX, got %v", claims.Platform)
			}

			// Verify TDX claims exist
			if claims.TDX == nil {
				t.Fatal("expected TDX claims, got nil")
			}

			// Verify MRTD is non-zero
			if isZero(claims.TDX.MRTD[:]) {
				t.Error("expected non-zero MRTD")
			}

			// Verify RTMRs (at least RTMR0 should be non-zero for a running TD)
			if isZero(claims.TDX.RTMR0[:]) && isZero(claims.TDX.RTMR1[:]) &&
				isZero(claims.TDX.RTMR2[:]) && isZero(claims.TDX.RTMR3[:]) {
				t.Error("expected at least one non-zero RTMR")
			}

			// Verify TeeTcbSvn is present
			if isZero(claims.TDX.TeeTcbSvn[:]) {
				t.Error("expected non-zero TeeTcbSvn")
			}

			// Production attestation should not be in debug mode
			if claims.TDX.Attributes.Debug {
				t.Error("expected Debug=false for production attestation")
			}

			// Verify Hardened flag matches expected value
			if claims.Hardened != tc.Hardened {
				t.Errorf("Hardened mismatch: got %v, want %v", claims.Hardened, tc.Hardened)
			}

			// Verify PCRs were extracted
			if len(claims.PCRs) != 4 {
				t.Errorf("expected 4 PCRs, got %d", len(claims.PCRs))
			}
			for _, idx := range []uint32{0, 4, 8, 9} {
				pcr, ok := claims.PCRs[idx]
				if !ok {
					t.Errorf("PCR %d not found", idx)
					continue
				}
				if isZero(pcr[:]) {
					t.Errorf("PCR %d is zero", idx)
				}
			}

			// Log container and GCE info if present (informational)
			if claims.Container != nil {
				t.Logf("Container: %s@%s", claims.Container.ImageReference, claims.Container.ImageDigest)
			}
			if claims.GCE != nil {
				t.Logf("GCE: project=%s zone=%s instance=%s",
					claims.GCE.ProjectID, claims.GCE.Zone, claims.GCE.InstanceName)
			}
		})
	}
}

// =============================================================================
// SEV-SNP Claim Extraction Tests
// =============================================================================

func TestExtractSevSnpClaims(t *testing.T) {
	for _, tc := range loadTestCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			verified, err := VerifyAttestation(tc.SevSnp.Attestation, tc.SevSnp.Nonce)
			if err != nil {
				t.Fatalf("VerifyAttestation failed: %v", err)
			}

			claims, err := verified.ExtractClaims(ExtractOptions{
				PCRIndices: []uint32{0, 4, 8, 9},
			})
			if err != nil {
				t.Fatalf("ExtractClaims failed: %v", err)
			}

			// Verify platform
			if claims.Platform != PlatformSevSnp {
				t.Errorf("expected platform SEV-SNP, got %v", claims.Platform)
			}

			// Verify SEV-SNP claims exist
			if claims.SevSnp == nil {
				t.Fatal("expected SEV-SNP claims, got nil")
			}

			// Verify Measurement is non-zero
			if isZero(claims.SevSnp.Measurement[:]) {
				t.Error("expected non-zero Measurement")
			}

			// Production attestation should not be in debug mode
			if claims.SevSnp.Policy.Debug {
				t.Error("expected Debug=false for production attestation")
			}

			// Verify Hardened flag matches expected value
			if claims.Hardened != tc.Hardened {
				t.Errorf("Hardened mismatch: got %v, want %v", claims.Hardened, tc.Hardened)
			}

			// Verify TCB fields (at least one should be non-zero)
			if claims.SevSnp.CurrentTcb == 0 && claims.SevSnp.ReportedTcb == 0 {
				t.Error("expected non-zero TCB values")
			}

			// Verify PCRs were extracted
			if len(claims.PCRs) != 4 {
				t.Errorf("expected 4 PCRs, got %d", len(claims.PCRs))
			}

			// Log container and GCE info if present
			if claims.Container != nil {
				t.Logf("Container: %s@%s", claims.Container.ImageReference, claims.Container.ImageDigest)
			}
			if claims.GCE != nil {
				t.Logf("GCE: project=%s zone=%s instance=%s",
					claims.GCE.ProjectID, claims.GCE.Zone, claims.GCE.InstanceName)
			}
		})
	}
}

// =============================================================================
// PCR Extraction Tests
// =============================================================================

func TestExtractPCRs_ValidIndices(t *testing.T) {
	cases := loadTestCases(t)
	if len(cases) == 0 {
		t.Fatal("no test cases found")
	}
	tdx := cases[0].TDX

	verified, err := VerifyAttestation(tdx.Attestation, tdx.Nonce)
	if err != nil {
		t.Fatalf("VerifyAttestation failed: %v", err)
	}

	// Request multiple valid PCR indices
	claims, err := verified.ExtractClaims(ExtractOptions{
		PCRIndices: []uint32{0, 4, 8, 9, 14},
	})
	if err != nil {
		t.Fatalf("ExtractClaims failed: %v", err)
	}

	// Verify all requested PCRs are present
	for _, idx := range []uint32{0, 4, 8, 9, 14} {
		if _, ok := claims.PCRs[idx]; !ok {
			t.Errorf("PCR %d not found", idx)
		}
	}
}

func TestExtractPCRs_InvalidIndex(t *testing.T) {
	cases := loadTestCases(t)
	if len(cases) == 0 {
		t.Fatal("no test cases found")
	}
	tdx := cases[0].TDX

	verified, err := VerifyAttestation(tdx.Attestation, tdx.Nonce)
	if err != nil {
		t.Fatalf("VerifyAttestation failed: %v", err)
	}

	// Request invalid PCR index (24 is invalid, max is 23)
	_, err = verified.ExtractClaims(ExtractOptions{
		PCRIndices: []uint32{24},
	})
	if err == nil {
		t.Fatal("expected error for invalid PCR index, got nil")
	}

	if !contains(err.Error(), "invalid PCR index") {
		t.Errorf("expected 'invalid PCR index' error, got: %v", err)
	}
}

// =============================================================================
// Negative Tests
// =============================================================================

func TestVerifyAttestation_InvalidProto(t *testing.T) {
	// Garbage bytes that are not valid protobuf
	garbage := []byte("this is not a valid protobuf message")

	_, err := VerifyAttestation(garbage, make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for invalid proto, got nil")
	}

	if !contains(err.Error(), "parse") && !contains(err.Error(), "unmarshal") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestVerifyAttestation_EmptyAttestation(t *testing.T) {
	// Empty but valid protobuf (no TDX or SEV-SNP attestation)
	emptyProto := []byte{}

	_, err := VerifyAttestation(emptyProto, make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for empty attestation, got nil")
	}

	if !contains(err.Error(), "no TEE attestation found") {
		t.Errorf("expected 'no TEE attestation found' error, got: %v", err)
	}
}

func TestVerifyAttestation_NilAttestation(t *testing.T) {
	_, err := VerifyAttestation(nil, make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for nil attestation, got nil")
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// userDataEqual compares user data, treating all-zeros as equivalent to empty.
func userDataEqual(got, want []byte) bool {
	return bytes.Equal(got, want) || (len(want) == 0 && isZero(got))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
