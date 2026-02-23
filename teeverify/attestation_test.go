package teeverify

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	attestpb "github.com/Layr-Labs/go-tpm-tools/proto/attest"
	tpmpb "github.com/Layr-Labs/go-tpm-tools/proto/tpm"
	"google.golang.org/protobuf/proto"
)

// testVector contains a decoded test attestation with its expected inputs.
type testVector struct {
	Name        string
	Platform    string
	Hardened    bool
	Attestation []byte // decoded pb.Attestation
	Challenge   []byte // decoded challenge
	ExtraData   []byte // decoded extra data (nil if empty)
}

type testVectorJSON struct {
	Name        string `json:"name"`
	Platform    string `json:"platform"`
	Hardened    bool   `json:"hardened"`
	Attestation string `json:"attestation"` // base64
	Challenge   string `json:"challenge"`   // hex
	ExtraData   string `json:"extra_data"`  // hex
}

// loadTestVectors loads all test vectors from testdata/attestations.json.
// Returns nil if the file doesn't exist or contains an empty array.
func loadTestVectors(t *testing.T) []testVector {
	t.Helper()

	data, err := os.ReadFile("testdata/attestations.json")
	if err != nil {
		return nil
	}

	var raw []testVectorJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse test data: %v", err)
	}
	if len(raw) == 0 {
		return nil
	}

	vectors := make([]testVector, len(raw))
	for i, r := range raw {
		vectors[i].Name = r.Name
		vectors[i].Platform = r.Platform
		vectors[i].Hardened = r.Hardened

		vectors[i].Attestation, err = base64.StdEncoding.DecodeString(r.Attestation)
		if err != nil {
			t.Fatalf("vector %q: failed to decode attestation: %v", r.Name, err)
		}
		vectors[i].Challenge, err = hex.DecodeString(r.Challenge)
		if err != nil {
			t.Fatalf("vector %q: failed to decode challenge: %v", r.Name, err)
		}
		if r.ExtraData != "" {
			vectors[i].ExtraData, err = hex.DecodeString(r.ExtraData)
			if err != nil {
				t.Fatalf("vector %q: failed to decode extra data: %v", r.Name, err)
			}
		}
	}

	return vectors
}

// expectedPlatform maps platform strings to Platform constants.
func expectedPlatform(s string) Platform {
	switch s {
	case "intel_tdx":
		return PlatformIntelTDX
	case "amd_sev_snp":
		return PlatformAMDSevSnp
	case "gcp_shielded_vm":
		return PlatformGCPShieldedVM
	default:
		return PlatformUnknown
	}
}

// =============================================================================
// Verification Tests
// =============================================================================

func TestVerifyBoundAttestation(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			verified, err := VerifyBoundAttestation(v.Attestation, v.Challenge, v.ExtraData)
			if err != nil {
				t.Fatalf("VerifyBoundAttestation failed: %v", err)
			}

			want := expectedPlatform(v.Platform)
			if verified.Platform != want {
				t.Errorf("platform mismatch: got %v, want %v", verified.Platform, want)
			}
		})
	}
}

func TestVerifyBoundAttestation_WrongChallenge(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	v := vectors[0]
	wrongChallenge := make([]byte, 32) // all zeros

	_, err := VerifyBoundAttestation(v.Attestation, wrongChallenge, v.ExtraData)
	if err == nil {
		t.Fatal("expected error with wrong challenge, got nil")
	}
	if !contains(err.Error(), "mismatch") {
		t.Errorf("expected mismatch error, got: %v", err)
	}
}

func TestVerifyBoundAttestation_NilChallenge(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	v := vectors[0]
	_, err := VerifyBoundAttestation(v.Attestation, nil, v.ExtraData)
	if err == nil {
		t.Fatal("expected error with nil challenge, got nil")
	}
}

// =============================================================================
// Claim Extraction Tests
// =============================================================================

func TestExtractClaims(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			verified, err := VerifyBoundAttestation(v.Attestation, v.Challenge, v.ExtraData)
			if err != nil {
				t.Fatalf("VerifyBoundAttestation failed: %v", err)
			}

			claims, err := verified.ExtractClaims(ExtractOptions{
				PCRIndices: []uint32{0, 4, 8, 9},
			})
			if err != nil {
				t.Fatalf("ExtractClaims failed: %v", err)
			}

			// Platform should match
			want := expectedPlatform(v.Platform)
			if claims.Platform != want {
				t.Errorf("platform mismatch: got %v, want %v", claims.Platform, want)
			}

			// Hardened flag should match
			if claims.Hardened != v.Hardened {
				t.Errorf("hardened mismatch: got %v, want %v", claims.Hardened, v.Hardened)
			}

			// Platform-specific claims
			switch want {
			case PlatformIntelTDX:
				if claims.TDX == nil {
					t.Fatal("expected TDX claims, got nil")
				}
				if claims.SevSnp != nil {
					t.Error("unexpected SEV-SNP claims on TDX vector")
				}
			case PlatformAMDSevSnp:
				if claims.SevSnp == nil {
					t.Fatal("expected SEV-SNP claims, got nil")
				}
				if claims.TDX != nil {
					t.Error("unexpected TDX claims on SEV-SNP vector")
				}
			case PlatformGCPShieldedVM:
				if claims.TDX != nil {
					t.Error("unexpected TDX claims on Shielded VM vector")
				}
				if claims.SevSnp != nil {
					t.Error("unexpected SEV-SNP claims on Shielded VM vector")
				}
			}

			// PCRs should be extracted
			if len(claims.PCRs) != 4 {
				t.Errorf("expected 4 PCRs, got %d", len(claims.PCRs))
			}
			for _, idx := range []uint32{0, 4, 8, 9} {
				if _, ok := claims.PCRs[idx]; !ok {
					t.Errorf("PCR %d not found", idx)
				}
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

func TestExtractClaims_InvalidPCRIndex(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	v := vectors[0]
	verified, err := VerifyBoundAttestation(v.Attestation, v.Challenge, v.ExtraData)
	if err != nil {
		t.Fatalf("VerifyBoundAttestation failed: %v", err)
	}

	// PCR index 24 is invalid (max is 23)
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

func TestVerifyBoundAttestation_InvalidProto(t *testing.T) {
	garbage := []byte("this is not a valid protobuf message")

	_, err := VerifyBoundAttestation(garbage, make([]byte, 32), nil)
	if err == nil {
		t.Fatal("expected error for invalid proto, got nil")
	}

	if !contains(err.Error(), "parse") && !contains(err.Error(), "unmarshal") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestVerifyBoundAttestation_ShieldedVM(t *testing.T) {
	// Construct a minimal TPM-only attestation (no TDX or SEV-SNP).
	// This should be detected as PlatformGCPShieldedVM and proceed past
	// platform detection. It will fail at TPM signature verification
	// (since we use dummy data), but should NOT fail with "no TEE attestation found".
	attestation := &attestpb.Attestation{
		AkCert: []byte("dummy-ak-cert"),
		Quotes: []*tpmpb.Quote{
			{Quote: []byte("dummy-quote")},
		},
	}
	attestationBytes, err := proto.Marshal(attestation)
	if err != nil {
		t.Fatalf("failed to marshal attestation: %v", err)
	}

	_, err = VerifyBoundAttestation(attestationBytes, make([]byte, 32), nil)
	if err == nil {
		t.Fatal("expected error (dummy data), got nil")
	}

	// Should NOT fail with "no TEE attestation found" — it should get past platform detection.
	if contains(err.Error(), "no TEE attestation found") {
		t.Errorf("Shielded VM attestation was rejected as unknown platform: %v", err)
	}
}

func TestVerifyBoundAttestation_EmptyAttestation(t *testing.T) {
	emptyProto := []byte{}

	_, err := VerifyBoundAttestation(emptyProto, make([]byte, 32), nil)
	if err == nil {
		t.Fatal("expected error for empty attestation, got nil")
	}

	if !contains(err.Error(), "no TEE attestation found") {
		t.Errorf("expected 'no TEE attestation found' error, got: %v", err)
	}
}

func TestVerifyBoundAttestation_NilAttestation(t *testing.T) {
	_, err := VerifyBoundAttestation(nil, make([]byte, 32), nil)
	if err == nil {
		t.Fatal("expected error for nil attestation, got nil")
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

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
