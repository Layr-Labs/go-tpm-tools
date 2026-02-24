package attest

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/Layr-Labs/go-tpm-tools/internal/nonce"
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

	data, err := os.ReadFile("../testdata/attestations.json")
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
// Parse Tests
// =============================================================================

func TestParse(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			att, err := Parse(v.Attestation)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			want := expectedPlatform(v.Platform)
			if att.Platform() != want {
				t.Errorf("platform mismatch: got %s, want %s", att.Platform().PlatformTag(), want.PlatformTag())
			}
		})
	}
}

func TestParse_InvalidProto(t *testing.T) {
	garbage := []byte("this is not a valid protobuf message")

	_, err := Parse(garbage)
	if err == nil {
		t.Fatal("expected error for invalid proto, got nil")
	}

	if !contains(err.Error(), "parse") && !contains(err.Error(), "unmarshal") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestParse_EmptyAttestation(t *testing.T) {
	_, err := Parse([]byte{})
	if err == nil {
		t.Fatal("expected error for empty attestation, got nil")
	}

	if !contains(err.Error(), "unknown platform") {
		t.Errorf("expected 'unknown platform' error, got: %v", err)
	}
}

func TestParse_NilAttestation(t *testing.T) {
	_, err := Parse(nil)
	if err == nil {
		t.Fatal("expected error for nil attestation, got nil")
	}
}

// =============================================================================
// VerifyTPM Tests
// =============================================================================

func TestVerifyTPM(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			att, err := Parse(v.Attestation)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			tpmResult, err := att.VerifyTPM(v.Challenge, v.ExtraData)
			if err != nil {
				t.Fatalf("VerifyTPM failed: %v", err)
			}

			want := expectedPlatform(v.Platform)
			if tpmResult.Platform != want {
				t.Errorf("platform mismatch: got %s, want %s", tpmResult.Platform.PlatformTag(), want.PlatformTag())
			}
		})
	}
}

func TestVerifyTPM_WrongChallenge(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	v := vectors[0]
	att, err := Parse(v.Attestation)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	wrongChallenge := make([]byte, 32) // all zeros
	_, err = att.VerifyTPM(wrongChallenge, v.ExtraData)
	if err == nil {
		t.Fatal("expected error with wrong challenge, got nil")
	}
	if !contains(err.Error(), "mismatch") {
		t.Errorf("expected mismatch error, got: %v", err)
	}
}

// =============================================================================
// VerifyBoundTEE Tests
// =============================================================================

func TestVerifyBoundTEE(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			att, err := Parse(v.Attestation)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			want := expectedPlatform(v.Platform)

			teeResult, err := att.VerifyBoundTEE(v.Challenge, v.ExtraData)
			if want == PlatformGCPShieldedVM {
				if err == nil {
					t.Fatal("expected error for Shielded VM, got nil")
				}
				if !contains(err.Error(), "not available") {
					t.Errorf("expected 'not available' error, got: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("VerifyBoundTEE failed: %v", err)
			}
			if teeResult.Platform != want {
				t.Errorf("platform mismatch: got %s, want %s", teeResult.Platform.PlatformTag(), want.PlatformTag())
			}
		})
	}
}

// =============================================================================
// Claim Extraction Tests
// =============================================================================

func TestExtractTPMClaims(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			att, err := Parse(v.Attestation)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			tpmResult, err := att.VerifyTPM(v.Challenge, v.ExtraData)
			if err != nil {
				t.Fatalf("VerifyTPM failed: %v", err)
			}

			claims, err := tpmResult.ExtractTPMClaims(ExtractOptions{
				PCRIndices: []uint32{0, 4, 8, 9},
			})
			if err != nil {
				t.Fatalf("ExtractTPMClaims failed: %v", err)
			}

			// Platform should match
			want := expectedPlatform(v.Platform)
			if claims.Platform != want {
				t.Errorf("platform mismatch: got %s, want %s", claims.Platform.PlatformTag(), want.PlatformTag())
			}

			// Hardened flag should match
			if claims.Hardened != v.Hardened {
				t.Errorf("hardened mismatch: got %v, want %v", claims.Hardened, v.Hardened)
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

			// Log GCE info if present
			if claims.GCE != nil {
				t.Logf("GCE: project=%s zone=%s instance=%s",
					claims.GCE.ProjectID, claims.GCE.Zone, claims.GCE.InstanceName)
			}
		})
	}
}

func TestExtractTEEClaims(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			att, err := Parse(v.Attestation)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			want := expectedPlatform(v.Platform)
			if want == PlatformGCPShieldedVM {
				t.Skip("no TEE claims for Shielded VM")
			}

			teeResult, err := att.VerifyBoundTEE(v.Challenge, v.ExtraData)
			if err != nil {
				t.Fatalf("VerifyBoundTEE failed: %v", err)
			}

			teeClaims, err := teeResult.ExtractTEEClaims()
			if err != nil {
				t.Fatalf("ExtractTEEClaims failed: %v", err)
			}

			if teeClaims.Platform != want {
				t.Errorf("platform mismatch: got %s, want %s", teeClaims.Platform.PlatformTag(), want.PlatformTag())
			}

			switch want {
			case PlatformIntelTDX:
				if teeClaims.TDX == nil {
					t.Fatal("expected TDX claims, got nil")
				}
				if teeClaims.SevSnp != nil {
					t.Error("unexpected SEV-SNP claims on TDX vector")
				}
			case PlatformAMDSevSnp:
				if teeClaims.SevSnp == nil {
					t.Fatal("expected SEV-SNP claims, got nil")
				}
				if teeClaims.TDX != nil {
					t.Error("unexpected TDX claims on SEV-SNP vector")
				}
			}
		})
	}
}

func TestExtractTEEClaims_ShieldedVMFails(t *testing.T) {
	// ExtractTEEClaims should fail for non-TEE platforms.
	// VerifyBoundTEE already rejects Shielded VM, so reaching
	// ExtractTEEClaims with it is a programming error.
	vta := &VerifiedTEEAttestation{
		Platform:    PlatformGCPShieldedVM,
		attestation: &attestpb.Attestation{},
	}

	_, err := vta.ExtractTEEClaims()
	if err == nil {
		t.Fatal("expected error for Shielded VM ExtractTEEClaims, got nil")
	}
	if !contains(err.Error(), "no TEE claims available") {
		t.Errorf("expected 'no TEE claims available' error, got: %v", err)
	}
}

func TestExtractTPMClaims_InvalidPCRIndex(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	v := vectors[0]
	att, err := Parse(v.Attestation)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	tpmResult, err := att.VerifyTPM(v.Challenge, v.ExtraData)
	if err != nil {
		t.Fatalf("VerifyTPM failed: %v", err)
	}

	// PCR index 24 is invalid (max is 23)
	_, err = tpmResult.ExtractTPMClaims(ExtractOptions{
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
// Anti-Downgrade Tests
// =============================================================================

func TestVerifyTPM_StrippedTEEQuote_FailsNonceMismatch(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	for _, v := range vectors {
		want := expectedPlatform(v.Platform)
		if want == PlatformGCPShieldedVM {
			continue // already a Shielded VM, nothing to strip
		}

		t.Run(v.Name, func(t *testing.T) {
			// Deserialize the real attestation.
			var attestation attestpb.Attestation
			if err := proto.Unmarshal(v.Attestation, &attestation); err != nil {
				t.Fatalf("failed to unmarshal attestation: %v", err)
			}

			// Strip the TEE quote so detectPlatform falls back to Shielded VM.
			attestation.TeeAttestation = nil

			stripped, err := proto.Marshal(&attestation)
			if err != nil {
				t.Fatalf("failed to re-marshal stripped attestation: %v", err)
			}

			att, err := Parse(stripped)
			if err != nil {
				t.Fatalf("Parse failed on stripped attestation: %v", err)
			}
			if att.Platform() != PlatformGCPShieldedVM {
				t.Fatalf("expected Shielded VM after stripping, got %s", att.Platform().PlatformTag())
			}

			// VerifyTPM must fail: the TPM quote was signed with the original
			// platform tag, but we now compute the nonce with GCP_SHIELDED_VM.
			_, err = att.VerifyTPM(v.Challenge, v.ExtraData)
			if err == nil {
				t.Fatal("expected VerifyTPM to fail after stripping TEE quote, got nil")
			}
			if !contains(err.Error(), "mismatch") {
				t.Errorf("expected nonce mismatch error, got: %v", err)
			}
		})
	}
}

// =============================================================================
// Shielded VM Tests
// =============================================================================

func TestShieldedVM_ParseSucceeds(t *testing.T) {
	// Construct a minimal TPM-only attestation (no TDX or SEV-SNP).
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

	att, err := Parse(attestationBytes)
	if err != nil {
		t.Fatalf("Parse should succeed for Shielded VM: %v", err)
	}
	if att.Platform() != PlatformGCPShieldedVM {
		t.Errorf("expected Shielded VM platform, got %s", att.Platform().PlatformTag())
	}
}

func TestShieldedVM_VerifyBoundTEE_Fails(t *testing.T) {
	// Construct a minimal TPM-only attestation.
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

	att, err := Parse(attestationBytes)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	_, err = att.VerifyBoundTEE(make([]byte, 32), nil)
	if err == nil {
		t.Fatal("expected error for Shielded VM VerifyBoundTEE, got nil")
	}
	if !contains(err.Error(), "not available") {
		t.Errorf("expected 'not available' error, got: %v", err)
	}
}

// =============================================================================
// PlatformTag Tests
// =============================================================================

func TestPlatformTag(t *testing.T) {
	tests := []struct {
		platform Platform
		wantTag  string
	}{
		{PlatformIntelTDX, nonce.PlatformTagIntelTDX},
		{PlatformAMDSevSnp, nonce.PlatformTagAMDSevSnp},
		{PlatformGCPShieldedVM, nonce.PlatformTagGCPShieldedVM},
	}

	for _, tt := range tests {
		t.Run(tt.wantTag, func(t *testing.T) {
			if got := tt.platform.PlatformTag(); got != tt.wantTag {
				t.Errorf("PlatformTag() = %q, want %q", got, tt.wantTag)
			}
		})
	}
}

func TestPlatformTag_UnknownPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for PlatformUnknown, got none")
		}
	}()
	PlatformUnknown.PlatformTag()
}

// =============================================================================
// Container Claims from Canonical Event Log
// =============================================================================

func TestExtractContainerClaims(t *testing.T) {
	vectors := loadTestVectors(t)
	if len(vectors) == 0 {
		t.Skip("no test vectors")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			// Check if this attestation has a canonical event log.
			var raw attestpb.Attestation
			if err := proto.Unmarshal(v.Attestation, &raw); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			cel := raw.GetCanonicalEventLog()
			if len(cel) == 0 {
				t.Skip("no canonical event log in this test vector")
			}

			att, err := Parse(v.Attestation)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			container, err := att.ExtractContainerClaims()
			if err != nil {
				t.Fatalf("ExtractContainerClaims failed: %v", err)
			}

			if container == nil {
				t.Fatal("expected container claims from canonical event log, got nil")
			}
			if container.ImageReference == "" {
				t.Error("expected non-empty ImageReference")
			}
			if container.ImageDigest == "" {
				t.Error("expected non-empty ImageDigest")
			}
			t.Logf("Container: ref=%s digest=%s", container.ImageReference, container.ImageDigest)
		})
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
