package kmsclient

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/Layr-Labs/go-tpm-tools/cel"
	"github.com/Layr-Labs/go-tpm-tools/launcher/agent"
	attestpb "github.com/Layr-Labs/go-tpm-tools/proto/attest"
	"github.com/Layr-Labs/go-tpm-tools/verifier"
	"google.golang.org/protobuf/proto"
)

// fakeAttestationAgent implements agent.AttestationAgent for testing.
type fakeAttestationAgent struct {
	boundAttestationEvidenceFunc func(opts agent.BoundAttestationOpts) (*attestpb.Attestation, error)
}

func (f *fakeAttestationAgent) MeasureEvent(_ cel.Content) error { return nil }
func (f *fakeAttestationAgent) Refresh(_ context.Context) error  { return nil }
func (f *fakeAttestationAgent) Close() error                     { return nil }
func (f *fakeAttestationAgent) Attest(_ context.Context, _ agent.AttestAgentOpts) ([]byte, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (f *fakeAttestationAgent) AttestWithClient(_ context.Context, _ agent.AttestAgentOpts, _ verifier.Client) ([]byte, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (f *fakeAttestationAgent) BoundAttestationEvidence(opts agent.BoundAttestationOpts) (*attestpb.Attestation, error) {
	if f.boundAttestationEvidenceFunc != nil {
		return f.boundAttestationEvidenceFunc(opts)
	}
	return nil, fmt.Errorf("unimplemented")
}

func TestInProcessAttestationProvider(t *testing.T) {
	// Create a fake attestation with known fields.
	fakeAttestation := &attestpb.Attestation{
		AkPub:             []byte("fake-ak-pub"),
		EventLog:          []byte("fake-event-log"),
		CanonicalEventLog: []byte("fake-cel"),
		AkCert:            []byte("fake-ak-cert"),
	}

	var capturedChallenge []byte
	fakeAgent := &fakeAttestationAgent{
		boundAttestationEvidenceFunc: func(opts agent.BoundAttestationOpts) (*attestpb.Attestation, error) {
			capturedChallenge = opts.Challenge
			return fakeAttestation, nil
		},
	}

	provider := NewInProcessAttestationProvider(fakeAgent)

	challenge := []byte("test-challenge-bytes")
	result, err := provider.GetAttestation(context.Background(), challenge)
	if err != nil {
		t.Fatalf("GetAttestation returned unexpected error: %v", err)
	}

	// Verify the challenge was passed through correctly.
	if !bytes.Equal(capturedChallenge, challenge) {
		t.Errorf("challenge mismatch: got %v, want %v", capturedChallenge, challenge)
	}

	// Verify the result is valid protobuf that can be unmarshaled back.
	var decoded attestpb.Attestation
	if err := proto.Unmarshal(result, &decoded); err != nil {
		t.Fatalf("failed to unmarshal protobuf result: %v", err)
	}

	if !bytes.Equal(decoded.AkPub, fakeAttestation.AkPub) {
		t.Errorf("AkPub mismatch: got %v, want %v", decoded.AkPub, fakeAttestation.AkPub)
	}
	if !bytes.Equal(decoded.EventLog, fakeAttestation.EventLog) {
		t.Errorf("EventLog mismatch: got %v, want %v", decoded.EventLog, fakeAttestation.EventLog)
	}
	if !bytes.Equal(decoded.CanonicalEventLog, fakeAttestation.CanonicalEventLog) {
		t.Errorf("CanonicalEventLog mismatch: got %v, want %v", decoded.CanonicalEventLog, fakeAttestation.CanonicalEventLog)
	}
	if !bytes.Equal(decoded.AkCert, fakeAttestation.AkCert) {
		t.Errorf("AkCert mismatch: got %v, want %v", decoded.AkCert, fakeAttestation.AkCert)
	}
}

func TestInProcessAttestationProvider_EmptyChallenge(t *testing.T) {
	fakeAgent := &fakeAttestationAgent{}
	provider := NewInProcessAttestationProvider(fakeAgent)

	_, err := provider.GetAttestation(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil challenge, got nil")
	}

	_, err = provider.GetAttestation(context.Background(), []byte{})
	if err == nil {
		t.Fatal("expected error for empty challenge, got nil")
	}
}

func TestInProcessAttestationProvider_AgentError(t *testing.T) {
	agentErr := fmt.Errorf("TPM device unavailable")
	fakeAgent := &fakeAttestationAgent{
		boundAttestationEvidenceFunc: func(_ agent.BoundAttestationOpts) (*attestpb.Attestation, error) {
			return nil, agentErr
		},
	}

	provider := NewInProcessAttestationProvider(fakeAgent)

	_, err := provider.GetAttestation(context.Background(), []byte("challenge"))
	if err == nil {
		t.Fatal("expected error from agent, got nil")
	}
	// Verify the original error is wrapped.
	if !bytes.Contains([]byte(err.Error()), []byte("TPM device unavailable")) {
		t.Errorf("expected error to contain 'TPM device unavailable', got: %v", err)
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte("sensitive-data-1234")
	original := make([]byte, len(data))
	copy(original, data)

	zeroBytes(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("byte at index %d not zeroed: got %d", i, b)
		}
	}

	// Sanity check: original data was non-zero.
	allZero := true
	for _, b := range original {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("original data was all zeros — test is invalid")
	}
}
