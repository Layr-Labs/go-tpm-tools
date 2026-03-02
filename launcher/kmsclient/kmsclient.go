// Package kmsclient provides an in-process attestation provider and a convenience
// function for retrieving a BIP39 mnemonic from the EigenX KMS.
//
// The mnemonic is highly sensitive — it is used to derive disk encryption keys.
// This package takes care to never log its value and to zero intermediate buffers
// containing key material after use.
package kmsclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Layr-Labs/eigenx-kms/pkg/envclient"
	"github.com/Layr-Labs/go-tpm-tools/launcher/agent"
	"github.com/Layr-Labs/go-tpm-tools/launcher/spec"
	"google.golang.org/protobuf/proto"
)

// InProcessAttestationProvider implements envclient.AttestationProvider by
// calling attestAgent.BoundAttestationEvidence() directly, rather than going
// through the teeserver Unix socket. This is more efficient and removes the
// dependency on the teeserver being ready.
type InProcessAttestationProvider struct {
	attestAgent agent.AttestationAgent
}

// NewInProcessAttestationProvider creates a provider that wraps the given
// attestation agent for in-process attestation generation.
func NewInProcessAttestationProvider(attestAgent agent.AttestationAgent) *InProcessAttestationProvider {
	return &InProcessAttestationProvider{attestAgent: attestAgent}
}

// GetAttestation generates bound attestation evidence using the in-process
// attestation agent and returns it as protobuf-encoded bytes — the same format
// that the teeserver's /v1/bound_evidence endpoint returns.
func (p *InProcessAttestationProvider) GetAttestation(ctx context.Context, challenge []byte) ([]byte, error) {
	if len(challenge) == 0 {
		return nil, fmt.Errorf("challenge must not be empty")
	}

	attestation, err := p.attestAgent.BoundAttestationEvidence(agent.BoundAttestationOpts{
		Challenge: challenge,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate bound attestation evidence: %w", err)
	}

	attestBytes, err := proto.Marshal(attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation to protobuf: %w", err)
	}

	return attestBytes, nil
}

// zeroBytes overwrites a byte slice with zeros to remove sensitive material
// from memory. This is a best-effort defense-in-depth measure.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GetMnemonicFromKMS retrieves a BIP39 mnemonic from the EigenX KMS using
// in-process attestation. The mnemonic is sensitive and must not be logged.
//
// The flow:
//  1. Decode the base64-encoded KMS signing public key from the launch spec.
//  2. Create an in-process attestation provider wrapping the attestAgent.
//  3. Use the envclient to perform the /env/v3 protocol (RSA key generation,
//     attestation, request, signature verification, JWE decryption).
//  4. Extract the MNEMONIC from the decrypted environment variables.
//  5. Zero intermediate sensitive buffers.
func GetMnemonicFromKMS(ctx context.Context, launchSpec spec.LaunchSpec, attestAgent agent.AttestationAgent) (string, error) {
	// Decode the base64-encoded KMS signing public key.
	kmsSigningPublicKeyBytes, err := base64.StdEncoding.DecodeString(launchSpec.KMSSigningPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode KMS signing public key from base64: %w", err)
	}

	provider := NewInProcessAttestationProvider(attestAgent)

	// The envclient expects *slog.Logger. The launcher sets slog.Default() to
	// write to the serial console (see logging.go), so this integrates with
	// the existing logging infrastructure.
	envClient := envclient.NewEnvClient(slog.Default(), provider, kmsSigningPublicKeyBytes, launchSpec.KMSServerURL, launchSpec.KMSUserAPIURL)

	envJSONBytes, err := envClient.GetEnv(ctx)
	if err != nil {
		return "", fmt.Errorf("envclient.GetEnv failed: %w", err)
	}
	// Zero the raw env JSON after parsing — it contains the mnemonic in plaintext.
	defer zeroBytes(envJSONBytes)

	kmsEnv := make(map[string]string)
	if err := json.Unmarshal(envJSONBytes, &kmsEnv); err != nil {
		return "", fmt.Errorf("failed to unmarshal KMS env response: %w", err)
	}

	mnemonic, ok := kmsEnv["MNEMONIC"]
	if !ok {
		return "", fmt.Errorf("KMS response missing required MNEMONIC field")
	}
	if mnemonic == "" {
		return "", fmt.Errorf("KMS response contains empty MNEMONIC")
	}

	return mnemonic, nil
}
