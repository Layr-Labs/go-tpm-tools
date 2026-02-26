package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	grafeas "google.golang.org/genproto/googleapis/grafeas/v1"
)

// TestECDSAVerifier_ValidSignature tests that ecdsaVerifier correctly verifies
// a valid ECDSA signature over SHA-256 hashed data.
func TestECDSAVerifier_ValidSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := []byte("test message for DSSE verification")
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	v := &ecdsaVerifier{key: &key.PublicKey, keyID: "test-key"}
	if err := v.Verify(context.Background(), data, sig); err != nil {
		t.Errorf("Verify() returned error for valid signature: %v", err)
	}
}

// TestECDSAVerifier_InvalidSignature tests that ecdsaVerifier rejects
// a signature that doesn't match the data.
func TestECDSAVerifier_InvalidSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Sign one message but verify with different data
	original := []byte("original message")
	hash := sha256.Sum256(original)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	v := &ecdsaVerifier{key: &key.PublicKey, keyID: "test-key"}
	if err := v.Verify(context.Background(), []byte("tampered message"), sig); err == nil {
		t.Error("Verify() should reject signature for tampered data")
	}
}

// TestECDSAVerifier_WrongKey tests that ecdsaVerifier rejects a signature
// created by a different key.
func TestECDSAVerifier_WrongKey(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}

	data := []byte("test message")
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, signingKey, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	v := &ecdsaVerifier{key: &wrongKey.PublicKey, keyID: "wrong-key"}
	if err := v.Verify(context.Background(), data, sig); err == nil {
		t.Error("Verify() should reject signature from wrong key")
	}
}

// TestECDSAVerifier_KeyID tests that KeyID returns the configured key ID.
func TestECDSAVerifier_KeyID(t *testing.T) {
	v := &ecdsaVerifier{keyID: "gcpkms://projects/p/locations/l/keyRings/kr/cryptoKeys/k/cryptoKeyVersions/1"}
	id, err := v.KeyID()
	if err != nil {
		t.Fatalf("KeyID() returned error: %v", err)
	}
	if id != "gcpkms://projects/p/locations/l/keyRings/kr/cryptoKeys/k/cryptoKeyVersions/1" {
		t.Errorf("KeyID() = %q, want full gcpkms:// URI", id)
	}
}

// signGrafeasEnvelope creates a properly signed grafeas.Envelope with raw byte
// fields, matching what Container Analysis returns. This is the format that
// verifyGrafeasEnvelope must convert to dsse.Envelope (base64 strings).
func signGrafeasEnvelope(t *testing.T, key *ecdsa.PrivateKey, keyID, payloadType string, payload []byte) *grafeas.Envelope {
	t.Helper()

	// DSSE PAE over the raw payload (not base64-encoded)
	pae := fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType,
		len(payload), payload)

	hash := sha256.Sum256([]byte(pae))
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign PAE: %v", err)
	}

	return &grafeas.Envelope{
		PayloadType: payloadType,
		Payload:     payload,
		Signatures: []*grafeas.EnvelopeSignature{
			{
				Keyid: keyID,
				Sig:   sig,
			},
		},
	}
}

// TestVerifyGrafeasEnvelope_Valid tests that verifyGrafeasEnvelope correctly
// converts a grafeas envelope (raw bytes) to a dsse envelope (base64) and verifies.
func TestVerifyGrafeasEnvelope_Valid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	keyID := "gcpkms://projects/test/locations/us/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
	payloadType := "application/vnd.in-toto+json"
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.1"}`)

	env := signGrafeasEnvelope(t, key, keyID, payloadType, payload)

	if err := verifyGrafeasEnvelope(context.Background(), env, &key.PublicKey, keyID); err != nil {
		t.Errorf("verifyGrafeasEnvelope() returned error for valid envelope: %v", err)
	}
}

// TestVerifyGrafeasEnvelope_TamperedPayload tests that modifying the raw payload
// bytes after signing causes verification to fail through the conversion path.
func TestVerifyGrafeasEnvelope_TamperedPayload(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	keyID := "test-key"
	env := signGrafeasEnvelope(t, key, keyID, "application/vnd.in-toto+json", []byte(`{"legit":"provenance"}`))

	// Tamper with the raw bytes payload
	env.Payload = []byte(`{"evil":"provenance"}`)

	if err := verifyGrafeasEnvelope(context.Background(), env, &key.PublicKey, keyID); err == nil {
		t.Error("verifyGrafeasEnvelope() should reject envelope with tampered payload")
	}
}

// TestVerifyGrafeasEnvelope_WrongKey tests that verification fails when using
// a different key than the one that signed the grafeas envelope.
func TestVerifyGrafeasEnvelope_WrongKey(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}

	keyID := "test-key"
	env := signGrafeasEnvelope(t, signingKey, keyID, "application/vnd.in-toto+json", []byte(`{}`))

	if err := verifyGrafeasEnvelope(context.Background(), env, &wrongKey.PublicKey, keyID); err == nil {
		t.Error("verifyGrafeasEnvelope() should reject envelope signed by different key")
	}
}

// TestVerifyGrafeasEnvelope_NoSignatures tests that a grafeas envelope with
// no signatures is rejected.
func TestVerifyGrafeasEnvelope_NoSignatures(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	env := &grafeas.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     []byte(`{}`),
		Signatures:  []*grafeas.EnvelopeSignature{},
	}

	if err := verifyGrafeasEnvelope(context.Background(), env, &key.PublicKey, "test-key"); err == nil {
		t.Error("verifyGrafeasEnvelope() should reject envelope with no signatures")
	}
}
