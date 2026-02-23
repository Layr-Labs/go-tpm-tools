package teeverify

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestComputeTPMNonce_Length(t *testing.T) {
	nonce := ComputeTPMNonce([]byte("challenge"), []byte("extra"))
	if len(nonce) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(nonce))
	}
}

func TestComputeTPMNonce_Determinism(t *testing.T) {
	challenge := []byte("test-challenge")
	extraData := []byte("test-extra")
	a := ComputeTPMNonce(challenge, extraData)
	b := ComputeTPMNonce(challenge, extraData)
	if !bytes.Equal(a, b) {
		t.Error("same inputs produced different outputs")
	}
}

func TestComputeTPMNonce_NilVsEmptyExtraData(t *testing.T) {
	challenge := []byte("challenge")
	withNil := ComputeTPMNonce(challenge, nil)
	withEmpty := ComputeTPMNonce(challenge, []byte{})
	if !bytes.Equal(withNil, withEmpty) {
		t.Error("nil and empty extraData should produce the same nonce")
	}
}

func TestComputeTPMNonce_InputNotMutated(t *testing.T) {
	challenge := make([]byte, 4)
	copy(challenge, []byte{1, 2, 3, 4})
	orig := make([]byte, 4)
	copy(orig, challenge)

	ComputeTPMNonce(challenge, []byte("extra"))

	if !bytes.Equal(challenge, orig) {
		t.Errorf("challenge was mutated: got %x, want %x", challenge, orig)
	}
}

func TestComputeTPMNonce_GoldenVector(t *testing.T) {
	challenge := []byte{0x01, 0x02, 0x03, 0x04}
	extraData := []byte{0x05, 0x06, 0x07, 0x08}
	got := ComputeTPMNonce(challenge, extraData)
	want, _ := hex.DecodeString("955815d1985340f21234fde19d4a42c3366e2973cfa1cb84ea1b3497917d3600")
	if !bytes.Equal(got, want) {
		t.Errorf("golden vector mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

func TestComputeTPMNonce_GoldenVector_NilExtraData(t *testing.T) {
	challenge := []byte{0x01, 0x02, 0x03, 0x04}
	got := ComputeTPMNonce(challenge, nil)
	want, _ := hex.DecodeString("d68d1b571d26d35fa0e1b61051f7378f488be48c8988804b00e19a2e65c17345")
	if !bytes.Equal(got, want) {
		t.Errorf("golden vector mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

func TestComputeBoundNonce_Length(t *testing.T) {
	nonce := ComputeBoundNonce([]byte("challenge"), []byte("akhash"), []byte("extra"))
	if len(nonce) != 64 {
		t.Errorf("expected 64 bytes, got %d", len(nonce))
	}
}

func TestComputeBoundNonce_Determinism(t *testing.T) {
	challenge := []byte("test-challenge")
	akHash := []byte("test-akhash")
	extraData := []byte("test-extra")
	a := ComputeBoundNonce(challenge, akHash, extraData)
	b := ComputeBoundNonce(challenge, akHash, extraData)
	if !bytes.Equal(a, b) {
		t.Error("same inputs produced different outputs")
	}
}

func TestComputeBoundNonce_NilVsEmptyExtraData(t *testing.T) {
	challenge := []byte("challenge")
	akHash := []byte("akhash")
	withNil := ComputeBoundNonce(challenge, akHash, nil)
	withEmpty := ComputeBoundNonce(challenge, akHash, []byte{})
	if !bytes.Equal(withNil, withEmpty) {
		t.Error("nil and empty extraData should produce the same nonce")
	}
}

func TestComputeBoundNonce_InputNotMutated(t *testing.T) {
	challenge := make([]byte, 4)
	copy(challenge, []byte{1, 2, 3, 4})
	origChallenge := make([]byte, 4)
	copy(origChallenge, challenge)

	akHash := make([]byte, 4)
	copy(akHash, []byte{5, 6, 7, 8})
	origAkHash := make([]byte, 4)
	copy(origAkHash, akHash)

	ComputeBoundNonce(challenge, akHash, []byte("extra"))

	if !bytes.Equal(challenge, origChallenge) {
		t.Errorf("challenge was mutated: got %x, want %x", challenge, origChallenge)
	}
	if !bytes.Equal(akHash, origAkHash) {
		t.Errorf("akHash was mutated: got %x, want %x", akHash, origAkHash)
	}
}

func TestComputeBoundNonce_GoldenVector(t *testing.T) {
	challenge := []byte{0x01, 0x02, 0x03, 0x04}
	akHash := []byte{0x0a, 0x0b, 0x0c, 0x0d}
	extraData := []byte{0x05, 0x06, 0x07, 0x08}
	got := ComputeBoundNonce(challenge, akHash, extraData)
	want, _ := hex.DecodeString("b205f813f5da0b23eae253063a448819249097c4cc23f068194d01218e06d19732a08e0930bad3c2cf6d745da2965957c1229b7c9571b38f28c7bec853a0a547")
	if !bytes.Equal(got, want) {
		t.Errorf("golden vector mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

func TestComputeBoundNonce_GoldenVector_NilExtraData(t *testing.T) {
	challenge := []byte{0x01, 0x02, 0x03, 0x04}
	akHash := []byte{0x0a, 0x0b, 0x0c, 0x0d}
	got := ComputeBoundNonce(challenge, akHash, nil)
	want, _ := hex.DecodeString("290ee7c79ce47a7eb10b0097398f63b9a23a96aefc25354e6b20b044407412c5e3e0e1581ba5a7e053a3098b3a7093260236cd226f95abc2ba1f4a0320953da6")
	if !bytes.Equal(got, want) {
		t.Errorf("golden vector mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}
