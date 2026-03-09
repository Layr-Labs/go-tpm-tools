package storage

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// Standard BIP39 test mnemonic (12 words, all "abandon" except last).
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// expectedKeyHex is the expected storage key for testMnemonic.
// This is pinned to detect accidental changes to the derivation logic.
// Derived via: BIP39 seed(testMnemonic) → HMAC-SHA256("EIGENX_STORAGE_KEY_DERIVATION_V1", seed)
//
//		var expectedKeyHex = func() string {
//		    key, err := DeriveStorageKey(testMnemonic)
//		    if err != nil {
//	       panic(err)
//		    }
//	     return hex.EncodeToString(key)
//	}()
const expectedKeyHex string = "336d8ebede32d5ebea916c9ea112fecffb6156ffc12a8ac0f497130d5655ce5f"

func TestDeriveStorageKey_Deterministic(t *testing.T) {
	// Derive twice from the same mnemonic and verify identical output.
	key1, err := DeriveStorageKey(testMnemonic)
	if err != nil {
		t.Fatalf("first derivation failed: %v", err)
	}
	key2, err := DeriveStorageKey(testMnemonic)
	if err != nil {
		t.Fatalf("second derivation failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Errorf("keys differ: %x != %x", key1, key2)
	}
}

func TestDeriveStorageKey_Stable(t *testing.T) {
	// Verify the output matches the pinned expected value.
	key, err := DeriveStorageKey(testMnemonic)
	if err != nil {
		t.Fatalf("derivation failed: %v", err)
	}
	got := hex.EncodeToString(key)
	fmt.Println("expectedKeyHex", expectedKeyHex)
	if got != expectedKeyHex {
		t.Errorf("key changed: got %s, want %s", got, expectedKeyHex)
	}
}

func TestDeriveStorageKey_DifferentMnemonics(t *testing.T) {
	mnemonic2 := "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

	key1, err := DeriveStorageKey(testMnemonic)
	if err != nil {
		t.Fatalf("first derivation failed: %v", err)
	}
	key2, err := DeriveStorageKey(mnemonic2)
	if err != nil {
		t.Fatalf("second derivation failed: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("different mnemonics produced the same key")
	}
}

func TestDeriveStorageKey_KeyLength(t *testing.T) {
	key, err := DeriveStorageKey(testMnemonic)
	if err != nil {
		t.Fatalf("derivation failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d bytes, want 32", len(key))
	}
}

func TestDeriveStorageKey_EmptyMnemonic(t *testing.T) {
	_, err := DeriveStorageKey("")
	if err == nil {
		t.Fatal("expected error for empty mnemonic, got nil")
	}
}

func TestDeriveStorageKey_InvalidMnemonic(t *testing.T) {
	// Wrong words (not in BIP39 wordlist).
	_, err := DeriveStorageKey("foo bar baz qux quux corge grault garply waldo fred plugh xyzzy")
	if err == nil {
		t.Fatal("expected error for invalid mnemonic, got nil")
	}

	// Valid words but bad checksum.
	_, err = DeriveStorageKey("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")
	if err == nil {
		t.Fatal("expected error for bad checksum mnemonic, got nil")
	}
}
