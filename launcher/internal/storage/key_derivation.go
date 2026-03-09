package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
)

// storageKeyDST is the domain separation tag for storage key derivation.
// It ensures the derived key is cryptographically independent from keys
// derived for other purposes (e.g. EVM/Solana addresses) from the same mnemonic.
// The _V1 suffix allows rotating to a new derivation scheme in the future.
const storageKeyDST = "EIGENX_STORAGE_KEY_DERIVATION_V1"

// DeriveStorageKey derives a 256-bit storage encryption key from a BIP39 mnemonic.
//
// The derivation:
//  1. BIP39: mnemonic → 64-byte seed via PBKDF2(mnemonic, "mnemonic", 2048, SHA-512)
//  2. HMAC-SHA256(key=DST, data=seed) → 32-byte key
//
// The caller is responsible for zeroing the returned key bytes after use.
func DeriveStorageKey(mnemonic string) ([]byte, error) {
	if mnemonic == "" {
		return nil, fmt.Errorf("mnemonic must not be empty")
	}

	// Validate BIP39: word count, wordlist membership, and checksum.
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid BIP39 mnemonic")
	}

	// BIP39: mnemonic → 64-byte seed.
	seed := pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New)
	defer ZeroBytes(seed)

	// HMAC-SHA256 with domain separation tag to produce a 32-byte key.
	h := hmac.New(sha256.New, []byte(storageKeyDST))
	h.Write(seed)
	return h.Sum(nil), nil
}

// ZeroBytes overwrites a byte slice with zeros to remove sensitive material
// from memory. This is a best-effort defense-in-depth measure.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
