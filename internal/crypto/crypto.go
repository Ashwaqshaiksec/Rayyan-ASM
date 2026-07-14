// Package crypto provides AES-256-GCM encryption helpers used to protect
// sensitive material at rest, such as external tool credentials
// (internal/modules/toolrunner/tools/smb_creds.go).
//
// The encryption key is provided out-of-band via RAYYAN_AUTH_CREDENTIALKEY
// (config: Auth.CredentialKey) and is never persisted to the database or
// logged. It must be exactly 32 bytes once decoded, suitable for AES-256.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// ErrInvalidKeyLength is returned when the supplied key does not decode to
// exactly 32 bytes (required for AES-256).
var ErrInvalidKeyLength = errors.New("crypto: key must be 32 bytes for AES-256")

// ErrCiphertextTooShort is returned when a ciphertext is shorter than the
// GCM nonce size and therefore cannot be valid.
var ErrCiphertextTooShort = errors.New("crypto: ciphertext too short")

// DecodeKey decodes a key supplied as either base64 or hex and validates
// that it is 32 bytes long (AES-256). Plain 32-byte raw strings are also
// accepted as a last resort.
func DecodeKey(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("crypto: empty key")
	}

	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(s) == 32 {
		return []byte(s), nil
	}
	return nil, ErrInvalidKeyLength
}

// Encrypt encrypts plaintext with AES-256-GCM using the given 32-byte key.
// The returned string is base64-encoded and contains the nonce prepended to
// the ciphertext.
func Encrypt(key, plaintext []byte) (string, error) {
	if len(key) != 32 {
		return "", ErrInvalidKeyLength
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("crypto: new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("crypto: new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: read nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt reverses Encrypt using the given 32-byte key.
func Decrypt(key []byte, encoded string) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("crypto: base64 decode: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return plaintext, nil
}
