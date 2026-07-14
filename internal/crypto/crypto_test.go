package crypto_test

import (
	"strings"
	"testing"

	crypto "github.com/ShadooowX/rayyan-asm/internal/crypto"
	"github.com/stretchr/testify/require"
)

// testKey returns a valid 32-byte AES-256 key.
func testKey() []byte {
	return []byte("12345678901234567890123456789012") // exactly 32 bytes
}

// wrongKey returns a different valid 32-byte key.
func wrongKey() []byte {
	return []byte("99999999999999999999999999999999")
}

// ── round-trip ────────────────────────────────────────────────────────────────

func TestEncryptDecrypt_ShortPayload(t *testing.T) {
	key := testKey()
	plain := []byte("hi")
	ct, err := crypto.Encrypt(key, plain)
	require.NoError(t, err)
	got, err := crypto.Decrypt(key, ct)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

func TestEncryptDecrypt_MediumPayload(t *testing.T) {
	key := testKey()
	plain := []byte(strings.Repeat("abcdefghij", 100)) // 1 000 bytes
	ct, err := crypto.Encrypt(key, plain)
	require.NoError(t, err)
	got, err := crypto.Decrypt(key, ct)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

func TestEncryptDecrypt_UnicodePayload(t *testing.T) {
	key := testKey()
	plain := []byte("こんにちは世界 🔐 مرحبا")
	ct, err := crypto.Encrypt(key, plain)
	require.NoError(t, err)
	got, err := crypto.Decrypt(key, ct)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

// ── error cases ───────────────────────────────────────────────────────────────

func TestDecrypt_WrongKey_ReturnsError(t *testing.T) {
	ct, err := crypto.Encrypt(testKey(), []byte("secret"))
	require.NoError(t, err)
	_, err = crypto.Decrypt(wrongKey(), ct)
	require.Error(t, err)
}

func TestDecrypt_TruncatedCiphertext_ReturnsError(t *testing.T) {
	ct, err := crypto.Encrypt(testKey(), []byte("secret"))
	require.NoError(t, err)
	// Truncate to fewer bytes than the GCM nonce size (12 bytes) by trimming
	// the base64 string down — the decoded bytes will be too short.
	truncated := ct[:4]
	_, err = crypto.Decrypt(testKey(), truncated)
	require.Error(t, err)
}

func TestDecrypt_EmptyInput_ReturnsError(t *testing.T) {
	_, err := crypto.Decrypt(testKey(), "")
	require.Error(t, err)
}

// ── nonce randomness ──────────────────────────────────────────────────────────

func TestEncrypt_SamePlaintext_DifferentCiphertexts(t *testing.T) {
	key := testKey()
	plain := []byte("same input every time")
	ct1, err := crypto.Encrypt(key, plain)
	require.NoError(t, err)
	ct2, err := crypto.Encrypt(key, plain)
	require.NoError(t, err)
	require.NotEqual(t, ct1, ct2, "two Encrypt calls on same plaintext must produce different ciphertexts (nonce randomness)")
}
