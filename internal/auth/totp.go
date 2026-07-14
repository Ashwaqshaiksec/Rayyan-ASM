package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const totpDigits = 6
const totpPeriod = 30

// GenerateTOTPSecret returns a random 20-byte base32-encoded secret suitable
// for use with any RFC 6238-compliant authenticator app.
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// TOTPUri returns the otpauth:// URI used to generate QR codes for authenticator
// apps (Google Authenticator, Authy, 1Password, etc.).
func TOTPUri(secret, email, issuer string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		url.PathEscape(issuer),
		url.PathEscape(email),
		secret,
		url.QueryEscape(issuer),
		totpDigits,
		totpPeriod,
	)
}

// ValidateTOTP checks whether code matches the current or adjacent time window
// for secret, providing ±30s clock drift tolerance.
func ValidateTOTP(secret, code string) bool {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return false
	}
	now := time.Now().Unix() / int64(totpPeriod)
	for _, counter := range []int64{now - 1, now, now + 1} {
		if computeHOTP(key, uint64(counter)) == code {
			return true
		}
	}
	return false
}

func computeHOTP(key []byte, counter uint64) string {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	code := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
	otp := int(code) % int(math.Pow10(totpDigits))
	return fmt.Sprintf("%0*d", totpDigits, otp)
}
