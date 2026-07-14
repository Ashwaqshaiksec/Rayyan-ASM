package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrExpiredToken    = errors.New("token expired")
	ErrRevokedToken    = errors.New("token revoked")
	ErrInvalidPassword = errors.New("invalid password")
	ErrAccountLocked   = errors.New("account locked")
	ErrWeakPassword    = errors.New("password does not meet complexity requirements")
)

// ValidatePasswordComplexity enforces a minimum password policy:
//   - at least 10 characters
//   - at least one uppercase letter
//   - at least one lowercase letter
//   - at least one digit
//   - at least one special character
func ValidatePasswordComplexity(password string) error {
	if len(password) < 10 {
		return fmt.Errorf("%w: minimum 10 characters", ErrWeakPassword)
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= '0' && ch <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if !hasUpper {
		return fmt.Errorf("%w: must contain at least one uppercase letter", ErrWeakPassword)
	}
	if !hasLower {
		return fmt.Errorf("%w: must contain at least one lowercase letter", ErrWeakPassword)
	}
	if !hasDigit {
		return fmt.Errorf("%w: must contain at least one digit", ErrWeakPassword)
	}
	if !hasSpecial {
		return fmt.Errorf("%w: must contain at least one special character", ErrWeakPassword)
	}
	return nil
}

type Claims struct {
	jwt.RegisteredClaims
	UserID    uuid.UUID `json:"uid"`
	OrgID     uuid.UUID `json:"oid"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	TokenType string    `json:"typ"` // access, refresh
}

type Manager struct {
	secret        []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	bcryptCost    int
}

func NewManager(secret string, accessExpiry, refreshExpiry time.Duration, bcryptCost int) *Manager {
	if bcryptCost < bcrypt.DefaultCost {
		bcryptCost = bcrypt.DefaultCost // enforce minimum cost of 10
	}
	return &Manager{
		secret:        []byte(secret),
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		bcryptCost:    bcryptCost,
	}
}

func (m *Manager) GenerateAccessToken(userID, orgID uuid.UUID, email, role string) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.accessExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "rayyan-asm",
			Subject:   userID.String(),
			ID:        uuid.New().String(), // jti — used for revocation
		},
		UserID:    userID,
		OrgID:     orgID,
		Email:     email,
		Role:      role,
		TokenType: "access",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *Manager) GenerateRefreshToken(userID, orgID uuid.UUID, email, role string) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID.String(),
			Issuer:    "rayyan-asm",
			ID:        uuid.New().String(), // jti
		},
		UserID:    userID,
		OrgID:     orgID,
		Email:     email,
		Role:      role,
		TokenType: "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *Manager) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func (m *Manager) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), m.bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (m *Manager) CheckPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// ValidatePasswordComplexity is a convenience method delegating to the package function.
func (m *Manager) ValidatePasswordComplexity(password string) error {
	return ValidatePasswordComplexity(password)
}

// AccessExpirySeconds returns the configured access token lifetime in seconds.
// Use this instead of hardcoding 86400 in responses.
func (m *Manager) AccessExpirySeconds() int {
	return int(m.accessExpiry.Seconds())
}

// GenerateAPIKey returns (fullKey, prefix12, error).
// prefix is stored plaintext for fast DB lookup; fullKey is shown once.
func GenerateAPIKey(length int) (string, string, error) {
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	key := "rayyan_" + base64.URLEncoding.EncodeToString(raw)
	prefix := key[:12]
	return key, prefix, nil
}

// HashAPIKey hashes an API key for storage. We use bcrypt cost 10 which is
// appropriate for API keys (long, random, not user-memorable passwords).
// Note: bcrypt truncates at 72 bytes; our keys are ~50 chars, well within limit.
func HashAPIKey(key string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(key), 10)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckAPIKey(hash, key string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(key)) == nil
}
