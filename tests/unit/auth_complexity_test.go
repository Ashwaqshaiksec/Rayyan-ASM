package unit_test

import (
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePasswordComplexity(t *testing.T) {
	tests := []struct {
		name    string
		pw      string
		wantErr bool
		errMsg  string
	}{
		{"too short", "Abc1!", true, "minimum 10 characters"},
		{"no uppercase", "abcdefgh1!", true, "uppercase"},
		{"no lowercase", "ABCDEFGH1!", true, "lowercase"},
		{"no digit", "Abcdefgh!!", true, "digit"},
		{"no special", "Abcdefgh12", true, "special character"},
		{"valid strong", "MyStr0ng!Pass", false, ""},
		{"valid with symbols", "P@ssw0rd#2024", false, ""},
		{"min length exactly 10", "Abcde1!xyz", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.ValidatePasswordComplexity(tt.pw)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBcryptMinCost(t *testing.T) {
	// Manager with cost below 10 should be raised to 10
	mgr := auth.NewManager("test-secret-32-bytes-long-enough!", 15*60*1000000000, 7*24*60*60*1000000000, 4)
	hash, err := mgr.HashPassword("MyStr0ng!Pass")
	require.NoError(t, err)
	// Verify the hash works
	require.NoError(t, mgr.CheckPassword(hash, "MyStr0ng!Pass"))
	assert.Error(t, mgr.CheckPassword(hash, "WrongPassword1!"))
}
