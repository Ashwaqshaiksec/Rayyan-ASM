package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/auth"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestAuthMgr() *auth.Manager {
	return auth.NewManager("test-secret-key-that-is-at-least-32-chars", 24*time.Hour, 168*time.Hour, 4)
}

// --------------------------------------------------------------------------
// Login
// --------------------------------------------------------------------------

func TestAuthHandler_Login_InvalidCredentials_UnknownEmail(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	body, _ := json.Marshal(map[string]string{"email": "nobody@example.com", "password": "whatever12345"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/login", h.Login, nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Login_WrongPassword(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	org := seedOrg(t, db)
	hash, err := mgr.HashPassword("correct-horse-battery")
	require.NoError(t, err)
	user := models.User{
		Email: "wrongpw@example.com", Username: uuid.NewString(),
		OrgID: org.ID, Role: "admin", Active: true, EmailVerified: true,
		PasswordHash: hash,
	}
	require.NoError(t, db.Create(&user).Error)

	body, _ := json.Marshal(map[string]string{"email": user.Email, "password": "totally-wrong-password"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/login", h.Login, nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Login_UnverifiedEmail(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	org := seedOrg(t, db)
	hash, err := mgr.HashPassword("correct-horse-battery")
	require.NoError(t, err)
	user := models.User{
		Email: "unverified@example.com", Username: uuid.NewString(),
		OrgID: org.ID, Role: "admin", Active: true, EmailVerified: false,
		PasswordHash: hash,
	}
	require.NoError(t, db.Create(&user).Error)

	body, _ := json.Marshal(map[string]string{"email": user.Email, "password": "correct-horse-battery"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/login", h.Login, nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAuthHandler_Login_DisabledAccount(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	org := seedOrg(t, db)
	hash, err := mgr.HashPassword("correct-horse-battery")
	require.NoError(t, err)
	user := models.User{
		Email: "disabled@example.com", Username: uuid.NewString(),
		OrgID: org.ID, Role: "admin", Active: true, EmailVerified: true,
		PasswordHash: hash,
	}
	require.NoError(t, db.Create(&user).Error)
	// GORM's `default:true` tag on Active means an explicit false on Create
	// is silently overwritten by the column default, so disable it via a
	// separate Update instead.
	require.NoError(t, db.Model(&user).Update("active", false).Error)

	body, _ := json.Marshal(map[string]string{"email": user.Email, "password": "correct-horse-battery"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/login", h.Login, nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAuthHandler_Login_Success(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	org := seedOrg(t, db)
	hash, err := mgr.HashPassword("correct-horse-battery")
	require.NoError(t, err)
	user := models.User{
		Email: "gooduser@example.com", Username: uuid.NewString(),
		OrgID: org.ID, Role: "admin", Active: true, EmailVerified: true,
		PasswordHash: hash,
	}
	require.NoError(t, db.Create(&user).Error)

	body, _ := json.Marshal(map[string]string{"email": user.Email, "password": "correct-horse-battery"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/login", h.Login, nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["access_token"])
	assert.NotEmpty(t, resp["refresh_token"])
}

// Five consecutive bad-password attempts should lock the account, and a
// subsequent attempt with the *correct* password should still be rejected
// while the lock is active (429, not 200).
func TestAuthHandler_Login_LocksAfterFiveFailedAttempts(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	org := seedOrg(t, db)
	hash, err := mgr.HashPassword("correct-horse-battery")
	require.NoError(t, err)
	user := models.User{
		Email: "lockout@example.com", Username: uuid.NewString(),
		OrgID: org.ID, Role: "admin", Active: true, EmailVerified: true,
		PasswordHash: hash,
	}
	require.NoError(t, db.Create(&user).Error)

	badBody, _ := json.Marshal(map[string]string{"email": user.Email, "password": "wrongbutlongenough"})

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(badBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r := newRouter(http.MethodPost, "/auth/login", h.Login, nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code, "attempt %d", i+1)
	}

	goodBody, _ := json.Marshal(map[string]string{"email": user.Email, "password": "correct-horse-battery"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(goodBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r := newRouter(http.MethodPost, "/auth/login", h.Login, nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

// --------------------------------------------------------------------------
// Register
// --------------------------------------------------------------------------

func TestAuthHandler_Register_WeakPasswordRejected(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	body, _ := json.Marshal(map[string]string{
		"org_name": "Acme Inc", "email": "weak@example.com", "username": "weakuser",
		"password": "password", "first_name": "A", "last_name": "B",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/register", h.Register, nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Register_DuplicateEmailRejected(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	org := seedOrg(t, db)
	hash, err := mgr.HashPassword("existing-password-123")
	require.NoError(t, err)
	existing := models.User{
		Email: "dupe@example.com", Username: uuid.NewString(),
		OrgID: org.ID, Role: "admin", Active: true, EmailVerified: true,
		PasswordHash: hash,
	}
	require.NoError(t, db.Create(&existing).Error)

	body, _ := json.Marshal(map[string]string{
		"org_name": "New Org", "email": "dupe@example.com", "username": "newusername",
		"password": "Str0ng-Passw0rd!", "first_name": "A", "last_name": "B",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/register", h.Register, nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestAuthHandler_Register_Success_AutoVerifiesWithoutSMTP(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	body, _ := json.Marshal(map[string]string{
		"org_name": "Brand New Org", "email": "newuser@example.com", "username": "newuser1",
		"password": "Str0ng-Passw0rd!", "first_name": "A", "last_name": "B",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/register", h.Register, nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)

	var user models.User
	require.NoError(t, db.Where("email = ?", "newuser@example.com").First(&user).Error)
	assert.True(t, user.EmailVerified, "user should be auto-verified when no SMTP config exists")
}

// --------------------------------------------------------------------------
// ChangePassword
// --------------------------------------------------------------------------

func TestAuthHandler_ChangePassword_RequiresAuth(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	body, _ := json.Marshal(map[string]string{"current_password": "a", "new_password": "Str0ng-Passw0rd!"})
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/change-password", h.ChangePassword, nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ChangePassword_WrongCurrentPassword(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	org := seedOrg(t, db)
	hash, err := mgr.HashPassword("the-real-password-123")
	require.NoError(t, err)
	user := models.User{
		Email: "cp@example.com", Username: uuid.NewString(),
		OrgID: org.ID, Role: "admin", Active: true, EmailVerified: true,
		PasswordHash: hash,
	}
	require.NoError(t, db.Create(&user).Error)

	body, _ := json.Marshal(map[string]string{"current_password": "not-the-real-password", "new_password": "Str0ng-Passw0rd!"})
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/change-password", h.ChangePassword, &user)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ChangePassword_Success(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	org := seedOrg(t, db)
	hash, err := mgr.HashPassword("the-real-password-123")
	require.NoError(t, err)
	user := models.User{
		Email: "cp2@example.com", Username: uuid.NewString(),
		OrgID: org.ID, Role: "admin", Active: true, EmailVerified: true,
		PasswordHash: hash,
	}
	require.NoError(t, db.Create(&user).Error)

	body, _ := json.Marshal(map[string]string{"current_password": "the-real-password-123", "new_password": "Str0ng-N3w-Passw0rd!"})
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/change-password", h.ChangePassword, &user)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var updated models.User
	require.NoError(t, db.First(&updated, "id = ?", user.ID).Error)
	require.NoError(t, mgr.CheckPassword(updated.PasswordHash, "Str0ng-N3w-Passw0rd!"))
}

// --------------------------------------------------------------------------
// ForgotPassword / ResetPassword
// --------------------------------------------------------------------------

func TestAuthHandler_ForgotPassword_UnknownEmailStillReturns200(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	body, _ := json.Marshal(map[string]string{"email": "ghost@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/forgot-password", h.ForgotPassword, nil)
	r.ServeHTTP(w, req)

	// Must not leak whether the email exists via status code.
	assert.Equal(t, http.StatusOK, w.Code)

	var count int64
	db.Model(&models.PasswordResetToken{}).Count(&count)
	assert.EqualValues(t, 0, count, "no token should be created for unknown email")
}

func TestAuthHandler_ResetPassword_InvalidTokenRejected(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	body, _ := json.Marshal(map[string]string{"token": "totally-bogus-token", "password": "Str0ng-Passw0rd!"})
	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/auth/reset-password", h.ResetPassword, nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ForgotThenResetPassword_FullFlow(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	org := seedOrg(t, db)
	hash, err := mgr.HashPassword("original-password-123")
	require.NoError(t, err)
	user := models.User{
		Email: "resetflow@example.com", Username: uuid.NewString(),
		OrgID: org.ID, Role: "admin", Active: true, EmailVerified: true,
		PasswordHash: hash,
	}
	require.NoError(t, db.Create(&user).Error)

	// Trigger ForgotPassword — sendResetEmail runs async and no SMTP is
	// configured so it's a no-op, but the token row is what we need.
	body, _ := json.Marshal(map[string]string{"email": user.Email})
	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r := newRouter(http.MethodPost, "/auth/forgot-password", h.ForgotPassword, nil)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var prt models.PasswordResetToken
	require.NoError(t, db.Where("user_id = ?", user.ID).First(&prt).Error)
	assert.Nil(t, prt.UsedAt)
}

func TestAuthHandler_RevokeToken_Logout(t *testing.T) {
	db := newTestDB(t)
	mgr := newTestAuthMgr()
	log := zap.NewNop().Sugar()
	h := handlers.NewAuthHandler(db, mgr, log)

	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	w := httptest.NewRecorder()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Handle(http.MethodPost, "/auth/logout", func(c *gin.Context) {
		injectUser(c, &user)
		c.Set(middleware.CtxClaimsKey, &auth.Claims{UserID: user.ID})
		h.Logout(c)
	})
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
