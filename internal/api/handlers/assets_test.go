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
	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newTestDB returns an in-memory SQLite DB with all migrations applied.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.New(config.DatabaseConfig{Driver: "sqlite", FilePath: ":memory:"})
	require.NoError(t, err)
	require.NoError(t, database.Migrate(db))
	return db
}

// injectUser sets up a Gin context that passes middleware.GetUser checks.
func injectUser(c *gin.Context, user *models.User) {
	c.Set(middleware.CtxUserKey, user)
}

// newRouter creates a minimal Gin engine wired to a handler, with an optional
// auth injector middleware so we can simulate authenticated requests.
func newRouter(method, path string, handler gin.HandlerFunc, user *models.User) *gin.Engine {
	r := gin.New()
	r.Handle(method, path, func(c *gin.Context) {
		if user != nil {
			injectUser(c, user)
		}
		handler(c)
	})
	return r
}

// seedOrg creates an org in the DB and returns it.
func seedOrg(t *testing.T, db *gorm.DB) models.Organization {
	t.Helper()
	id := uuid.NewString()
	org := models.Organization{Name: "Test Org " + id, Slug: id}
	require.NoError(t, db.Create(&org).Error)
	return org
}

// seedUser creates a user belonging to the given org.
func seedUser(t *testing.T, db *gorm.DB, orgID uuid.UUID) models.User {
	t.Helper()
	uname := uuid.NewString()
	user := models.User{
		Email:    uname + "@test.com",
		Username: uname,
		OrgID:    orgID,
		Role:     "admin",
	}
	require.NoError(t, db.Create(&user).Error)
	return user
}

// --------------------------------------------------------------------------
// DomainHandler tests
// --------------------------------------------------------------------------

func TestDomainHandler_Create_RequiresName(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)
	log := zap.NewNop().Sugar()
	h := handlers.NewDomainHandler(db, log)

	// Missing required "name" field.
	body, _ := json.Marshal(map[string]string{"status": "active"})
	req := httptest.NewRequest(http.MethodPost, "/domains", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/domains", h.Create, &user)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "Name")
}

func TestDomainHandler_Create_Success(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)
	log := zap.NewNop().Sugar()
	h := handlers.NewDomainHandler(db, log)

	body, _ := json.Marshal(map[string]string{"name": "example.com", "environment": "production"})
	req := httptest.NewRequest(http.MethodPost, "/domains", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/domains", h.Create, &user)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp models.Domain
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "example.com", resp.Name)
	assert.Equal(t, org.ID, resp.OrgID)
}

func TestDomainHandler_Create_Unauthenticated(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	h := handlers.NewDomainHandler(db, log)

	body, _ := json.Marshal(map[string]string{"name": "example.com"})
	req := httptest.NewRequest(http.MethodPost, "/domains", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// No user injected — simulates missing JWT.
	r := newRouter(http.MethodPost, "/domains", h.Create, nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDomainHandler_List_IsolatedByOrg(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()

	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	userA := seedUser(t, db, orgA.ID)

	// Seed a domain for org A and one for org B.
	domA := models.Domain{Base: models.Base{ID: uuid.New()}, OrgID: orgA.ID, Name: "org-a.com"}
	domB := models.Domain{Base: models.Base{ID: uuid.New()}, OrgID: orgB.ID, Name: "org-b.com"}
	require.NoError(t, db.Create(&domA).Error)
	require.NoError(t, db.Create(&domB).Error)

	h := handlers.NewDomainHandler(db, log)
	req := httptest.NewRequest(http.MethodGet, "/domains", nil)
	w := httptest.NewRecorder()

	r := newRouter(http.MethodGet, "/domains", h.List, &userA)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Data  []models.Domain `json:"data"`
		Total int64           `json:"total"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(1), resp.Total)
	assert.Equal(t, "org-a.com", resp.Data[0].Name)
}

func TestDomainHandler_Update_CannotReassignOrg(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	userA := seedUser(t, db, orgA.ID)

	dom := models.Domain{Base: models.Base{ID: uuid.New()}, OrgID: orgA.ID, Name: "mine.com", Status: "active"}
	require.NoError(t, db.Create(&dom).Error)

	h := handlers.NewDomainHandler(db, log)

	// Attempt to smuggle org_id and id through the update body.
	body, _ := json.Marshal(map[string]string{
		"name":   "still-mine.com",
		"org_id": orgB.ID.String(),
		"id":     uuid.New().String(),
	})
	req := httptest.NewRequest(http.MethodPut, "/domains/"+dom.ID.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPut, "/domains/:id", h.Update, &userA)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var fromDB models.Domain
	require.NoError(t, db.First(&fromDB, dom.ID).Error)
	assert.Equal(t, orgA.ID, fromDB.OrgID, "org_id must not be reassignable via Update")
	assert.Equal(t, dom.ID, fromDB.ID, "id must not be reassignable via Update")
	assert.Equal(t, "still-mine.com", fromDB.Name, "allowlisted fields should still update")
}

func TestDomainHandler_Get_NotFoundCrossOrg(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()

	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	userA := seedUser(t, db, orgA.ID)

	// Domain belongs to org B.
	domB := models.Domain{Base: models.Base{ID: uuid.New()}, OrgID: orgB.ID, Name: "secret.com"}
	require.NoError(t, db.Create(&domB).Error)

	h := handlers.NewDomainHandler(db, log)
	req := httptest.NewRequest(http.MethodGet, "/domains/"+domB.ID.String(), nil)
	w := httptest.NewRecorder()

	r := newRouter(http.MethodGet, "/domains/:id", h.Get, &userA)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDomainHandler_Delete_RowsAffected(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	dom := models.Domain{Base: models.Base{ID: uuid.New()}, OrgID: org.ID, Name: "delete-me.com"}
	require.NoError(t, db.Create(&dom).Error)

	h := handlers.NewDomainHandler(db, log)
	req := httptest.NewRequest(http.MethodDelete, "/domains/"+dom.ID.String(), nil)
	w := httptest.NewRecorder()

	r := newRouter(http.MethodDelete, "/domains/:id", h.Delete, &user)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Second delete of same ID → 404 (rows affected = 0).
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodDelete, "/domains/"+dom.ID.String(), nil)
	r.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusNotFound, w2.Code)
}

// --------------------------------------------------------------------------
// HostHandler tests
// --------------------------------------------------------------------------

func TestHostHandler_Create_RequiresIP(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)
	log := zap.NewNop().Sugar()
	h := handlers.NewHostHandler(db, log)

	// Missing required "ip" field.
	body, _ := json.Marshal(map[string]string{"hostname": "no-ip-host"})
	req := httptest.NewRequest(http.MethodPost, "/hosts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/hosts", h.Create, &user)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHostHandler_Create_Success(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)
	log := zap.NewNop().Sugar()
	h := handlers.NewHostHandler(db, log)

	body, _ := json.Marshal(map[string]string{"ip": "192.168.1.1", "hostname": "web-01"})
	req := httptest.NewRequest(http.MethodPost, "/hosts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r := newRouter(http.MethodPost, "/hosts", h.Create, &user)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp models.Host
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "192.168.1.1", resp.IP)
	assert.Equal(t, org.ID, resp.OrgID)
}

func TestHostHandler_List_FilterByProvider(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	hosts := []models.Host{
		{Base: models.Base{ID: uuid.New()}, OrgID: org.ID, IP: "1.1.1.1", Provider: "aws"},
		{Base: models.Base{ID: uuid.New()}, OrgID: org.ID, IP: "2.2.2.2", Provider: "gcp"},
		{Base: models.Base{ID: uuid.New()}, OrgID: org.ID, IP: "3.3.3.3", Provider: "aws"},
	}
	require.NoError(t, db.Create(&hosts).Error)

	h := handlers.NewHostHandler(db, log)
	req := httptest.NewRequest(http.MethodGet, "/hosts?provider=aws", nil)
	w := httptest.NewRecorder()

	r := newRouter(http.MethodGet, "/hosts", h.List, &user)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Total int64 `json:"total"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(2), resp.Total)
}

func TestHostHandler_Get_PreloadsServices(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	host := models.Host{Base: models.Base{ID: uuid.New()}, OrgID: org.ID, IP: "10.0.0.5"}
	require.NoError(t, db.Create(&host).Error)
	svc := models.Service{Base: models.Base{ID: uuid.New()}, OrgID: org.ID, HostID: host.ID, Port: 443, Protocol: "tcp"}
	require.NoError(t, db.Create(&svc).Error)

	h := handlers.NewHostHandler(db, log)
	req := httptest.NewRequest(http.MethodGet, "/hosts/"+host.ID.String(), nil)
	w := httptest.NewRecorder()

	r := newRouter(http.MethodGet, "/hosts/:id", h.Get, &user)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp models.Host
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Services, 1)
	assert.Equal(t, 443, resp.Services[0].Port)
}

// --------------------------------------------------------------------------
// CertificateHandler tests
// --------------------------------------------------------------------------

func TestCertificateHandler_Expiring_RespectsDaysWindow(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	now := time.Now()
	certs := []models.Certificate{
		{Base: models.Base{ID: uuid.New()}, OrgID: org.ID, Subject: "soon.com", Issuer: "CA", Fingerprint: uuid.NewString(), NotAfter: now.AddDate(0, 0, 5)},
		{Base: models.Base{ID: uuid.New()}, OrgID: org.ID, Subject: "later.com", Issuer: "CA", Fingerprint: uuid.NewString(), NotAfter: now.AddDate(0, 0, 90)},
	}
	require.NoError(t, db.Create(&certs).Error)

	h := handlers.NewCertificateHandler(db, log)
	req := httptest.NewRequest(http.MethodGet, "/certificates/expiring?days=30", nil)
	w := httptest.NewRecorder()

	r := newRouter(http.MethodGet, "/certificates/expiring", h.Expiring, &user)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Total int64                `json:"total"`
		Data  []models.Certificate `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(1), resp.Total)
	assert.Equal(t, "soon.com", resp.Data[0].Subject)
}

func TestCertificateHandler_List_IsolatedByOrg(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()

	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	userA := seedUser(t, db, orgA.ID)

	certA := models.Certificate{Base: models.Base{ID: uuid.New()}, OrgID: orgA.ID, Subject: "a.com", Issuer: "CA", Fingerprint: uuid.NewString()}
	certB := models.Certificate{Base: models.Base{ID: uuid.New()}, OrgID: orgB.ID, Subject: "b.com", Issuer: "CA", Fingerprint: uuid.NewString()}
	require.NoError(t, db.Create(&certA).Error)
	require.NoError(t, db.Create(&certB).Error)

	h := handlers.NewCertificateHandler(db, log)
	req := httptest.NewRequest(http.MethodGet, "/certificates", nil)
	w := httptest.NewRecorder()

	r := newRouter(http.MethodGet, "/certificates", h.List, &userA)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Total int64 `json:"total"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(1), resp.Total)
}
