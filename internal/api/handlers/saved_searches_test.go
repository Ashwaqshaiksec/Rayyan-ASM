package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSavedSearch_CreateAndList(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	h := handlers.NewSavedSearchHandler(db, zap.NewNop().Sugar())

	createR := newRouter("POST", "/saved-searches", h.Create, &user)
	body, _ := json.Marshal(map[string]string{"name": "Critical internet-facing", "query": "severity:critical type:findings"})
	req := httptest.NewRequest("POST", "/saved-searches", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	createR.ServeHTTP(w, req)
	require.Equal(t, 201, w.Code)

	listR := newRouter("GET", "/saved-searches", h.List, &user)
	req2 := httptest.NewRequest("GET", "/saved-searches", nil)
	w2 := httptest.NewRecorder()
	listR.ServeHTTP(w2, req2)
	require.Equal(t, 200, w2.Code)

	var resp struct {
		Data []models.SavedSearch `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 1)
	require.Equal(t, "Critical internet-facing", resp.Data[0].Name)
	require.Equal(t, "severity:critical type:findings", resp.Data[0].Query)
}

func TestSavedSearch_DeleteRequiresOwnership(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	owner := seedUser(t, db, org.ID)
	other := seedUser(t, db, org.ID)

	s := models.SavedSearch{OrgID: org.ID, UserID: owner.ID, Name: "mine", Query: "port:22"}
	require.NoError(t, db.Create(&s).Error)

	h := handlers.NewSavedSearchHandler(db, zap.NewNop().Sugar())

	// A different user in the same org should not be able to delete
	// someone else's saved search.
	r := newRouter("DELETE", "/saved-searches/:id", h.Delete, &other)
	req := httptest.NewRequest("DELETE", "/saved-searches/"+s.ID.String(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, 404, w.Code)

	// The owner can.
	r2 := newRouter("DELETE", "/saved-searches/:id", h.Delete, &owner)
	req2 := httptest.NewRequest("DELETE", "/saved-searches/"+s.ID.String(), nil)
	w2 := httptest.NewRecorder()
	r2.ServeHTTP(w2, req2)
	require.Equal(t, 200, w2.Code)
}

func TestSavedSearch_UseBumpsCount(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	s := models.SavedSearch{OrgID: org.ID, UserID: user.ID, Name: "mine", Query: "port:22"}
	require.NoError(t, db.Create(&s).Error)

	h := handlers.NewSavedSearchHandler(db, zap.NewNop().Sugar())
	r := newRouter("POST", "/saved-searches/:id/use", h.Use, &user)
	req := httptest.NewRequest("POST", "/saved-searches/"+s.ID.String()+"/use", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, 200, w.Code)

	var reloaded models.SavedSearch
	require.NoError(t, db.First(&reloaded, "id = ?", s.ID).Error)
	require.Equal(t, 1, reloaded.UseCount)
}
