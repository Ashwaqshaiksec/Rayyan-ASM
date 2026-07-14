package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

func TestProjectCRUD(t *testing.T) {
	token := setupOrgUser(t, "ProjOrg", "proj@org.com", "projuser")

	// Create
	resp, data := do("POST", "/api/v1/projects", map[string]interface{}{
		"name":        "Q4 Audit",
		"description": "Quarterly security audit",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	projID := data["id"].(string)
	assert.Equal(t, "Q4 Audit", data["name"])

	// Get
	resp, data = do("GET", "/api/v1/projects/"+projID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, projID, data["id"])

	// List
	respList, listData := do("GET", "/api/v1/projects", nil, token)
	require.Equal(t, http.StatusOK, respList.StatusCode)
	items, _ := listData["data"].([]interface{})
	assert.Len(t, items, 1)

	// Update
	resp, data = do("PUT", "/api/v1/projects/"+projID, map[string]interface{}{
		"name": "Q4 Audit (Updated)",
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	// Verify
	_, data = do("GET", "/api/v1/projects/"+projID, nil, token)
	assert.Equal(t, "Q4 Audit (Updated)", data["name"])

	// Delete
	resp, _ = do("DELETE", "/api/v1/projects/"+projID, nil, token)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	_, listData = do("GET", "/api/v1/projects", nil, token)
	items, _ = listData["data"].([]interface{})
	assert.Len(t, items, 0)
}

func TestProjectRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/projects", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------

func TestNotesCRUD(t *testing.T) {
	token := setupOrgUser(t, "NoteOrg", "note@org.com", "noteuser")

	resp, data := do("POST", "/api/v1/notes", map[string]interface{}{
		"title":   "Finding Note",
		"content": "Discovered open RDP port on 203.0.113.1",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	noteID := data["id"].(string)

	resp, data = do("GET", "/api/v1/notes/"+noteID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Finding Note", data["title"])

	resp, data = do("PUT", "/api/v1/notes/"+noteID, map[string]interface{}{
		"content": "Updated content",
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	resp, _ = do("DELETE", "/api/v1/notes/"+noteID, nil, token)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestNotesRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/notes", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Todos
// ---------------------------------------------------------------------------

func TestTodoCRUD(t *testing.T) {
	token := setupOrgUser(t, "TodoOrg", "todo@org.com", "todouser")

	resp, data := do("POST", "/api/v1/todos", map[string]interface{}{
		"title":    "Patch nginx",
		"priority": "high",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	todoID := data["id"].(string)
	assert.Equal(t, "Patch nginx", data["title"])
	assert.Equal(t, "open", data["status"])

	// Mark done
	resp, data = do("PUT", "/api/v1/todos/"+todoID, map[string]interface{}{
		"status": "done",
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	resp, data = do("GET", "/api/v1/todos/"+todoID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "done", data["status"])

	// Delete
	resp, _ = do("DELETE", "/api/v1/todos/"+todoID, nil, token)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestTodosRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/todos", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Notification configs
// ---------------------------------------------------------------------------

func TestNotificationConfigCRUD(t *testing.T) {
	token := setupOrgUser(t, "NotifOrg", "notif@org.com", "notifuser")

	resp, data := do("POST", "/api/v1/notifications", map[string]interface{}{
		"name":        "Slack Alerts",
		"channel":     "slack",
		"webhook_url": "https://hooks.slack.com/services/T000/B000/xxx",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	cfgID := data["id"].(string)

	respList, items := doList("GET", "/api/v1/notifications", nil, token)
	require.Equal(t, http.StatusOK, respList.StatusCode)
	assert.Len(t, items, 1)

	// Update
	resp, data = do("PUT", "/api/v1/notifications/"+cfgID, map[string]interface{}{
		"active": false,
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	// Delete
	resp, _ = do("DELETE", "/api/v1/notifications/"+cfgID, nil, token)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	_, items = doList("GET", "/api/v1/notifications", nil, token)
	assert.Len(t, items, 0)
}

func TestNotificationConfigRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/notifications", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
