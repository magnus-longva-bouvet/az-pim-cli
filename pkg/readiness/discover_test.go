package readiness

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscover(t *testing.T) {
	const group = "6971c588-fd3c-4da6-8ac5-2b5800ba0c2b"
	const ownerID = "/providers/Microsoft.Authorization/RoleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	const vaultAdminID = "/providers/Microsoft.Authorization/RoleDefinitions/00482a5a-887f-4fb3-b363-3b7fe8e74483"
	var roleReads atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer token for "+armScope, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/providers/Microsoft.ResourceGraph/resources":
			var request struct {
				Query   string         `json:"query"`
				Options map[string]any `json:"options"`
			}
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			assert.Contains(t, request.Query, "=~ '"+group+"'")
			assert.Equal(t, "objectArray", request.Options["resultFormat"])
			_, _ = io.WriteString(w, `{"data":[
				{"scope":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv","roleDefinitionId":"`+vaultAdminID+`"},
				{"scope":"/subscriptions/s","roleDefinitionId":"`+ownerID+`"},
				{"scope":"/subscriptions/t","roleDefinitionId":"`+ownerID+`"}
			]}`)
		case r.Method == http.MethodGet && strings.EqualFold(r.URL.Path, ownerID):
			roleReads.Add(1)
			_, _ = io.WriteString(w, `{"properties":{"roleName":"Owner","permissions":[{"actions":["*"]}]}}`)
		case r.Method == http.MethodGet && strings.EqualFold(r.URL.Path, vaultAdminID):
			roleReads.Add(1)
			_, _ = io.WriteString(w, `{"properties":{"roleName":"Key Vault Administrator","permissions":[{"dataActions":["Microsoft.KeyVault/vaults/*"]}]}}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	assignments, err := Discover(context.Background(), server.Client(), fakeTokens, server.URL, strings.ToUpper(group))

	require.NoError(t, err)
	assert.Equal(t, []Assignment{
		{Scope: "/subscriptions/s", RoleName: "Owner", Grant: []Permission{{Actions: []string{"*"}}}},
		{Scope: "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv", RoleName: "Key Vault Administrator", Grant: []Permission{{DataActions: []string{"Microsoft.KeyVault/vaults/*"}}}},
		{Scope: "/subscriptions/t", RoleName: "Owner", Grant: []Permission{{Actions: []string{"*"}}}},
	}, assignments)
	assert.Equal(t, int32(2), roleReads.Load(), "each role definition is read once")
}

func TestDiscoverRejectsAGroupIDThatIsNotAGUID(t *testing.T) {
	_, err := Discover(context.Background(), http.DefaultClient, failingTokens, "https://unused", "x' or 1 == 1")
	require.Error(t, err)
}

func TestDiscoverReportsAResourceGraphError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"code":"BadRequest"}}`)
	}))
	defer server.Close()

	_, err := Discover(context.Background(), server.Client(), fakeTokens, server.URL, "6971c588-fd3c-4da6-8ac5-2b5800ba0c2b")

	require.ErrorContains(t, err, "HTTP 400 BadRequest")
}
