package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTokens hands out a token naming its scope, so a server can tell which
// token a check sent.
func fakeTokens(_ context.Context, scope string) (string, error) {
	return "token for " + scope, nil
}

func failingTokens(context.Context, string) (string, error) {
	return "", errors.New("az is not signed in")
}

func TestArmPermissionsCheck(t *testing.T) {
	contributor := Permission{
		Actions:    []string{"*"},
		NotActions: []string{"Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write"},
	}
	reader := `{"actions":["*/read"],"notActions":[],"dataActions":[],"notDataActions":[]}`
	contributorAsReported := `{"actions":["*"],"notActions":["Microsoft.Authorization/*/Write","microsoft.authorization/*/delete"],"dataActions":[],"notDataActions":[]}`

	tests := []struct {
		name    string
		status  int
		body    string
		want    Outcome
		wantHas string
	}{
		{"role among the permissions", http.StatusOK, `{"value":[` + reader + `,` + contributorAsReported + `]}`, Pass, ""},
		{"role not among them yet", http.StatusOK, `{"value":[` + reader + `]}`, Fail, "not among"},
		{"error status", http.StatusInternalServerError, `{"error":{"code":"InternalServerError"}}`, Unknown, "HTTP 500 InternalServerError"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "/subscriptions/s/providers/Microsoft.Authorization/permissions", r.URL.Path)
				assert.Equal(t, "Bearer token for "+armScope, r.Header.Get("Authorization"))
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()
			check := armPermissionsCheck{
				url:    server.URL + "/subscriptions/s/providers/Microsoft.Authorization/permissions?api-version=2022-04-01",
				grant:  []Permission{contributor},
				client: server.Client(),
			}

			result := check.Run(context.Background(), fakeTokens)

			assert.Equal(t, tt.want, result.Outcome)
			assert.Contains(t, result.Detail, tt.wantHas)
		})
	}

	t.Run("no token", func(t *testing.T) {
		result := armPermissionsCheck{client: http.DefaultClient}.Run(context.Background(), failingTokens)
		assert.Equal(t, Unknown, result.Outcome)
	})
}

func TestBlobDeleteCheck(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
		want   Outcome
	}{
		{"no such container", http.StatusNotFound, "ContainerNotFound", Pass},
		{"a container without a lease", http.StatusPreconditionFailed, "LeaseNotPresentWithContainerOperation", Pass},
		{"a container with another lease", http.StatusPreconditionFailed, "LeaseIdMismatchWithContainerOperation", Pass},
		{"role not in effect", http.StatusForbidden, "AuthorizationPermissionMismatch", Fail},
		{"storage firewall", http.StatusForbidden, "AuthorizationFailure", Unknown},
		{"server error", http.StatusInternalServerError, "", Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodDelete, r.Method)
				assert.Regexp(t, probeNamePattern, strings.TrimPrefix(r.URL.Path, "/"))
				assert.Equal(t, "container", r.URL.Query().Get("restype"))
				assert.Regexp(t, uuidV4Pattern, r.Header.Get("x-ms-lease-id"), "the lease id guards a container that happens to exist")
				assert.NotEmpty(t, r.Header.Get("x-ms-version"))
				assert.NotEmpty(t, r.Header.Get("x-ms-date"))
				assert.Equal(t, "Bearer token for "+storageScope, r.Header.Get("Authorization"))
				if tt.code != "" {
					w.Header().Set("x-ms-error-code", tt.code)
				}
				w.WriteHeader(tt.status)
			}))
			defer server.Close()
			check := blobDeleteCheck{endpoint: server.URL, client: server.Client()}

			assert.Equal(t, tt.want, check.Run(context.Background(), fakeTokens).Outcome)
		})
	}
}

func TestKeyVaultDeleteCheck(t *testing.T) {
	tests := []struct {
		name       string
		collection string
		notFound   string
		status     int
		body       string
		want       Outcome
	}{
		{"no such key", "keys", "KeyNotFound", http.StatusNotFound, `{"error":{"code":"KeyNotFound"}}`, Pass},
		{"no such certificate", "certificates", "CertificateNotFound", http.StatusNotFound, `{"error":{"code":"CertificateNotFound"}}`, Pass},
		{"role not in effect", "keys", "KeyNotFound", http.StatusForbidden, `{"error":{"code":"Forbidden","innererror":{"code":"ForbiddenByRbac"}}}`, Fail},
		{"vault firewall", "keys", "KeyNotFound", http.StatusForbidden, `{"error":{"code":"Forbidden","innererror":{"code":"ForbiddenByFirewall"}}}`, Unknown},
		{"unexpected not-found code", "keys", "KeyNotFound", http.StatusNotFound, `{"error":{"code":"SecretNotFound"}}`, Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodDelete, r.Method)
				collection, name, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
				assert.Equal(t, tt.collection, collection)
				assert.Regexp(t, probeNamePattern, name)
				assert.Equal(t, "7.4", r.URL.Query().Get("api-version"))
				assert.Equal(t, "Bearer token for "+vaultScope, r.Header.Get("Authorization"))
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()
			check := keyVaultDeleteCheck{vaultURL: server.URL, collection: tt.collection, notFound: tt.notFound, client: server.Client()}

			assert.Equal(t, tt.want, check.Run(context.Background(), fakeTokens).Outcome)
		})
	}
}

var uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestProbeName(t *testing.T) {
	name, err := probeName()
	require.NoError(t, err)
	assert.Regexp(t, probeNamePattern, name)

	other, err := probeName()
	require.NoError(t, err)
	assert.NotEqual(t, name, other)
}

func TestCheckedProbeNameRefusesAnythingButPrefixAndRandomUUID(t *testing.T) {
	for _, name := range []string{
		"",
		"pim-wait-",
		"pim-wait-not-a-uuid",
		"pim-wait-00000000-0000-0000-0000-000000000000",
		"pim-wait-6ba7b810-9dad-11d1-80b4-00c04fd430c8",  // version 1
		"pim-wait-0F8FAD5B-D9CB-469F-A165-70867728950E",  // upper case
		"pim-wait-0f8fad5b-d9cb-469f-a165-70867728950e/", // trailing path
		"pim-wait-0f8fad5b-d9cb-469f-a165-70867728950e?x",
		"x/pim-wait-0f8fad5b-d9cb-469f-a165-70867728950e",
		"0f8fad5b-d9cb-469f-a165-70867728950e",
	} {
		_, err := checkedProbeName(name)
		assert.Error(t, err, "%q", name)
	}
	name, err := checkedProbeName("pim-wait-0f8fad5b-d9cb-469f-a165-70867728950e")
	require.NoError(t, err)
	assert.Equal(t, "pim-wait-0f8fad5b-d9cb-469f-a165-70867728950e", name)
}

type brokenRandomness struct{}

func (brokenRandomness) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// Not parallel: uuid.SetRand swaps the package's source of randomness for the
// whole process.
func TestDeleteChecksSendNothingWithoutARandomUUID(t *testing.T) {
	uuid.SetRand(brokenRandomness{})
	t.Cleanup(func() { uuid.SetRand(nil) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("sent %s %s without a random UUID", r.Method, r.URL)
	}))
	defer server.Close()

	for _, check := range []Check{
		blobDeleteCheck{endpoint: server.URL, client: server.Client()},
		keyVaultDeleteCheck{vaultURL: server.URL, collection: "keys", notFound: "KeyNotFound", client: server.Client()},
		keyVaultDeleteCheck{vaultURL: server.URL, collection: "certificates", notFound: "CertificateNotFound", client: server.Client()},
	} {
		result := check.Run(context.Background(), fakeTokens)
		assert.Equal(t, Unknown, result.Outcome)
		assert.Contains(t, result.Detail, "refusing to probe")
	}
}

func TestGraphMemberCheck(t *testing.T) {
	const group = "6971c588-fd3c-4da6-8ac5-2b5800ba0c2b"
	tests := []struct {
		name   string
		status int
		body   string
		want   Outcome
	}{
		{"member", http.StatusOK, `{"value":["6971C588-FD3C-4DA6-8AC5-2B5800BA0C2B"]}`, Pass},
		{"not a member yet", http.StatusOK, `{"value":[]}`, Fail},
		{"refused", http.StatusForbidden, `{"error":{"code":"Authorization_RequestDenied"}}`, Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "Bearer token for "+graphScope, r.Header.Get("Authorization"))
				var body struct {
					GroupIDs []string `json:"groupIds"`
				}
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				assert.Equal(t, []string{group}, body.GroupIDs)
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()
			check := graphMemberCheck{url: server.URL, groupID: group, client: server.Client()}

			assert.Equal(t, tt.want, check.Run(context.Background(), fakeTokens).Outcome)
		})
	}
}

func TestKubeWhoamiCheck(t *testing.T) {
	const group = "6971c588-fd3c-4da6-8ac5-2b5800ba0c2b"
	review := func(groups ...string) []byte {
		out, err := json.Marshal(map[string]any{"status": map[string]any{"userInfo": map[string]any{"groups": groups}}})
		require.NoError(t, err)
		return out
	}
	tests := []struct {
		name string
		out  []byte
		err  error
		want Outcome
	}{
		{"group listed", review("system:authenticated", group), nil, Pass},
		{"group not listed yet", review("system:authenticated"), nil, Fail},
		{"kubectl failed", nil, errors.New("connection refused"), Unknown},
		{"unreadable output", []byte("not json"), nil, Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := kubeWhoamiCheck{groupID: group, whoami: func(context.Context) ([]byte, error) { return tt.out, tt.err }}
			assert.Equal(t, tt.want, check.Run(context.Background(), nil).Outcome)
		})
	}
}

func TestBuildChecks(t *testing.T) {
	const group = "6971c588-fd3c-4da6-8ac5-2b5800ba0c2b"
	const rg = "/subscriptions/s/resourceGroups/rg/providers"
	owner := []Permission{{Actions: []string{"*"}}}
	blobDataOwner := []Permission{{
		Actions:     []string{"Microsoft.Storage/storageAccounts/blobServices/containers/*"},
		DataActions: []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"},
	}}
	blobDataReader := []Permission{{
		Actions:     []string{"Microsoft.Storage/storageAccounts/blobServices/containers/read"},
		DataActions: []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"},
	}}
	vaultAdmin := []Permission{{DataActions: []string{"Microsoft.KeyVault/vaults/*"}}}
	secretsUser := []Permission{{DataActions: []string{"Microsoft.KeyVault/vaults/secrets/getSecret/action"}}}
	opts := Options{ARMBaseURL: "https://arm", GraphBaseURL: "https://graph", HTTPClient: http.DefaultClient}
	whoami := func(context.Context) ([]byte, error) { return nil, nil }

	assignments := []Assignment{
		{Scope: "/subscriptions/s", RoleName: "Owner", Grant: owner},
		{Scope: "/subscriptions/s", RoleName: "Owner", Grant: owner},
		{Scope: rg + "/Microsoft.Storage/storageAccounts/StateAccount", RoleName: "Storage Blob Data Owner", Grant: blobDataOwner},
		{Scope: rg + "/Microsoft.Storage/storageAccounts/logs", RoleName: "Storage Blob Data Reader", Grant: blobDataReader},
		{Scope: rg + "/Microsoft.KeyVault/vaults/gitops-kv", RoleName: "Key Vault Administrator", Grant: vaultAdmin},
		{Scope: rg + "/Microsoft.KeyVault/vaults/app-kv", RoleName: "Key Vault Secrets User", Grant: secretsUser},
	}

	t.Run("one check per assignment, plus the data planes and kubectl", func(t *testing.T) {
		withKube := opts
		withKube.Whoami = whoami
		var names []string
		for _, check := range BuildChecks(group, assignments, withKube) {
			names = append(names, check.Name())
		}
		assert.Equal(t, []string{
			"Azure: Owner on /subscriptions/s",
			"Azure: Storage Blob Data Owner on " + rg + "/Microsoft.Storage/storageAccounts/StateAccount",
			"Azure: Storage Blob Data Reader on " + rg + "/Microsoft.Storage/storageAccounts/logs",
			"Azure: Key Vault Administrator on " + rg + "/Microsoft.KeyVault/vaults/gitops-kv",
			"Azure: Key Vault Secrets User on " + rg + "/Microsoft.KeyVault/vaults/app-kv",
			"Storage: delete containers in stateaccount",
			"Key Vault: delete keys in gitops-kv",
			"Key Vault: delete certificates in gitops-kv",
			"kubectl: the group in 'kubectl auth whoami'",
		}, names)
	})

	t.Run("a name Azure would not allow gets no data-plane check", func(t *testing.T) {
		var names []string
		for _, check := range BuildChecks(group, []Assignment{
			{Scope: rg + "/Microsoft.Storage/storageAccounts/evil.example#", RoleName: "Storage Blob Data Owner", Grant: blobDataOwner},
			{Scope: rg + "/Microsoft.KeyVault/vaults/kv?x=1", RoleName: "Key Vault Administrator", Grant: vaultAdmin},
		}, opts) {
			names = append(names, check.Name())
		}
		assert.NotContains(t, strings.Join(names, "\n"), "delete")
	})

	t.Run("the endpoints come from the scopes", func(t *testing.T) {
		checks := BuildChecks(group, assignments, opts)
		require.Len(t, checks, 8)
		arm, ok := checks[0].(armPermissionsCheck)
		require.True(t, ok)
		assert.Equal(t, "https://arm/subscriptions/s/providers/Microsoft.Authorization/permissions?api-version=2022-04-01", arm.url)
		blob, ok := checks[5].(blobDeleteCheck)
		require.True(t, ok)
		assert.Equal(t, "https://stateaccount.blob.core.windows.net", blob.endpoint)
		vault, ok := checks[6].(keyVaultDeleteCheck)
		require.True(t, ok)
		assert.Equal(t, "https://gitops-kv.vault.azure.net", vault.vaultURL)
	})

	t.Run("membership stands in when nothing else can be checked", func(t *testing.T) {
		checks := BuildChecks(group, nil, opts)
		require.Len(t, checks, 1)
		assert.Equal(t, graphMemberCheck{url: "https://graph/v1.0/me/checkMemberGroups", groupID: group, client: http.DefaultClient}, checks[0])
	})

	t.Run("kubectl alone is enough", func(t *testing.T) {
		withKube := opts
		withKube.Whoami = whoami
		checks := BuildChecks(group, nil, withKube)
		require.Len(t, checks, 1)
		assert.IsType(t, kubeWhoamiCheck{}, checks[0])
	})
}
