package readiness

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAzureCLIContextProblem(t *testing.T) {
	view := func(user string) []byte {
		return []byte(`{"current-context": "happi-aks-test", "users": [{"name": "u", "user": ` + user + `}]}`)
	}
	tests := []struct {
		name    string
		view    []byte
		wantHas string
	}{
		{"kubelogin through az", view(`{"exec": {"command": "kubelogin", "args": ["get-token", "--login", "azurecli", "--server-id", "6dae42f8"]}}`), ""},
		{"kubelogin through az, short flag", view(`{"exec": {"command": "/usr/local/bin/kubelogin", "args": ["get-token", "-l", "azurecli"]}}`), ""},
		{"kubelogin through az, joined flag", view(`{"exec": {"command": "kubelogin", "args": ["get-token", "--login=azurecli"]}}`), ""},
		{"kubelogin with its own cache", view(`{"exec": {"command": "kubelogin", "args": ["get-token", "--login", "devicecode"]}}`), "devicecode"},
		{"kubelogin defaults to device code", view(`{"exec": {"command": "kubelogin", "args": ["get-token"]}}`), "devicecode"},
		{"another plugin", view(`{"exec": {"command": "gke-gcloud-auth-plugin"}}`), "gke-gcloud-auth-plugin"},
		{"a client certificate", view(`{"client-certificate-data": "..."}`), "exec plugin"},
		{"no users", []byte(`{"current-context": "kind"}`), "exec plugin"},
		{"unreadable", []byte(`not json`), "unreadable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AAD_LOGIN_METHOD", "")
			problem := azureCLIContextProblem(tt.view)
			if tt.wantHas == "" {
				assert.Empty(t, problem)
			} else {
				assert.Contains(t, problem, tt.wantHas)
			}
		})
	}
}

func TestKubeloginModeFallsBackToTheEnvironment(t *testing.T) {
	t.Setenv("AAD_LOGIN_METHOD", "azurecli")
	assert.Equal(t, "azurecli", kubeloginMode([]string{"get-token"}))
	assert.Equal(t, "spn", kubeloginMode([]string{"get-token", "--login", "spn"}), "the flag wins")
}
