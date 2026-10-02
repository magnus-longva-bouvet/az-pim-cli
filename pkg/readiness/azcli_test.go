package readiness

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cacheDocument is a trimmed MSAL token cache in the layout az writes: two
// signed-in accounts, access tokens from az and from another app, and a
// refresh token that must survive.
const cacheDocument = `{
  "Account": {
    "home1-login.microsoftonline.com-tenant": {"home_account_id": "home1", "username": "Admin@Example.com", "realm": "tenant"},
    "home2-login.microsoftonline.com-tenant": {"home_account_id": "home2", "username": "someone.else@example.com", "realm": "tenant"}
  },
  "AccessToken": {
    "arm": {"client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "home_account_id": "home1", "secret": "arm-token"},
    "aks": {"client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "home_account_id": "home1", "secret": "aks-token"},
    "other-account": {"client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "home_account_id": "home2", "secret": "kept-1"},
    "other-app": {"client_id": "28476910-19b6-4a4c-a41e-13f2d5658775", "home_account_id": "home1", "secret": "kept<&>2"}
  },
  "RefreshToken": {
    "rt": {"client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "home_account_id": "home1", "secret": "refresh-token"}
  }
}`

func TestWithoutAccessTokens(t *testing.T) {
	updated, dropped, err := withoutAccessTokens([]byte(cacheDocument), "admin@example.com")

	require.NoError(t, err)
	assert.Equal(t, 2, dropped)
	var document struct {
		AccessToken  map[string]json.RawMessage `json:"AccessToken"`
		RefreshToken map[string]json.RawMessage `json:"RefreshToken"`
		Account      map[string]json.RawMessage `json:"Account"`
	}
	require.NoError(t, json.Unmarshal(updated, &document))
	assert.ElementsMatch(t, []string{"other-account", "other-app"}, keys(document.AccessToken))
	assert.Contains(t, document.RefreshToken, "rt")
	assert.Len(t, document.Account, 2)
	assert.Contains(t, string(updated), "kept<&>2", "values come back byte for byte, without HTML escaping")
}

func TestWithoutAccessTokensLeavesACacheWithNothingToDropAlone(t *testing.T) {
	const document = `{"Account": {"a": {"home_account_id": "home1", "username": "admin@example.com"}}}`

	updated, dropped, err := withoutAccessTokens([]byte(document), "admin@example.com")

	require.NoError(t, err)
	assert.Zero(t, dropped)
	assert.JSONEq(t, document, string(updated))
}

func TestWithoutAccessTokensNeedsTheAccount(t *testing.T) {
	_, _, err := withoutAccessTokens([]byte(cacheDocument), "nobody@example.com")
	require.ErrorContains(t, err, "nobody@example.com")
}

func TestDropCachedAccessTokens(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("az's token cache is encrypted on Windows")
	}
	dir := t.TempDir()
	profile := "\xef\xbb\xbf" + `{"subscriptions": [
		{"isDefault": false, "user": {"name": "someone.else@example.com"}},
		{"isDefault": true, "user": {"name": "admin@example.com"}}
	]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "azureProfile.json"), []byte(profile), 0o600))
	cachePath := filepath.Join(dir, "msal_token_cache.json")
	require.NoError(t, os.WriteFile(cachePath, []byte(cacheDocument), 0o600))

	dropped, err := DropCachedAccessTokens(dir)

	require.NoError(t, err)
	assert.Equal(t, 2, dropped)
	raw, err := os.ReadFile(cachePath)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "arm-token")
	assert.Contains(t, string(raw), "refresh-token")
	info, err := os.Stat(cachePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	dropped, err = DropCachedAccessTokens(dir)
	require.NoError(t, err)
	assert.Zero(t, dropped, "a second run finds nothing left to drop")
}

func TestDropCachedAccessTokensRefusesAnEncryptedCache(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "azureProfile.json"), []byte(`{"subscriptions": [{"isDefault": true, "user": {"name": "admin@example.com"}}]}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "msal_token_cache.bin"), []byte("ciphertext"), 0o600))

	_, err := DropCachedAccessTokens(dir)

	require.ErrorContains(t, err, "encrypted")
}

func TestSignedInUsernameNeedsADefaultSubscription(t *testing.T) {
	path := filepath.Join(t.TempDir(), "azureProfile.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"subscriptions": [{"isDefault": false, "user": {"name": "admin@example.com"}}]}`), 0o600))

	_, err := signedInUsername(path)

	require.Error(t, err)
}

func TestSignedInObjectID(t *testing.T) {
	sign := func(claims jwt.MapClaims) string {
		token, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)
		return token
	}
	tokensReturning := func(token string) TokenSource {
		return func(_ context.Context, scope string) (string, error) {
			assert.Equal(t, armScope, scope)
			return token, nil
		}
	}

	oid, err := SignedInObjectID(context.Background(), tokensReturning(sign(jwt.MapClaims{"oid": "0ea1a819-4422-4f4b-8ca3-74de91f528ce"})))
	require.NoError(t, err)
	assert.Equal(t, "0ea1a819-4422-4f4b-8ca3-74de91f528ce", oid)

	_, err = SignedInObjectID(context.Background(), tokensReturning(sign(jwt.MapClaims{"sub": "x"})))
	require.Error(t, err)

	_, err = SignedInObjectID(context.Background(), failingTokens)
	require.Error(t, err)
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
