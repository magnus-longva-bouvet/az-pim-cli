package readiness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/golang-jwt/jwt/v5"
)

// azureCLIClientID is the Azure CLI's own application id: the client its
// cached tokens were issued to.
const azureCLIClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

// AzureCLITokens fetches tokens through `az account get-access-token`, so they
// come from, and land in, the cache az and kubelogin use. Every call starts az;
// nothing is kept in this process.
func AzureCLITokens() (TokenSource, error) {
	cred, err := azidentity.NewAzureCLICredential(nil)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, scope string) (string, error) {
		token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
		if err != nil {
			return "", err
		}
		return token.Token, nil
	}, nil
}

// SignedInObjectID returns the object id of the account az is signed in as.
func SignedInObjectID(ctx context.Context, tokens TokenSource) (string, error) {
	token, err := tokens(ctx, armScope)
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return "", fmt.Errorf("reading az's token: %w", err)
	}
	oid, _ := claims["oid"].(string)
	if oid == "" {
		return "", errors.New("az's token carries no object id")
	}
	return oid, nil
}

// AzureCLIConfigDir is where az keeps its profile and token cache.
func AzureCLIConfigDir() (string, error) {
	if dir := os.Getenv("AZURE_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".azure"), nil
}

// DropCachedAccessTokens deletes the access tokens az has cached for its
// signed-in account and keeps the refresh token. The next az call, and
// kubelogin through it, then mints new tokens without a sign-in, and those
// reflect group memberships as they are now. It returns how many it dropped.
//
// Tested on Linux only, where az keeps the cache as plain JSON. On Windows az
// encrypts it with DPAPI (msal_token_cache.bin) or leaves tokens to the WAM
// broker, and on macOS an encrypted cache would sit in the keychain; this
// returns an error in those cases rather than guessing.
func DropCachedAccessTokens(configDir string) (int, error) {
	username, err := signedInUsername(filepath.Join(configDir, "azureProfile.json"))
	if err != nil {
		return 0, err
	}
	cachePath := filepath.Join(configDir, "msal_token_cache.json")
	if _, err := os.Stat(cachePath); err != nil {
		if _, binErr := os.Stat(filepath.Join(configDir, "msal_token_cache.bin")); binErr == nil {
			return 0, errors.New("az keeps its token cache encrypted, which this cannot edit")
		}
		return 0, fmt.Errorf("az's token cache: %w", err)
	}

	unlock, err := lockFile(cachePath + ".lockfile")
	if err != nil {
		return 0, fmt.Errorf("locking az's token cache: %w", err)
	}
	defer unlock()

	raw, err := os.ReadFile(cachePath)
	if err != nil {
		return 0, err
	}
	updated, dropped, err := withoutAccessTokens(raw, username)
	if err != nil || dropped == 0 {
		return 0, err
	}
	if err := replaceFile(cachePath, updated); err != nil {
		return 0, err
	}
	return dropped, nil
}

// withoutAccessTokens removes the Azure CLI client's access tokens for the
// account with this username from an MSAL token cache document. Everything
// else in the document, refresh tokens included, is passed through untouched.
func withoutAccessTokens(raw []byte, username string) (updated []byte, dropped int, err error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, 0, fmt.Errorf("reading az's token cache: %w", err)
	}
	var accounts map[string]struct {
		HomeAccountID string `json:"home_account_id"`
		Username      string `json:"username"`
	}
	if err := json.Unmarshal(document["Account"], &accounts); err != nil && document["Account"] != nil {
		return nil, 0, fmt.Errorf("reading az's cached accounts: %w", err)
	}
	homes := map[string]bool{}
	for _, account := range accounts {
		if strings.EqualFold(account.Username, username) {
			homes[account.HomeAccountID] = true
		}
	}
	if len(homes) == 0 {
		return nil, 0, fmt.Errorf("az's token cache holds no account %s; run 'az login'", username)
	}

	var accessTokens map[string]json.RawMessage
	if err := json.Unmarshal(document["AccessToken"], &accessTokens); err != nil && document["AccessToken"] != nil {
		return nil, 0, fmt.Errorf("reading az's cached access tokens: %w", err)
	}
	for key, entry := range accessTokens {
		var token struct {
			ClientID      string `json:"client_id"`
			HomeAccountID string `json:"home_account_id"`
		}
		if json.Unmarshal(entry, &token) == nil && token.ClientID == azureCLIClientID && homes[token.HomeAccountID] {
			delete(accessTokens, key)
			dropped++
		}
	}
	if dropped == 0 {
		return raw, 0, nil
	}

	encoded, err := encode(accessTokens)
	if err != nil {
		return nil, 0, err
	}
	document["AccessToken"] = encoded
	updated, err = encode(document)
	if err != nil {
		return nil, 0, err
	}
	return updated, dropped, nil
}

// signedInUsername reads the account of az's default subscription.
func signedInUsername(profilePath string) (string, error) {
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		return "", fmt.Errorf("az's profile: %w", err)
	}
	// az writes its profile with a byte order mark, which encoding/json rejects.
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	var profile struct {
		Subscriptions []struct {
			IsDefault bool `json:"isDefault"`
			User      struct {
				Name string `json:"name"`
			} `json:"user"`
		} `json:"subscriptions"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		return "", fmt.Errorf("reading az's profile: %w", err)
	}
	for _, sub := range profile.Subscriptions {
		if sub.IsDefault && sub.User.Name != "" {
			return sub.User.Name, nil
		}
	}
	return "", errors.New("az has no default subscription; run 'az login'")
}

// encode marshals without HTML escaping, so a value comes back out byte for
// byte the way msal wrote it.
func encode(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// replaceFile writes data next to path and renames it into place, so a reader
// never sees half a cache.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
