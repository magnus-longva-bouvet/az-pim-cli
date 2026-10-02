package readiness

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectoryRoleCheck(t *testing.T) {
	const userAdministrator = "fe930be7-5e62-47db-91af-98c3a49a38b1"
	const defaultUserRole = "b79fbf4d-3ef9-4689-8143-76b194e85509"
	graphToken := func(claims jwt.MapClaims) TokenSource {
		token, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)
		return func(_ context.Context, scope string) (string, error) {
			assert.Equal(t, graphScope, scope)
			return token, nil
		}
	}
	tests := []struct {
		name   string
		tokens TokenSource
		want   Outcome
	}{
		{"role in the token", graphToken(jwt.MapClaims{"wids": []string{defaultUserRole, "FE930BE7-5E62-47DB-91AF-98C3A49A38B1"}}), Pass},
		{"role not in the token yet", graphToken(jwt.MapClaims{"wids": []string{defaultUserRole}}), Fail},
		{"token without the claim", graphToken(jwt.MapClaims{"oid": "x"}), Unknown},
		{"no token", failingTokens, Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := DirectoryRoleCheck(userAdministrator, "User Administrator")
			assert.Equal(t, tt.want, check.Run(context.Background(), tt.tokens).Outcome)
		})
	}
}
