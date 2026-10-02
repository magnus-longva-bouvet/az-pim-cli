package readiness

import (
	"context"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// DirectoryRoleCheck checks that this shell's Microsoft Graph token carries a
// built-in Entra role. Microsoft Entra lists the built-in roles a user holds
// tenant-wide in the token's wids claim, by template id; a token issued before
// the activation does not list the role, and Graph keeps refusing what the role
// allows for as long as that token is used. Custom roles, and roles scoped to an
// administrative unit, are not listed there, so this check does not fit them.
func DirectoryRoleCheck(roleTemplateID, roleName string) Check {
	return directoryRoleCheck{roleTemplateID: roleTemplateID, roleName: roleName}
}

type directoryRoleCheck struct {
	roleTemplateID string
	roleName       string
}

func (c directoryRoleCheck) Name() string {
	return "Entra: " + c.roleName + " in this shell's Microsoft Graph token"
}

func (c directoryRoleCheck) Run(ctx context.Context, tokens TokenSource) Result {
	token, err := tokens(ctx, graphScope)
	if err != nil {
		return unknown("no Microsoft Graph token: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return unknown("unreadable Microsoft Graph token: %v", err)
	}
	roles, ok := claims["wids"].([]any)
	if !ok {
		return unknown("the token lists no directory roles (no wids claim)")
	}
	for _, role := range roles {
		if id, ok := role.(string); ok && strings.EqualFold(id, c.roleTemplateID) {
			return Result{Outcome: Pass}
		}
	}
	return Result{Outcome: Fail, Detail: "the token does not carry the role yet"}
}
