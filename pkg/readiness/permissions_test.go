package readiness

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllows(t *testing.T) {
	owner := []Permission{{Actions: []string{"*"}}}
	contributor := []Permission{{
		Actions:    []string{"*"},
		NotActions: []string{"Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write"},
	}}
	blobReader := []Permission{{
		Actions:     []string{"Microsoft.Storage/storageAccounts/blobServices/containers/read"},
		DataActions: []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"},
	}}
	vaultAdmin := []Permission{{
		Actions:     []string{"Microsoft.KeyVault/vaults/read"},
		DataActions: []string{"Microsoft.KeyVault/vaults/*"},
	}}
	vaultAdminWithoutCertificates := []Permission{{
		DataActions:    []string{"Microsoft.KeyVault/vaults/*"},
		NotDataActions: []string{"Microsoft.KeyVault/vaults/certificates/*"},
	}}

	tests := []struct {
		name      string
		perms     []Permission
		operation string
		data      bool
		want      bool
	}{
		{"wildcard grants any action", owner, containerDelete, false, true},
		{"wildcard spans slashes", contributor, containerDelete, false, true},
		{"not-action removes a match", contributor, "Microsoft.Authorization/roleAssignments/write", false, false},
		{"matching ignores case", contributor, "microsoft.authorization/ROLEASSIGNMENTS/WRITE", false, false},
		{"actions do not grant data actions", owner, keyDelete, true, false},
		{"read-only role cannot delete", blobReader, containerDelete, false, false},
		{"data wildcard grants a data action", vaultAdmin, keyDelete, true, true},
		{"not-data-action removes a match", vaultAdminWithoutCertificates, certificateDelete, true, false},
		{"no permissions grant nothing", nil, containerDelete, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, allows(tt.perms, tt.operation, tt.data))
		})
	}
}

func TestSameGrant(t *testing.T) {
	definition := Permission{
		Actions:    []string{"*"},
		NotActions: []string{"Microsoft.Authorization/*/Write", "Microsoft.Authorization/*/Delete"},
	}
	reported := Permission{
		Actions:        []string{"*"},
		NotActions:     []string{"microsoft.authorization/*/delete", "Microsoft.Authorization/*/Write"},
		DataActions:    []string{},
		NotDataActions: nil,
	}
	assert.True(t, sameGrant(definition, reported), "order, case and nil versus empty must not matter")

	owner := Permission{Actions: []string{"*"}}
	assert.False(t, sameGrant(definition, owner), "a role without the not-actions is another role")
}
