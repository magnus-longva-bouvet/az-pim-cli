package readiness

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
)

// Assignment is one Azure role assignment the group holds, with the
// permissions of its role.
type Assignment struct {
	Scope    string
	RoleName string
	Grant    []Permission
}

// Discover lists the group's Azure role assignments through Azure Resource
// Graph, then reads each role's permissions. It runs with this shell's token
// before the activation, so it finds only assignments the account can already
// read. Assignments at management group scope are not found either: Resource
// Graph returns those only for queries scoped to a management group.
func Discover(ctx context.Context, client *http.Client, tokens TokenSource, armBaseURL, groupID string) ([]Assignment, error) {
	id, err := uuid.Parse(groupID)
	if err != nil {
		return nil, fmt.Errorf("group id %q: %w", groupID, err)
	}
	token, err := tokens(ctx, armScope)
	if err != nil {
		return nil, fmt.Errorf("getting an Azure Resource Manager token: %w", err)
	}

	query := fmt.Sprintf("authorizationresources"+
		" | where type =~ 'microsoft.authorization/roleassignments'"+
		" | where tostring(properties.principalId) =~ '%s'"+
		" | project scope = tostring(properties.scope), roleDefinitionId = tostring(properties.roleDefinitionId)", id)
	payload, err := json.Marshal(map[string]any{
		"query":   query,
		"options": map[string]any{"resultFormat": "objectArray", "$top": 1000},
	})
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	resp, err := send(ctx, client, http.MethodPost, armBaseURL+"/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01", token, header, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("querying Azure Resource Graph: %w", err)
	}
	if resp.status != http.StatusOK {
		return nil, fmt.Errorf("querying Azure Resource Graph: HTTP %d %s", resp.status, armErrorCode(resp.body))
	}
	var rows struct {
		Data []struct {
			Scope            string `json:"scope"`
			RoleDefinitionID string `json:"roleDefinitionId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.body, &rows); err != nil {
		return nil, fmt.Errorf("reading the Azure Resource Graph answer: %w", err)
	}

	roles := map[string]roleDefinition{}
	var assignments []Assignment
	for _, row := range rows.Data {
		key := strings.ToLower(row.RoleDefinitionID)
		role, ok := roles[key]
		if !ok {
			role, err = readRoleDefinition(ctx, client, armBaseURL, token, row.RoleDefinitionID)
			if err != nil {
				return nil, err
			}
			roles[key] = role
		}
		assignments = append(assignments, Assignment{Scope: row.Scope, RoleName: role.name, Grant: role.permissions})
	}
	slices.SortFunc(assignments, func(a, b Assignment) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a.Scope), strings.ToLower(b.Scope)), cmp.Compare(a.RoleName, b.RoleName))
	})
	return assignments, nil
}

type roleDefinition struct {
	name        string
	permissions []Permission
}

func readRoleDefinition(ctx context.Context, client *http.Client, armBaseURL, token, id string) (roleDefinition, error) {
	resp, err := send(ctx, client, http.MethodGet, armBaseURL+id+"?api-version=2022-04-01", token, nil, nil)
	if err != nil {
		return roleDefinition{}, fmt.Errorf("reading role definition %s: %w", id, err)
	}
	if resp.status != http.StatusOK {
		return roleDefinition{}, fmt.Errorf("reading role definition %s: HTTP %d %s", id, resp.status, armErrorCode(resp.body))
	}
	var def struct {
		Properties struct {
			RoleName    string       `json:"roleName"`
			Permissions []Permission `json:"permissions"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(resp.body, &def); err != nil {
		return roleDefinition{}, fmt.Errorf("reading role definition %s: %w", id, err)
	}
	return roleDefinition{name: def.Properties.RoleName, permissions: def.Properties.Permissions}, nil
}
