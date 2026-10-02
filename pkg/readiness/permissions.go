package readiness

import (
	"regexp"
	"slices"
	"strings"
)

// Permission is one entry of an Azure role definition's permissions. The ARM
// permissions API reports the caller's effective permissions in the same shape,
// one entry per role that applies at the scope.
type Permission struct {
	Actions        []string `json:"actions"`
	NotActions     []string `json:"notActions"`
	DataActions    []string `json:"dataActions"`
	NotDataActions []string `json:"notDataActions"`
}

// allows reports whether perms grant operation, a control-plane action when
// data is false and a data action when it is true. Azure RBAC wildcards match
// any run of characters, '/' included, and case does not matter.
func allows(perms []Permission, operation string, data bool) bool {
	for _, p := range perms {
		granted, denied := p.Actions, p.NotActions
		if data {
			granted, denied = p.DataActions, p.NotDataActions
		}
		if matchesAny(granted, operation) && !matchesAny(denied, operation) {
			return true
		}
	}
	return false
}

func matchesAny(patterns []string, operation string) bool {
	return slices.ContainsFunc(patterns, func(pattern string) bool {
		expr := "(?i)^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
		matched, err := regexp.MatchString(expr, operation)
		return err == nil && matched
	})
}

// sameGrant compares two permission entries as sets: order and case differ
// between a role definition and the permissions API's view of it.
func sameGrant(a, b Permission) bool {
	return sameSet(a.Actions, b.Actions) &&
		sameSet(a.NotActions, b.NotActions) &&
		sameSet(a.DataActions, b.DataActions) &&
		sameSet(a.NotDataActions, b.NotDataActions)
}

func sameSet(a, b []string) bool {
	return slices.Equal(normalized(a), normalized(b))
}

func normalized(items []string) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = strings.ToLower(item)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
