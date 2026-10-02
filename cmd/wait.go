package cmd

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/netr0m/az-pim-cli/pkg/pim"
	"github.com/netr0m/az-pim-cli/pkg/readiness"
)

// Exit code for "active, but this shell could not be confirmed able to use it".
// The activation stands either way.
const EXIT_NOT_READY = 4

// waitInterval is the pause between two rounds of checks.
const waitInterval = 5 * time.Second

var waitUntilUsable bool
var waitTimeout time.Duration

// --wait is wired up for groups and Entra roles. Azure resource roles (activate
// resource) are enforced by ARM the way a group's roles are, so the group checks
// would fit them, but that is neither wired up nor tested.

func checkWaitFlags() {
	if !waitUntilUsable {
		return
	}
	if azureEnv != "global" {
		slog.Error("'--wait' only knows the endpoints of the global cloud", "cloud", azureEnv)
		os.Exit(1)
	}
	if waitTimeout <= 0 {
		slog.Error("'--wait-timeout' must be positive", "waitTimeout", waitTimeout.String())
		os.Exit(1)
	}
}

// newWaiter makes sure az in this shell is signed in as principalId, the account
// being activated: the checks use az's credentials and could never pass
// otherwise. Like everything that prepares a wait, it changes nothing.
func newWaiter(ctx context.Context, principalId string) (*readiness.Waiter, readiness.TokenSource) {
	tokens, err := readiness.AzureCLITokens()
	if err != nil {
		slog.Error("'--wait' needs the Azure CLI", "error", err.Error())
		os.Exit(1)
	}
	azObjectId, err := readiness.SignedInObjectID(ctx, tokens)
	if err != nil {
		slog.Error("'--wait' checks this shell's az session, which gave no token", "error", err.Error(), "hint", "run 'az login'")
		os.Exit(1)
	}
	if !strings.EqualFold(azObjectId, principalId) {
		slog.Error(
			"az in this shell is signed in as another account than the one being activated",
			"azObjectId", azObjectId,
			"activatingObjectId", principalId,
			"hint", "sign az and az-pim-cli in as the same account",
		)
		os.Exit(1)
	}
	configDir, err := readiness.AzureCLIConfigDir()
	if err != nil {
		slog.Error("Could not find az's configuration directory", "error", err.Error())
		os.Exit(1)
	}

	return &readiness.Waiter{
		Tokens: tokens,
		Refresh: func() error {
			dropped, err := readiness.DropCachedAccessTokens(configDir)
			if err == nil {
				slog.Debug("Dropped az's cached access tokens", "count", dropped)
			}
			return err
		},
		Interval: waitInterval,
		Timeout:  waitTimeout,
	}, tokens
}

// prepareGroupWait works out what to check for a group membership: the group's
// Azure role assignments, its storage accounts and key vaults, and kubectl.
func prepareGroupWait(ctx context.Context, principalId, groupId, accessId string) *readiness.Waiter {
	if !strings.EqualFold(accessId, "member") {
		slog.Error("'--wait' applies to memberships only; owners do not get a group's access", "accessId", accessId)
		os.Exit(1)
	}
	waiter, tokens := newWaiter(ctx, principalId)

	client := &http.Client{Timeout: 30 * time.Second}
	assignments, err := readiness.Discover(ctx, client, tokens, AzureClientInstance.ARMBaseURL, groupId)
	if err != nil {
		slog.Warn("Could not list the group's Azure role assignments", "error", err.Error())
	}
	whoami, reason := readiness.KubectlWhoami(ctx)
	if whoami == nil {
		slog.Info("Not checking kubectl", "reason", reason)
	}
	waiter.Checks = readiness.BuildChecks(groupId, assignments, readiness.Options{
		ARMBaseURL:   AzureClientInstance.ARMBaseURL,
		GraphBaseURL: AzureClientInstance.GraphBaseURL,
		HTTPClient:   client,
		Whoami:       whoami,
	})
	logChecks(waiter.Checks)
	return waiter
}

// prepareRoleWait works out what to check for an Entra role: that az's Microsoft
// Graph token carries it. Tokens list only built-in roles held tenant-wide, so
// for any other role the wait can do no more than refresh the tokens.
func prepareRoleWait(ctx context.Context, principalId string, role *pim.GraphRoleEligibilityInstance, roleName string) *readiness.Waiter {
	waiter, _ := newWaiter(ctx, principalId)

	templateId, builtIn := role.RoleDefinitionId, true
	if role.RoleDefinition != nil {
		if role.RoleDefinition.TemplateId != "" {
			templateId = role.RoleDefinition.TemplateId
		}
		builtIn = role.RoleDefinition.IsBuiltIn
	}
	switch {
	case !builtIn:
		slog.Warn("Tokens do not list custom roles; '--wait' only refreshes this shell's tokens", "role", roleName)
	case directoryScope(role.DirectoryScopeId) != pim.GRAPH_DEFAULT_DIRECTORY_SCOPE:
		slog.Warn("Tokens do not list roles scoped to an administrative unit; '--wait' only refreshes this shell's tokens", "role", roleName, "directoryScope", role.DirectoryScopeId)
	default:
		waiter.Checks = []readiness.Check{readiness.DirectoryRoleCheck(templateId, roleName)}
	}
	logChecks(waiter.Checks)
	return waiter
}

func logChecks(checks []readiness.Check) {
	for _, check := range checks {
		slog.Info("Will check", "check", check.Name())
	}
}

// runWait waits, and exits with EXIT_NOT_READY when the wait fails. kind
// ("group" or "role") and name say what was activated.
func runWait(ctx context.Context, waiter *readiness.Waiter, kind, name string) {
	report, err := waiter.Wait(ctx)
	if err != nil {
		slog.Error(
			"Could not confirm that this shell can use the "+kind,
			kind, name,
			"error", err.Error(),
			"pending", strings.Join(report.Pending, "; "),
			"hint", "the activation stands; run 'az login' for new tokens, then rerun with '--wait' to check again",
		)
		os.Exit(EXIT_NOT_READY)
	}
	for _, unverified := range report.Unverified {
		slog.Warn("Could not verify", "check", unverified.Name, "reason", unverified.Detail)
	}
	if len(waiter.Checks) == 0 {
		slog.Info("Refreshed this shell's tokens; nothing could be checked", kind, name)
		return
	}
	slog.Info("This shell can use the "+kind, kind, name, "elapsed", report.Elapsed.Round(time.Second).String())
}

// activeMembership returns the group's live assignment with the given access
// type, or nil when there is none.
func activeMembership(principalId, token, groupId, accessId string) *pim.GraphGroupAssignmentInstance {
	active := pim.GetActiveGroupAssignments(principalId, token, AzureClientInstance)
	for i := range active.Value {
		instance := &active.Value[i]
		if strings.EqualFold(instance.GroupId, groupId) && strings.EqualFold(instance.AccessId, accessId) {
			return instance
		}
	}
	return nil
}

// activeRoleAssignment returns the role's live assignment at the eligible
// assignment's directory scope, or nil when there is none.
func activeRoleAssignment(principalId, token string, role *pim.GraphRoleEligibilityInstance) *pim.GraphRoleAssignmentInstance {
	active := pim.GetActiveRoleAssignments(principalId, token, AzureClientInstance)
	for i := range active.Value {
		instance := &active.Value[i]
		if strings.EqualFold(instance.RoleDefinitionId, role.RoleDefinitionId) &&
			directoryScope(instance.DirectoryScopeId) == directoryScope(role.DirectoryScopeId) {
			return instance
		}
	}
	return nil
}

func directoryScope(scope string) string {
	if scope == "" {
		return pim.GRAPH_DEFAULT_DIRECTORY_SCOPE
	}
	return scope
}
