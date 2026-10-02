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

// Exit code for "the group is active, but this shell could not be confirmed
// able to use it". The activation stands either way.
const EXIT_NOT_READY = 4

// waitInterval is the pause between two rounds of checks.
const waitInterval = 5 * time.Second

var waitUntilUsable bool
var waitTimeout time.Duration

// --wait is wired up for groups only. Entra role activations (activate role)
// reach tokens the same way and Azure resource roles (activate resource) are
// enforced by ARM like a group's roles, so pkg/readiness would fit both, but
// neither is tested, and a mistake with Entra roles lands in the directory.

func checkWaitFlags() {
	if !waitUntilUsable {
		return
	}
	if extend {
		slog.Error("'--wait' has nothing to wait for with '--extend': extending does not change who is a member")
		os.Exit(1)
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

// prepareWait runs before the activation is requested, and changes nothing. It
// makes sure az in this shell is signed in as the account being activated,
// since the checks use az's credentials and would otherwise never pass, and
// works out what to check.
func prepareWait(ctx context.Context, principalId string, group *pim.GraphGroupEligibilityInstance) *readiness.Waiter {
	if !strings.EqualFold(group.AccessId, "member") {
		slog.Error("'--wait' applies to memberships only; owners do not get a group's access", "accessId", group.AccessId)
		os.Exit(1)
	}
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

	client := &http.Client{Timeout: 30 * time.Second}
	assignments, err := readiness.Discover(ctx, client, tokens, AzureClientInstance.ARMBaseURL, group.GroupId)
	if err != nil {
		slog.Warn("Could not list the group's Azure role assignments", "error", err.Error())
	}
	whoami, reason := readiness.KubectlWhoami(ctx)
	if whoami == nil {
		slog.Info("Not checking kubectl", "reason", reason)
	}
	checks := readiness.BuildChecks(group.GroupId, assignments, readiness.Options{
		ARMBaseURL:   AzureClientInstance.ARMBaseURL,
		GraphBaseURL: AzureClientInstance.GraphBaseURL,
		HTTPClient:   client,
		Whoami:       whoami,
	})
	for _, check := range checks {
		slog.Info("Will check", "check", check.Name())
	}

	return &readiness.Waiter{
		Checks: checks,
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
	}
}

func runWait(ctx context.Context, waiter *readiness.Waiter, groupName string) {
	report, err := waiter.Wait(ctx)
	if err != nil {
		slog.Error(
			"Could not confirm that this shell can use the group",
			"group", groupName,
			"error", err.Error(),
			"pending", strings.Join(report.Pending, "; "),
			"hint", "the activation stands; run 'az login' for new tokens, then rerun with '--wait' to check again",
		)
		os.Exit(EXIT_NOT_READY)
	}
	for _, unverified := range report.Unverified {
		slog.Warn("Could not verify", "check", unverified.Name, "reason", unverified.Detail)
	}
	slog.Info("This shell can use the group", "group", groupName, "elapsed", report.Elapsed.Round(time.Second).String())
}

// activeMembership returns the group's live assignment with the eligible
// assignment's access type, or nil when there is none.
func activeMembership(principalId string, token string, group *pim.GraphGroupEligibilityInstance) *pim.GraphGroupAssignmentInstance {
	active := pim.GetActiveGroupAssignments(principalId, token, AzureClientInstance)
	for i := range active.Value {
		instance := &active.Value[i]
		if strings.EqualFold(instance.GroupId, group.GroupId) && strings.EqualFold(instance.AccessId, group.AccessId) {
			return instance
		}
	}
	return nil
}
