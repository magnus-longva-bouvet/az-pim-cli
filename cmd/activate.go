/*
Copyright © 2023 netr0m <netr0m@pm.me>
*/
package cmd

import (
	"os"
	"time"

	"log/slog"

	"github.com/netr0m/az-pim-cli/pkg/pim"
	"github.com/netr0m/az-pim-cli/pkg/utils"
	"github.com/spf13/cobra"
)

var name string
var prefix string
var roleName string
var duration int
var startDate string
var startTime string
var reason string
var ticketSystem string
var ticketNumber string
var dryRun bool
var validateOnly bool
var resourceScope string
var extend bool

// Exit code for "--extend, but there is no live assignment to extend". Distinct
// from 1 so a caller looping over many groups can tell "nothing to do here" apart
// from a genuine failure without parsing log output.
const EXIT_NOT_ACTIVE = 3

var activateCmd = &cobra.Command{
	Use:     "activate",
	Aliases: []string{"a", "ac", "act"},
	Short:   "Send a request to Azure PIM to activate a role assignment",
	Run:     func(cmd *cobra.Command, args []string) {},
}

var activateResourceCmd = &cobra.Command{
	Use:     "resource",
	Aliases: []string{"r", "res", "resource", "resources", "sub", "subs", "subscriptions"},
	Short:   "Sends a request to Azure PIM to activate the given resource (azure resources)",
	Run: func(cmd *cobra.Command, args []string) {
		token := pim.GetAccessToken(AzureClientInstance.ARMBaseURL, AzureClientInstance)
		subjectId := pim.GetUserInfo(token).ObjectId

		eligibleResourceAssignments := pim.GetEligibleResourceAssignments(token, AzureClientInstance)
		resourceAssignment := utils.GetResourceAssignment(name, prefix, roleName, eligibleResourceAssignments)
		scope, assignmentRequest := pim.CreateResourceAssignmentRequestWithScope(subjectId, resourceAssignment, resourceScope, duration, startDate, startTime, reason, ticketSystem, ticketNumber)

		slog.Info(
			"Requesting activation",
			"role", resourceAssignment.Properties.ExpandedProperties.RoleDefinition.DisplayName,
			"scope", scope,
			"reason", reason,
			"ticketNumber", ticketNumber,
			"ticketSystem", ticketSystem,
			"duration", duration,
			"startDateTime", assignmentRequest.Properties.ScheduleInfo.StartDateTime,
			"cloud", azureEnv,
		)

		if dryRun {
			slog.Warn("Skipping activation due to '--dry-run'")
			os.Exit(0)
		}
		if validateOnly {
			slog.Warn("Running validation only")
			validationSuccessful := pim.ValidateResourceAssignmentRequest(scope, assignmentRequest, token, AzureClientInstance)
			if validationSuccessful {
				os.Exit(0)
			}
			os.Exit(1)
		}
		requestResponse := pim.RequestResourceAssignment(scope, assignmentRequest, token, AzureClientInstance)
		slog.Info(
			"Request completed",
			"role", resourceAssignment.Properties.ExpandedProperties.RoleDefinition.DisplayName,
			"scope", scope,
			"status", requestResponse.Properties.Status,
		)
	},
}

func startDateTimeDisplay(scheduleInfo *pim.GraphScheduleInfo) string {
	if scheduleInfo != nil && scheduleInfo.StartDateTime != nil {
		return *scheduleInfo.StartDateTime
	}
	return "immediate"
}

// extendGroupAssignment pushes the end of an already-active group assignment out to
// "now + duration".
//
// Two cases are deliberately not failures, because the caller's question is "do I
// have this group for the next N minutes", and in both the answer is already yes or
// is not this command's business:
//
//   - Nothing active for the group -> exit EXIT_NOT_ACTIVE. Extending something you
//     have not activated is meaningless; the caller decides whether to activate.
//   - More than N minutes already left, or a permanent assignment -> exit 0 having
//     sent nothing. selfExtend replaces the schedule outright rather than adding to
//     it, so requesting "now + 2h" while three hours remain would *shorten* access.
//     That is the one outcome an extend flag must never produce silently.
func extendGroupAssignment(principalId string, token string) {
	activeAssignments := pim.GetActiveGroupAssignments(principalId, token, AzureClientInstance)
	groupAssignment := utils.FindActiveGroupAssignment(name, prefix, roleName, activeAssignments)
	if groupAssignment == nil {
		slog.Warn(
			"No active assignment to extend",
			"group", nameOrPrefix(),
			"hint", "activate it first, or drop '--extend'",
		)
		os.Exit(EXIT_NOT_ACTIVE)
	}

	groupName := groupAssignment.GroupId
	if groupAssignment.Group != nil {
		groupName = groupAssignment.Group.DisplayName
	}

	requestedEnd := time.Now().UTC().Add(time.Duration(duration) * time.Minute)
	if groupAssignment.EndDateTime == nil {
		slog.Info(
			"Assignment does not expire; nothing to extend",
			"group", groupName,
			"accessId", groupAssignment.AccessId,
		)
		return
	}
	currentEnd, err := time.Parse(time.RFC3339, *groupAssignment.EndDateTime)
	if err != nil {
		slog.Error("Could not parse the current assignment end time", "group", groupName, "endDateTime", *groupAssignment.EndDateTime, "error", err.Error())
		os.Exit(1)
	}
	if !currentEnd.Before(requestedEnd) {
		slog.Info(
			"Assignment already lasts longer than requested; leaving it alone",
			"group", groupName,
			"accessId", groupAssignment.AccessId,
			"currentEnd", currentEnd.UTC().Format(time.RFC3339),
			"requestedEnd", requestedEnd.Format(time.RFC3339),
		)
		return
	}

	extendRequest := pim.CreateGraphGroupExtendRequest(principalId, groupAssignment, duration, reason, ticketSystem, ticketNumber)
	slog.Info(
		"Requesting extension",
		"group", groupName,
		"accessId", groupAssignment.AccessId,
		"reason", reason,
		"ticketNumber", ticketNumber,
		"ticketSystem", ticketSystem,
		"duration", duration,
		"currentEnd", currentEnd.UTC().Format(time.RFC3339),
		"requestedEnd", requestedEnd.Format(time.RFC3339),
		"cloud", azureEnv,
	)

	if dryRun {
		slog.Warn("Skipping extension due to '--dry-run'")
		os.Exit(0)
	}
	requestResponse := pim.RequestGroupAssignment(extendRequest, token, AzureClientInstance)
	slog.Info(
		"Request completed",
		"group", groupName,
		"accessId", groupAssignment.AccessId,
		"status", requestResponse.Status,
	)
}

// nameOrPrefix reports whichever selector the user actually passed, for messages
// emitted before any assignment has been resolved to a display name.
func nameOrPrefix() string {
	if name != "" {
		return name
	}
	return prefix
}

func activateGovernanceRole(roleType string) {
	if !pim.IsGovernanceRoleType(roleType) {
		slog.Error("Invalid role type specified.")
		os.Exit(1)
	}
	requireGraphClient()
	if validateOnly {
		slog.Error("'--validate-only' is not supported for group/role activation via Microsoft Graph; use '--dry-run' to preview instead")
		os.Exit(1)
	}

	token := pim.GetAccessToken(AzureClientInstance.GraphScope, AzureClientInstance)
	principalId := pim.GetUserInfo(token).ObjectId

	switch roleType {
	case pim.ROLE_TYPE_AAD_GROUPS:
		if extend {
			extendGroupAssignment(principalId, token)
			return
		}
		eligibleAssignments := pim.GetEligibleGroupAssignments(principalId, token, AzureClientInstance)
		groupAssignment := utils.GetEligibleGroupAssignment(name, prefix, roleName, eligibleAssignments)
		assignmentRequest := pim.CreateGraphGroupAssignmentRequest(principalId, groupAssignment, duration, startDate, startTime, reason, ticketSystem, ticketNumber)

		groupName := groupAssignment.GroupId
		if groupAssignment.Group != nil {
			groupName = groupAssignment.Group.DisplayName
		}
		slog.Info(
			"Requesting activation",
			"group", groupName,
			"accessId", groupAssignment.AccessId,
			"reason", reason,
			"ticketNumber", ticketNumber,
			"ticketSystem", ticketSystem,
			"duration", duration,
			"startDateTime", startDateTimeDisplay(assignmentRequest.ScheduleInfo),
			"cloud", azureEnv,
		)

		if dryRun {
			slog.Warn("Skipping activation due to '--dry-run'")
			os.Exit(0)
		}
		requestResponse := pim.RequestGroupAssignment(assignmentRequest, token, AzureClientInstance)
		slog.Info(
			"Request completed",
			"group", groupName,
			"accessId", groupAssignment.AccessId,
			"status", requestResponse.Status,
		)
	case pim.ROLE_TYPE_ENTRA_ROLES:
		eligibleAssignments := pim.GetEligibleRoleAssignments(principalId, token, AzureClientInstance)
		roleAssignment := utils.GetEligibleRoleAssignment(name, prefix, roleName, eligibleAssignments)
		assignmentRequest := pim.CreateGraphRoleAssignmentRequest(principalId, roleAssignment, duration, startDate, startTime, reason, ticketSystem, ticketNumber)

		displayName := roleAssignment.RoleDefinitionId
		if roleAssignment.RoleDefinition != nil {
			displayName = roleAssignment.RoleDefinition.DisplayName
		}
		slog.Info(
			"Requesting activation",
			"role", displayName,
			"reason", reason,
			"ticketNumber", ticketNumber,
			"ticketSystem", ticketSystem,
			"duration", duration,
			"startDateTime", startDateTimeDisplay(assignmentRequest.ScheduleInfo),
			"cloud", azureEnv,
		)

		if dryRun {
			slog.Warn("Skipping activation due to '--dry-run'")
			os.Exit(0)
		}
		requestResponse := pim.RequestRoleAssignment(assignmentRequest, token, AzureClientInstance)
		slog.Info(
			"Request completed",
			"role", displayName,
			"status", requestResponse.Status,
		)
	}
}

var activateGroupCmd = &cobra.Command{
	Use:     "group",
	Aliases: []string{"g", "grp", "groups"},
	Short:   "Sends a request to Azure PIM to activate the given group",
	Run: func(cmd *cobra.Command, args []string) {
		activateGovernanceRole(pim.ROLE_TYPE_AAD_GROUPS)
	},
}

var activateEntraRoleCmd = &cobra.Command{
	Use:     "role",
	Aliases: []string{"rl", "role", "roles"},
	Short:   "Sends a request to Azure PIM to activate the given Entra role",
	Run: func(cmd *cobra.Command, args []string) {
		activateGovernanceRole(pim.ROLE_TYPE_ENTRA_ROLES)
	},
}

func init() {
	rootCmd.AddCommand(activateCmd)
	activateCmd.AddCommand(activateResourceCmd)
	activateCmd.AddCommand(activateGroupCmd)
	activateCmd.AddCommand(activateEntraRoleCmd)

	// Flags
	activateCmd.PersistentFlags().StringVarP(&name, "name", "n", "", "The name of the resource to activate")
	activateCmd.PersistentFlags().StringVarP(&prefix, "prefix", "p", "", "The name prefix of the resource to activate (e.g. 'S399'). Alternative to 'name'.")
	activateCmd.PersistentFlags().StringVarP(&roleName, "role", "r", "", "Specify the role to activate, if multiple roles are found for a resource (e.g. 'Owner' and 'Contributor')")
	activateCmd.PersistentFlags().IntVarP(&duration, "duration", "d", pim.DEFAULT_DURATION_MINUTES, "Duration in minutes that the role should be activated for")
	activateCmd.PersistentFlags().StringVar(&startDate, "start-date", "", "Start date for the activation (as DD/MM/YYYY)")
	activateCmd.PersistentFlags().StringVarP(&startTime, "start-time", "s", "", "Start time for the activation (as HH:MM)")
	activateCmd.PersistentFlags().StringVar(&reason, "reason", pim.DEFAULT_REASON, "Reason for the activation")
	activateCmd.PersistentFlags().StringVar(&ticketSystem, "ticket-system", "", "Ticket system for the activation")
	activateCmd.PersistentFlags().StringVarP(&ticketNumber, "ticket-number", "T", "", "Ticket number for the activation")
	activateGroupCmd.PersistentFlags().BoolVar(&extend, "extend", false, "Extend an already-active group assignment to 'now + --duration' instead of activating. Never shortens: if more time than that is already left, nothing is requested. Exits 3 if the group is not currently active.")
	activateCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Display the resource that would be activated, without requesting the activation")
	activateCmd.PersistentFlags().BoolVarP(&validateOnly, "validate-only", "v", false, "Send the request to the validation endpoint of Azure PIM, without requesting the activation")

	activateCmd.MarkFlagsOneRequired("name", "prefix")
	activateCmd.MarkFlagsMutuallyExclusive("name", "prefix")

	activateResourceCmd.Flags().StringVar(&resourceScope, "scope", "", "The scope to activate the resource role at, if different from the eligible assignment scope")
}
