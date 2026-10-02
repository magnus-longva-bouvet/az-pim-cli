package readiness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Token scopes in the global cloud. The Azure Resource Manager scope is the one
// az itself requests, so the checks read the same cached token az commands use.
const (
	armScope     = "https://management.core.windows.net//.default"
	graphScope   = "https://graph.microsoft.com/.default"
	storageScope = "https://storage.azure.com/.default"
	vaultScope   = "https://vault.azure.net/.default"
)

// Data-plane endpoint suffixes in the global cloud. Other clouds use their own
// (blob.core.usgovcloudapi.net, vault.usgovcloudapi.net, ...), so --wait is
// limited to the global cloud.
const (
	blobEndpointSuffix  = ".blob.core.windows.net"
	vaultEndpointSuffix = ".vault.azure.net"
)

// Operations whose grant decides whether a data-plane check applies.
const (
	containerDelete   = "Microsoft.Storage/storageAccounts/blobServices/containers/delete"
	keyDelete         = "Microsoft.KeyVault/vaults/keys/delete"
	certificateDelete = "Microsoft.KeyVault/vaults/certificates/delete"
)

// The captured names become the host of a DELETE, so they are held to Azure's
// naming rules for storage accounts and vaults; a scope naming anything else
// gets no data-plane check.
var (
	storageAccountScope = regexp.MustCompile(`(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Storage/storageAccounts/([a-z0-9]{3,24})$`)
	keyVaultScope       = regexp.MustCompile(`(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/([a-z][a-z0-9-]{1,22}[a-z0-9])$`)
)

// Options says where the checks send their requests.
type Options struct {
	ARMBaseURL   string
	GraphBaseURL string
	HTTPClient   *http.Client
	// Whoami runs `kubectl auth whoami -o json` for kubectl's current context.
	// It is nil when that context does not take its token from az, because then
	// dropping az's cached tokens would not reach kubectl.
	Whoami func(ctx context.Context) ([]byte, error)
}

// BuildChecks turns the group's role assignments into checks:
//
//   - every assignment: ARM's view of this shell's permissions at its scope;
//   - a storage account where the role may delete containers: a container DELETE;
//   - a key vault where the role may delete keys or certificates: a DELETE of each;
//   - kubectl's current context, when it signs in through az: auth whoami.
//
// Data roles held at a broader scope than one account or vault get no
// data-plane check, and neither do read-only data roles: a delete is refused
// for those whether the role is in effect or not. Secrets are never addressed.
// When nothing else can be checked, the group membership in Microsoft Graph
// stands in.
func BuildChecks(groupID string, assignments []Assignment, opts Options) []Check {
	var checks []Check
	seen := map[string]bool{}
	add := func(key string, check Check) {
		if !seen[key] {
			seen[key] = true
			checks = append(checks, check)
		}
	}

	for _, a := range assignments {
		add(strings.ToLower("arm|"+a.Scope+"|"+a.RoleName), armPermissionsCheck{
			name:   fmt.Sprintf("Azure: %s on %s", a.RoleName, a.Scope),
			url:    opts.ARMBaseURL + a.Scope + "/providers/Microsoft.Authorization/permissions?api-version=2022-04-01",
			grant:  a.Grant,
			client: opts.HTTPClient,
		})
	}
	for _, a := range assignments {
		if m := storageAccountScope.FindStringSubmatch(a.Scope); m != nil && allows(a.Grant, containerDelete, false) {
			account := strings.ToLower(m[1])
			add("blob|"+account, blobDeleteCheck{
				name:     "Storage: delete containers in " + account,
				endpoint: "https://" + account + blobEndpointSuffix,
				client:   opts.HTTPClient,
			})
		}
		if m := keyVaultScope.FindStringSubmatch(a.Scope); m != nil {
			vault := strings.ToLower(m[1])
			for _, kv := range []struct{ collection, operation, notFound string }{
				{"keys", keyDelete, "KeyNotFound"},
				{"certificates", certificateDelete, "CertificateNotFound"},
			} {
				if allows(a.Grant, kv.operation, true) {
					add("kv|"+vault+"|"+kv.collection, keyVaultDeleteCheck{
						name:       "Key Vault: delete " + kv.collection + " in " + vault,
						vaultURL:   "https://" + vault + vaultEndpointSuffix,
						collection: kv.collection,
						notFound:   kv.notFound,
						client:     opts.HTTPClient,
					})
				}
			}
		}
	}
	if opts.Whoami != nil {
		add("kube", kubeWhoamiCheck{groupID: groupID, whoami: opts.Whoami})
	}
	if len(checks) == 0 {
		add("graph", graphMemberCheck{
			url:     opts.GraphBaseURL + "/v1.0/me/checkMemberGroups",
			groupID: groupID,
			client:  opts.HTTPClient,
		})
	}
	return checks
}

// probeNamePattern is the only shape a name the DELETE checks address may
// have: the prefix and a random (version 4) UUID, in lower case.
var probeNamePattern = regexp.MustCompile(`^pim-wait-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// randomUUID returns a fresh version 4 UUID, or an error when the system's
// randomness fails or the result is not one, so that a DELETE is never sent
// with anything else.
func randomUUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("no random UUID: %w", err)
	}
	if id.Version() != 4 || id.Variant() != uuid.RFC4122 {
		return "", fmt.Errorf("not a random UUID: %s", id)
	}
	return id.String(), nil
}

// probeName returns a name no real container, key or certificate has. The
// DELETE checks address it, so a check can only ever be refused or told that
// nothing by that name exists. It errs rather than return any other name.
func probeName() (string, error) {
	id, err := randomUUID()
	if err != nil {
		return "", fmt.Errorf("refusing to probe: %w", err)
	}
	return checkedProbeName("pim-wait-" + id)
}

func checkedProbeName(name string) (string, error) {
	if !probeNamePattern.MatchString(name) {
		return "", fmt.Errorf("refusing to probe: %q is not pim-wait-<random UUID>", name)
	}
	return name, nil
}

type armPermissionsCheck struct {
	name   string
	url    string
	grant  []Permission
	client *http.Client
}

func (c armPermissionsCheck) Name() string { return c.name }

// Run asks ARM what this shell's token may do at the scope. ARM answers with
// one entry per role that applies there, so the check passes once the role's
// own entry is among them.
func (c armPermissionsCheck) Run(ctx context.Context, tokens TokenSource) Result {
	token, err := tokens(ctx, armScope)
	if err != nil {
		return unknown("no Azure Resource Manager token: %v", err)
	}
	resp, err := send(ctx, c.client, http.MethodGet, c.url, token, nil, nil)
	if err != nil {
		return unknown("%v", err)
	}
	if resp.status != http.StatusOK {
		return unknown("HTTP %d %s", resp.status, armErrorCode(resp.body))
	}
	var effective struct {
		Value []Permission `json:"value"`
	}
	if err := json.Unmarshal(resp.body, &effective); err != nil {
		return unknown("unreadable permissions: %v", err)
	}
	for _, want := range c.grant {
		if !slices.ContainsFunc(effective.Value, func(got Permission) bool { return sameGrant(got, want) }) {
			return Result{Outcome: Fail, Detail: "the role is not among this token's permissions yet"}
		}
	}
	return Result{Outcome: Pass}
}

type blobDeleteCheck struct {
	name     string
	endpoint string
	client   *http.Client
}

func (c blobDeleteCheck) Name() string { return c.name }

// Run deletes a container by a random name with a random lease id, which
// cannot remove anything: no such container answers 404, and one that existed
// would answer 412 for the lease. Storage checks the caller's role before it
// looks the container up, so 403 AuthorizationPermissionMismatch means the
// role is not in effect for this token yet.
func (c blobDeleteCheck) Run(ctx context.Context, tokens TokenSource) Result {
	token, err := tokens(ctx, storageScope)
	if err != nil {
		return unknown("no Storage token: %v", err)
	}
	name, err := probeName()
	if err != nil {
		return unknown("%v", err)
	}
	leaseID, err := randomUUID()
	if err != nil {
		return unknown("refusing to probe without a random lease id: %v", err)
	}
	header := http.Header{}
	header.Set("x-ms-version", "2023-11-03")
	header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	header.Set("x-ms-lease-id", leaseID)
	resp, err := send(ctx, c.client, http.MethodDelete, c.endpoint+"/"+name+"?restype=container", token, header, nil)
	if err != nil {
		return unknown("%v", err)
	}
	code := resp.header.Get("x-ms-error-code")
	switch {
	case resp.status == http.StatusNotFound && code == "ContainerNotFound",
		resp.status == http.StatusPreconditionFailed && strings.HasPrefix(code, "Lease"):
		return Result{Outcome: Pass}
	case resp.status == http.StatusForbidden && code == "AuthorizationPermissionMismatch":
		return Result{Outcome: Fail, Detail: code}
	default:
		// 403 AuthorizationFailure is the storage firewall, not the role.
		return unknown("HTTP %d %s", resp.status, code)
	}
}

type keyVaultDeleteCheck struct {
	name       string
	vaultURL   string
	collection string
	notFound   string
	client     *http.Client
}

func (c keyVaultDeleteCheck) Name() string { return c.name }

// Run is the container check's idea for Key Vault. A vault has no lease to
// guard with, so the name's randomness is what keeps the DELETE off real keys
// and certificates.
func (c keyVaultDeleteCheck) Run(ctx context.Context, tokens TokenSource) Result {
	token, err := tokens(ctx, vaultScope)
	if err != nil {
		return unknown("no Key Vault token: %v", err)
	}
	name, err := probeName()
	if err != nil {
		return unknown("%v", err)
	}
	resp, err := send(ctx, c.client, http.MethodDelete, c.vaultURL+"/"+c.collection+"/"+name+"?api-version=7.4", token, nil, nil)
	if err != nil {
		return unknown("%v", err)
	}
	code := keyVaultErrorCode(resp.body)
	switch {
	case resp.status == http.StatusNotFound && code == c.notFound:
		return Result{Outcome: Pass}
	case resp.status == http.StatusForbidden && code == "ForbiddenByRbac":
		return Result{Outcome: Fail, Detail: code}
	default:
		// ForbiddenByFirewall and ForbiddenByConnection are the vault's network rules.
		return unknown("HTTP %d %s", resp.status, code)
	}
}

type kubeWhoamiCheck struct {
	groupID string
	whoami  func(ctx context.Context) ([]byte, error)
}

func (c kubeWhoamiCheck) Name() string { return "kubectl: the group in 'kubectl auth whoami'" }

// Run asks the API server of kubectl's current context who this shell is. Its
// RBAC bindings are matched against the groups it lists.
func (c kubeWhoamiCheck) Run(ctx context.Context, _ TokenSource) Result {
	out, err := c.whoami(ctx)
	if err != nil {
		return unknown("%v", err)
	}
	var review struct {
		Status struct {
			UserInfo struct {
				Groups []string `json:"groups"`
			} `json:"userInfo"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &review); err != nil {
		return unknown("unreadable 'kubectl auth whoami' output: %v", err)
	}
	if slices.ContainsFunc(review.Status.UserInfo.Groups, func(g string) bool { return strings.EqualFold(g, c.groupID) }) {
		return Result{Outcome: Pass}
	}
	return Result{Outcome: Fail, Detail: "the API server does not list the group for this token yet"}
}

type graphMemberCheck struct {
	url     string
	groupID string
	client  *http.Client
}

func (c graphMemberCheck) Name() string { return "Microsoft Graph: membership of the group" }

// Run asks Microsoft Graph whether the signed-in user is a member of the group.
// It only stands in when nothing the group grants can be checked: the
// directory reports a membership a little later than new tokens carry it, and
// it says nothing about this shell's tokens.
func (c graphMemberCheck) Run(ctx context.Context, tokens TokenSource) Result {
	token, err := tokens(ctx, graphScope)
	if err != nil {
		return unknown("no Microsoft Graph token: %v", err)
	}
	body, err := json.Marshal(map[string][]string{"groupIds": {c.groupID}})
	if err != nil {
		return unknown("%v", err)
	}
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	resp, err := send(ctx, c.client, http.MethodPost, c.url, token, header, bytes.NewReader(body))
	if err != nil {
		return unknown("%v", err)
	}
	if resp.status != http.StatusOK {
		return unknown("HTTP %d %s", resp.status, armErrorCode(resp.body))
	}
	var groups struct {
		Value []string `json:"value"`
	}
	if err := json.Unmarshal(resp.body, &groups); err != nil {
		return unknown("unreadable membership answer: %v", err)
	}
	if slices.ContainsFunc(groups.Value, func(g string) bool { return strings.EqualFold(g, c.groupID) }) {
		return Result{Outcome: Pass}
	}
	return Result{Outcome: Fail, Detail: "Microsoft Graph does not list the membership yet"}
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func send(ctx context.Context, client *http.Client, method, url, token string, header http.Header, body io.Reader) (response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return response{}, err
	}
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return response{}, err
	}
	return response{status: res.StatusCode, header: res.Header, body: data}, nil
}

// armErrorCode reads the code from an ARM or Microsoft Graph error body.
func armErrorCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error.Code
}

// keyVaultErrorCode prefers the inner code: Key Vault puts the reason for a
// 403 (ForbiddenByRbac, ForbiddenByFirewall) there, under a generic Forbidden.
func keyVaultErrorCode(body []byte) string {
	var e struct {
		Error struct {
			Code       string `json:"code"`
			InnerError struct {
				Code string `json:"code"`
			} `json:"innererror"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	if e.Error.InnerError.Code != "" {
		return e.Error.InnerError.Code
	}
	return e.Error.Code
}

func unknown(format string, args ...any) Result {
	return Result{Outcome: Unknown, Detail: fmt.Sprintf(format, args...)}
}
