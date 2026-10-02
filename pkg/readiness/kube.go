package readiness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// KubectlWhoami returns a function running `kubectl auth whoami` for kubectl's
// current context, or nil and the reason no such check applies: kubectl is
// missing, there is no current context, or the context does not take its token
// from az. Only kubelogin in azurecli mode does; other modes keep their own
// token cache, which dropping az's cached tokens would not reach.
func KubectlWhoami(ctx context.Context) (whoami func(context.Context) ([]byte, error), reason string) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return nil, "kubectl is not installed"
	}
	view, err := exec.CommandContext(ctx, "kubectl", "config", "view", "--minify", "-o", "json").Output()
	if err != nil {
		return nil, "kubectl has no current context"
	}
	if reason := azureCLIContextProblem(view); reason != "" {
		return nil, reason
	}
	return runWhoami, ""
}

func runWhoami(ctx context.Context) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "auth", "whoami", "-o", "json", "--request-timeout=20s")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl auth whoami: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// azureCLIContextProblem reads `kubectl config view --minify -o json` and says
// why its context does not sign in through az, or returns "" when it does.
func azureCLIContextProblem(view []byte) string {
	var config struct {
		CurrentContext string `json:"current-context"`
		Users          []struct {
			User struct {
				Exec *struct {
					Command string   `json:"command"`
					Args    []string `json:"args"`
				} `json:"exec"`
			} `json:"user"`
		} `json:"users"`
	}
	if err := json.Unmarshal(view, &config); err != nil {
		return "unreadable kubeconfig"
	}
	if len(config.Users) == 0 || config.Users[0].User.Exec == nil {
		return fmt.Sprintf("context %q does not sign in through an exec plugin", config.CurrentContext)
	}
	plugin := config.Users[0].User.Exec
	if name := strings.TrimSuffix(filepath.Base(plugin.Command), ".exe"); name != "kubelogin" {
		return fmt.Sprintf("context %q signs in through %s, not kubelogin", config.CurrentContext, name)
	}
	if mode := kubeloginMode(plugin.Args); mode != "azurecli" {
		return fmt.Sprintf("context %q uses kubelogin --login %s, which keeps its own token cache", config.CurrentContext, mode)
	}
	return ""
}

// kubeloginMode is the --login value, falling back the way kubelogin does: to
// $AAD_LOGIN_METHOD, then devicecode.
func kubeloginMode(args []string) string {
	for i, arg := range args {
		if value, ok := strings.CutPrefix(arg, "--login="); ok {
			return value
		}
		if (arg == "--login" || arg == "-l") && i+1 < len(args) {
			return args[i+1]
		}
	}
	if mode := os.Getenv("AAD_LOGIN_METHOD"); mode != "" {
		return mode
	}
	return "devicecode"
}
