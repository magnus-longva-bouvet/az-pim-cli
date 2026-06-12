/*
Copyright © 2023 netr0m <netr0m@pm.me>
*/
package pim

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBrowserCommand(t *testing.T) {
	const url = "https://login.microsoftonline.com/common"
	tests := []struct {
		name     string
		entry    string
		wantName string
		wantArgs []string
		wantOK   bool
	}{
		{"simple command appends url", "firefox", "firefox", []string{url}, true},
		{"placeholder substitution", "chromium --app=%s", "chromium", []string{"--app=" + url}, true},
		{"flags then appended url", "open -a Safari", "open", []string{"-a", "Safari", url}, true},
		{"trailing ampersand ignored", "firefox &", "firefox", []string{url}, true},
		{"empty entry", "   ", "", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, args, ok := browserCommand(tt.entry, url)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantArgs, args)
		})
	}
}

func TestTokenCachePath(t *testing.T) {
	t.Run("prefers AZURE_CONFIG_DIR when set", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("AZURE_CONFIG_DIR", dir)

		assert.Equal(t, filepath.Join(dir, TOKEN_CACHE_FILE_NAME), tokenCachePath())
	})

	t.Run("falls back to the home directory", func(t *testing.T) {
		t.Setenv("AZURE_CONFIG_DIR", "")

		home, err := os.UserHomeDir()
		if err != nil {
			t.Skipf("home directory unavailable: %v", err)
		}
		assert.Equal(t, filepath.Join(home, TOKEN_CACHE_FILE_NAME), tokenCachePath())
	})
}

func TestOpenURLHonorsBrowserEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on a POSIX shell script")
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "called.txt")
	script := filepath.Join(dir, "fakebrowser.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \"$1\" > \""+marker+"\"\n"), 0o755); err != nil { //nolint:gosec // test helper script must be executable
		t.Fatal(err)
	}
	t.Setenv("BROWSER", script)

	const url = "https://example.com/auth"
	if err := openURL(url); err != nil {
		t.Fatal(err)
	}

	// openURL starts the browser command asynchronously, so poll for the result.
	var got string
	for range 100 {
		if data, err := os.ReadFile(marker); err == nil {
			got = string(data)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.Equal(t, url, got, "openURL should have invoked the BROWSER command with the URL")
}
