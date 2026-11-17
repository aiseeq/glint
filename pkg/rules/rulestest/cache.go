package rulestest

import (
	"os"
	"path/filepath"
	"testing"
)

// IsolateUserCache gives a test a fresh XDG cache directory while preserving
// the user's Go build cache. Without an explicit GOCACHE, the go command uses
// XDG_CACHE_HOME/go-build on Linux.
func IsolateUserCache(t *testing.T, dir string) {
	t.Helper()
	if os.Getenv("GOCACHE") == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("GOCACHE", filepath.Join(base, "go-build"))
	}
	t.Setenv("XDG_CACHE_HOME", dir)
}
