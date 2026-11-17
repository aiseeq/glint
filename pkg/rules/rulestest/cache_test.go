package rulestest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsolateUserCachePreservesGoBuildCache(t *testing.T) {
	dir := t.TempDir()
	wasSet := os.Getenv("GOCACHE") != ""
	want := os.Getenv("GOCACHE")
	if !wasSet {
		base, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		want = filepath.Join(base, "go-build")
	}

	IsolateUserCache(t, dir)

	out, err := exec.Command("go", "env", "GOCACHE").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		t.Errorf("go env GOCACHE = %q, want %q", got, want)
	}
	if got := os.Getenv("XDG_CACHE_HOME"); got != dir {
		t.Errorf("XDG_CACHE_HOME = %q, want %q", got, dir)
	}
}
