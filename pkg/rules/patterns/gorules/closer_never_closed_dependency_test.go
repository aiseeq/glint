package gorules

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const lockdepPath, lockdepVersion = "example.com/lockdep", "v1.0.0"

// lockdepSource is a dependency whose Close only delegates to Unlock: a
// deferred Unlock closes the lock.
var lockdepSource = map[string]string{
	"go.mod": "module " + lockdepPath + "\n\ngo 1.24\n",
	"lock.go": `package lockdep

type Lock struct{ held bool }

func New() *Lock { return &Lock{held: true} }

func (l *Lock) Close() error { return l.Unlock() }

func (l *Lock) Unlock() error {
	l.held = false
	return nil
}
`,
}

const lockdepStoreSource = `package store

import "example.com/lockdep"

func Released() {
	l := lockdep.New()
	defer l.Unlock()
}

func Leaked() {
	l := lockdep.New()
	if l == nil {
		return
	}
}
`

// A dependency's Close is read from its source wherever the go command keeps
// it - the module cache, a directory a replace points at, the vendor
// directory - and the findings are the same whether the go command trims the
// file paths it compiles into export data or not.
func TestCloserNeverClosedDependencyCloseWithTrimpath(t *testing.T) {
	layouts := []struct {
		name  string
		setup func(t *testing.T, root string) []string
	}{
		{name: "module cache", setup: lockdepFromModuleCache},
		{name: "replace directory", setup: lockdepFromReplaceDirectory},
		{name: "vendor", setup: lockdepFromVendor},
	}
	for _, layout := range layouts {
		for _, flags := range []string{"", "-trimpath"} {
			t.Run(layout.name+" "+flags, func(t *testing.T) {
				root := t.TempDir()
				env := layout.setup(t, root)
				for _, kv := range env {
					key, value, _ := strings.Cut(kv, "=")
					if key == "GOFLAGS" {
						value = strings.TrimSpace(value + " " + flags)
					}
					t.Setenv(key, value)
				}
				t.Setenv("GOWORK", "off")
				t.Setenv("GOTOOLCHAIN", "local")
				var contexts []*core.FileContext
				for _, ctx := range rulestest.ModuleIn(t, root, map[string]string{
					"go.mod":         readTestFile(t, filepath.Join(root, "go.mod")),
					"store/store.go": lockdepStoreSource,
				}) {
					if strings.HasPrefix(ctx.RelPath, "store/") {
						contexts = append(contexts, ctx)
					}
				}
				project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
				require.NoError(t, err)
				violations, err := NewCloserNeverClosedRule().AnalyzeGoProject(project)
				require.NoError(t, err)
				require.Equal(t, []string{"store/store.go:11"}, rulestest.ViolationPlaces(violations))
			})
		}
	}
}

// lockdepFromModuleCache serves the dependency from a file proxy into a
// module cache of the test.
func lockdepFromModuleCache(t *testing.T, root string) []string {
	t.Helper()
	proxy := t.TempDir()
	writeLockdepProxy(t, proxy)
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/projecta\n\ngo 1.24\n\nrequire "+lockdepPath+" "+lockdepVersion+"\n")
	return []string{
		"GOMODCACHE=" + t.TempDir(),
		"GOPROXY=file://" + filepath.ToSlash(proxy),
		"GOSUMDB=off",
		"GOFLAGS=-mod=mod -modcacherw",
	}
}

// lockdepFromReplaceDirectory replaces the dependency with a directory of the
// project.
func lockdepFromReplaceDirectory(t *testing.T, root string) []string {
	t.Helper()
	for name, content := range lockdepSource {
		writeTestFile(t, filepath.Join(root, "third_party", "lockdep", name), content)
	}
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/projecta\n\ngo 1.24\n\nrequire "+lockdepPath+" "+lockdepVersion+"\n\nreplace "+lockdepPath+" => ./third_party/lockdep\n")
	return []string{"GOPROXY=off", "GOFLAGS=-mod=mod"}
}

// lockdepFromVendor vendors the dependency from the module cache, and loads
// with an empty one: only the vendor directory holds its source.
func lockdepFromVendor(t *testing.T, root string) []string {
	t.Helper()
	env := lockdepFromModuleCache(t, root)
	writeTestFile(t, filepath.Join(root, "store", "store.go"), lockdepStoreSource)
	for _, args := range [][]string{{"mod", "tidy"}, {"mod", "vendor"}} {
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), append(env, "GOWORK=off", "GOTOOLCHAIN=local")...)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "go %s:\n%s", strings.Join(args, " "), output)
	}
	return []string{"GOMODCACHE=" + t.TempDir(), "GOPROXY=off", "GOFLAGS=-mod=vendor"}
}

// writeLockdepProxy writes the dependency as a module proxy serves it.
func writeLockdepProxy(t *testing.T, proxy string) {
	t.Helper()
	escaped, err := module.EscapePath(lockdepPath)
	require.NoError(t, err)
	dir := filepath.Join(proxy, filepath.FromSlash(escaped), "@v")
	writeTestFile(t, filepath.Join(dir, "list"), lockdepVersion+"\n")
	writeTestFile(t, filepath.Join(dir, lockdepVersion+".info"), `{"Version":"`+lockdepVersion+`","Time":"2026-01-01T00:00:00Z"}`)
	writeTestFile(t, filepath.Join(dir, lockdepVersion+".mod"), lockdepSource["go.mod"])
	source := t.TempDir()
	for name, content := range lockdepSource {
		writeTestFile(t, filepath.Join(source, name), content)
	}
	var archive bytes.Buffer
	require.NoError(t, modzip.CreateFromDir(&archive, module.Version{Path: lockdepPath, Version: lockdepVersion}, source))
	writeTestFile(t, filepath.Join(dir, lockdepVersion+".zip"), archive.String())
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}
