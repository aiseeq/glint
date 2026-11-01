package qarules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Repro from a real project: a test read recordings from testdata that
// .gitignore left out of the repository - it passed on the author's machine
// and failed on a fresh clone.
func TestTestDataIgnoredByGit(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, ".git"), 0o755))
	patterntest.WriteFiles(t, root, map[string]string{
		".gitignore":                         "*.rep\nlogs/\n!keep/testdata/**/*.rep\n",
		"report/testdata/idle/logs/x.log":    "log\n",
		"report/testdata/idle/replays/a.rep": "replay\n",
		"report/testdata/plain/x.txt":        "kept\n",
		"report/idle_test.go": `package report

import "testing"

func TestIdle(t *testing.T) {
	log := "testdata/idle/logs/x.log" // want
	_ = log
	plain := filepath.Join("testdata", "plain", "x.txt")
	_ = plain
}
`,
		"keep/testdata/replays/b.rep": "replay\n",
		"keep/keep_test.go": `package keep

import "testing"

func TestKeep(t *testing.T) {
	_ = "testdata/replays/b.rep"
}
`,
		"glob/testdata/runs/c.rep": "replay\n",
		"glob/glob_test.go": `package glob

import (
	"path/filepath"
	"testing"
)

func TestGlob(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "runs", "*.rep")) // want
	_ = files
}
`,
	})
	got := patterntest.ShellFindingsIn(t, "test-data-ignored-by-git", root, "report/idle_test.go", "keep/keep_test.go", "glob/glob_test.go")
	assert.Equal(t, []string{"glob/glob_test.go:9", "report/idle_test.go:6"}, got)
}

// Every test of a package names the same testdata directory; on a large root
// walking it once per test file took seconds, so a run walks it once.
func TestTestDataIgnoredWalksEachDirectoryOnce(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, ".git"), 0o755))
	files := map[string]string{
		".gitignore":                  "*.rep\n",
		"report/testdata/runs/a.rep":  "replay\n",
		"report/testdata/runs/b.json": "{}\n",
	}
	var tests []string
	for _, name := range []string{"a", "b", "c"} {
		path := "report/" + name + "_test.go"
		files[path] = "package report\n\nvar _ = \"testdata/runs/a.rep\"\n"
		tests = append(tests, path)
	}
	patterntest.WriteFiles(t, root, files)
	walks := 0
	real := listIgnoredFiles
	listIgnoredFiles = func(dir string) ([]string, error) {
		walks++
		return real(dir)
	}
	t.Cleanup(func() { listIgnoredFiles = real })

	got := patterntest.ShellFindingsIn(t, "test-data-ignored-by-git", root, tests...)

	assert.Equal(t, []string{"report/a_test.go:3", "report/b_test.go:3", "report/c_test.go:3"}, got)
	assert.Equal(t, 1, walks)
}
