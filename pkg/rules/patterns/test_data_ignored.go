package patterns

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(&testDataIgnoredRule{BaseRule: rules.NewBaseRule("test-data-ignored-by-git", "patterns",
		"Detects a test that reads a testdata directory holding files .gitignore leaves out of the repository — the test passes where the files were made and fails on a fresh clone",
		core.SeverityHigh)})
}

type testDataIgnoredRule struct{ *rules.BaseRule }

// ReadsOtherFiles reports that the findings depend on testdata and .gitignore.
func (r *testDataIgnoredRule) ReadsOtherFiles() bool { return true }

var (
	testDataLiteral = regexp.MustCompile(`"(testdata/[^"]*)"`)
	testDataJoin    = regexp.MustCompile(`"testdata"((?:\s*,\s*"[^"]*")*)`)
	joinPart        = regexp.MustCompile(`"([^"]*)"`)
)

// AnalyzeFile reports each testdata path of a Go test whose directory holds
// files git ignores.
func (r *testDataIgnoredRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !strings.HasSuffix(ctx.Path, "_test.go") {
		return nil
	}
	pkgDir := filepath.Dir(ctx.Path)
	checked := map[string]bool{}
	var out []*core.Violation
	for i, line := range ctx.Lines {
		for _, rel := range testDataPaths(line) {
			dir := testDataSubtree(rel)
			if checked[dir] || ctx.IsSuppressed(i+1, r.Name()) {
				continue
			}
			checked[dir] = true
			ignored, err := ignoredUnder(filepath.Join(pkgDir, dir))
			switch {
			case err != nil:
				out = append(out, r.CreateViolation(ctx.RelPath, i+1, dir+" could not be checked against .gitignore: "+err.Error()))
			case len(ignored) > 0:
				v := r.CreateViolation(ctx.RelPath, i+1,
					dir+" holds files .gitignore leaves out of the repository ("+strings.Join(firstOf(ignored, 3), ", ")+") — the test passes where they were made and fails on a fresh clone")
				v.Suggestion = "Commit the files the test needs (a !pattern in .gitignore for them), or let the test make them"
				out = append(out, v)
			}
		}
	}
	return out
}

// testDataPaths returns the testdata paths a line names: "testdata/x/y" or
// filepath.Join("testdata", "x", "y").
func testDataPaths(line string) []string {
	var out []string
	for _, m := range testDataLiteral.FindAllStringSubmatch(line, -1) {
		out = append(out, m[1])
	}
	for _, m := range testDataJoin.FindAllStringSubmatch(line, -1) {
		parts := []string{"testdata"}
		for _, p := range joinPart.FindAllStringSubmatch(m[1], -1) {
			parts = append(parts, p[1])
		}
		out = append(out, strings.Join(parts, "/"))
	}
	return out
}

// testDataSubtree returns the directory of testdata a path belongs to: the
// first directory under testdata, whose files one test reads together.
func testDataSubtree(rel string) string {
	parts := strings.Split(rel, "/")
	if len(parts) <= 2 || strings.ContainsAny(parts[1], "*?[") {
		return "testdata"
	}
	return "testdata/" + parts[1]
}

// ignoredUnder returns the ignored files of a directory; none when there is
// no such directory - the test makes it, or names a file.
func ignoredUnder(dir string) ([]string, error) {
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("stat %s: %w", dir, err)
	case !info.IsDir():
		return nil, nil
	}
	return core.IgnoredFiles(dir)
}

func firstOf(list []string, n int) []string {
	if len(list) > n {
		return append(list[:n:n], "...")
	}
	return list
}
