package patterns

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewRepoRootMarkerFileMissingRule())
}

// RepoRootMarkerFileMissingRule detects a script that recognizes the
// repository root by a file the repository no longer has:
//
//	if (existsSync(path.join(dir, 'VERSION')) && existsSync(path.join(dir, 'Makefile'))) return dir
//	if (!fs.existsSync(path.join(projectRoot, 'Makefile'))) fail('run inside the repository')
//
// The Makefile went away in a clean-up, and the walk up never finds the root
// or the guard refuses to run. A probe counts as a marker when it decides
// where the root is: found, it returns; missing, it fails. The name is looked
// for in the file's own directory and every directory above it.
type RepoRootMarkerFileMissingRule struct {
	*rules.BaseRule
}

// NewRepoRootMarkerFileMissingRule creates the rule
func NewRepoRootMarkerFileMissingRule() *RepoRootMarkerFileMissingRule {
	return &RepoRootMarkerFileMissingRule{BaseRule: rules.NewBaseRule(
		"repo-root-marker-file-missing",
		"patterns",
		"Detects a script finding the repository root by a marker file (existsSync(path.join(dir, 'Makefile'))) that exists in no directory above it — the root is never found",
		core.SeverityHigh,
	)}
}

// ReadsOtherFiles reports that the findings depend on the files around.
func (r *RepoRootMarkerFileMissingRule) ReadsOtherFiles() bool { return true }

var (
	markerProbe = regexp.MustCompile(`(!\s*)?(?:fs\.)?existsSync\s*\(\s*(?:path\.)?(?:join|resolve)\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*['"]([^'"/\\$]+)['"]\s*\)\s*\)`)
	rootFailure = regexp.MustCompile(`\b(?:throw|fail|exit)\b`)
)

// AnalyzeFile reports the root markers of a script that exist nowhere above
// it.
func (r *RepoRootMarkerFileMissingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || ctx.Path == "" {
		return nil
	}
	src := newJSSource(ctx)
	var violations []*core.Violation
	for i, line := range src.text {
		for _, m := range markerProbe.FindAllStringSubmatchIndex(line, -1) {
			base, name := strings.ToLower(line[m[4]:m[5]]), line[m[6]:m[7]]
			if !strings.Contains(base, "root") && !strings.Contains(base, "dir") {
				continue
			}
			if !decidesRoot(src.code, i, m[2] >= 0, line[m[4]:m[5]]) || existsAbove(filepath.Dir(ctx.Path), name) || ctx.IsSuppressed(i+1, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, i+1,
				"'"+name+"' is probed as a marker of the repository root, and no directory from here up has it — the root is never found")
			v.WithCode(strings.TrimSpace(ctx.GetLine(i + 1)))
			v.WithSuggestion("Probe a file the repository root keeps (VERSION, .git, the build configuration it uses now)")
			violations = append(violations, v)
		}
	}
	return violations
}

// decidesRoot reports a probe whose answer decides the root: found, the
// line or the next returns the directory probed; negated, the line or the
// next two fail.
func decidesRoot(code []string, line int, negated bool, dir string) bool {
	window := func(n int) string {
		return strings.Join(code[line:min(line+n, len(code))], "\n")
	}
	if negated {
		return rootFailure.MatchString(window(3))
	}
	words := strings.FieldsFunc(window(2), func(c rune) bool { return !isJSIdentRune(c) })
	for k := 0; k+1 < len(words); k++ {
		if words[k] == "return" && words[k+1] == dir {
			return true
		}
	}
	return false
}

// isJSIdentRune reports a rune of a JavaScript identifier.
func isJSIdentRune(c rune) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// existsAbove reports a file of the name in dir or any directory above it.
func existsAbove(dir, name string) bool {
	for {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}
