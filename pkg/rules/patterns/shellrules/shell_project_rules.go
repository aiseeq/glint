package shellrules

import (
	"path"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// shellProjectRule is a shell rule that needs to know which files of the
// root exist.
type shellProjectRule struct {
	*shellRule
	paths map[string]bool
}

// UseProjectFiles records the root's paths.
func (r *shellProjectRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	for _, ctx := range files {
		r.paths[ctx.RelPath] = true
	}
}

// ResetState drops the root's files.
func (r *shellProjectRule) ResetState() {
	r.paths = make(map[string]bool)
}

func init() {
	missing := &shellProjectRule{}
	missing.shellRule = newShellRule("shell-script-reference-missing",
		"Detects a script that runs a sibling script ($SCRIPT_DIR/name.sh) which does not exist next to it",
		core.SeverityHigh, func(_ *shellRule, src *patternkit.ShellSource) []*core.Violation {
			return checkMissingScript(missing, src)
		})
	missing.ResetState()
	rules.Register(missing)
}

var (
	scriptDirAssign  = regexp.MustCompile(`^\s*(?:readonly\s+|local\s+)?([A-Za-z_][A-Za-z0-9_]*)=.*(?:dirname|BASH_SOURCE)`)
	siblingScriptRef = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/([A-Za-z0-9_.-]+\.sh)\b|\$\(dirname\s+"?\$\{?0\}?"?\)/([A-Za-z0-9_.-]+\.sh)\b`)
	existenceTest    = regexp.MustCompile(`(?:\[\[?|test)\s+!?\s*-[efxrs]\s`)
)

// checkMissingScript reports $SCRIPT_DIR/name.sh when no name.sh exists in
// the script's own directory.
func checkMissingScript(r *shellProjectRule, src *patternkit.ShellSource) []*core.Violation {
	if src.Make {
		return nil
	}
	dirVars := make(map[string]bool)
	for _, l := range src.Lines {
		if m := scriptDirAssign.FindStringSubmatch(l.Text); m != nil && !strings.Contains(l.Text, "/..") {
			dirVars[m[1]] = true
		}
	}
	dir := path.Dir(src.Ctx.RelPath)
	var out []*core.Violation
	for _, l := range src.Lines {
		if strings.Contains(l.Text, "ssh ") || existenceTest.MatchString(l.Text) {
			continue
		}
		for _, m := range siblingScriptRef.FindAllStringSubmatchIndex(l.Text, -1) {
			name := ""
			switch {
			case m[2] >= 0 && dirVars[l.Text[m[2]:m[3]]]:
				name = l.Text[m[4]:m[5]]
			case m[6] >= 0:
				name = l.Text[m[6]:m[7]]
			default:
				continue
			}
			if r.paths[path.Join(dir, name)] {
				continue
			}
			out = appendReport(out, src.Report(r, l.LineAt(m[0]),
				name+" is run from the script's directory, and there is no such file next to it",
				"Point to the script that exists, or add it"))
		}
	}
	return out
}

func init() {
	rules.Register(&shellRule{
		BaseRule: rules.NewBaseRule("shell-db-password-literal", "security",
			"Detects a database password written into a shell script or make recipe: PGPASSWORD=literal, password=literal in a connection string, postgres://user:literal@",
			core.SeverityHigh),
		check: checkDBPasswordLiteral,
	})
}

var (
	dbPasswordLiteral = regexp.MustCompile(`\bPGPASSWORD=["']?([^\s"'$;]+)|(?i:\bpassword=)([^\s"'$;&]+)|postgres(?:ql)?://[^:/@\s"']+:([^@\s"'$]+)@`)
	libpqKeyword      = regexp.MustCompile(`(?i)\b(?:dbname|host|user)=`)
)

// passwordValue returns the password a dbPasswordLiteral match captured.
func passwordValue(text string, m []int) string {
	for g := 1; 2*g+1 < len(m); g++ {
		if m[2*g] >= 0 {
			return text[m[2*g]:m[2*g+1]]
		}
	}
	return ""
}

// checkDBPasswordLiteral reports a database password written as a literal;
// a test script's DSN is a fixture, a printf verb (%s) and a regular
// expression stand where a password goes.
func checkDBPasswordLiteral(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	if src.Ctx.IsTestFile() {
		return nil
	}
	var out []*core.Violation
	for _, l := range src.Lines {
		for _, m := range dbPasswordLiteral.FindAllStringSubmatchIndex(l.Text, -1) {
			if m[4] >= 0 && !libpqKeyword.MatchString(l.Text) {
				continue // password= outside a libpq connection string
			}
			value := passwordValue(l.Text, m)
			if helpers.LooksLikeRegexpShape(value) {
				continue // a pattern: the shape a scanner searches for, a sed extracting the password
			}
			if patternkit.PrintfVerb.ReplaceAllString(value, "") == "" {
				continue // a printf format: the password is an argument
			}
			out = appendReport(out, src.Report(r, l.LineAt(m[0]),
				"A database password is written into the script — it is in the repository and in the process list of the host",
				"Read the password from the environment or a file the deploy places (PGPASSWORD=\"$DB_PASSWORD\", ~/.pgpass)"))
			break
		}
	}
	return out
}
