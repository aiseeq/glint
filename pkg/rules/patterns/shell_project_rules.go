package patterns

import (
	"path"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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
		core.SeverityHigh, func(_ *shellRule, src *shellSource) []*core.Violation { return checkMissingScript(missing, src) })
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
func checkMissingScript(r *shellProjectRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	dirVars := make(map[string]bool)
	for _, l := range src.lines {
		if m := scriptDirAssign.FindStringSubmatch(l.text); m != nil && !strings.Contains(l.text, "/..") {
			dirVars[m[1]] = true
		}
	}
	dir := path.Dir(src.ctx.RelPath)
	var out []*core.Violation
	for _, l := range src.lines {
		if strings.Contains(l.text, "ssh ") || existenceTest.MatchString(l.text) {
			continue
		}
		for _, m := range siblingScriptRef.FindAllStringSubmatchIndex(l.text, -1) {
			name := ""
			switch {
			case m[2] >= 0 && dirVars[l.text[m[2]:m[3]]]:
				name = l.text[m[4]:m[5]]
			case m[6] >= 0:
				name = l.text[m[6]:m[7]]
			default:
				continue
			}
			if r.paths[path.Join(dir, name)] {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(m[0]),
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

// checkDBPasswordLiteral reports a database password written as a literal.
func checkDBPasswordLiteral(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		for _, m := range dbPasswordLiteral.FindAllStringSubmatchIndex(l.text, -1) {
			if m[4] >= 0 && !libpqKeyword.MatchString(l.text) {
				continue // password= outside a libpq connection string
			}
			out = appendReport(out, src.report(r, l.lineAt(m[0]),
				"A database password is written into the script — it is in the repository and in the process list of the host",
				"Read the password from the environment or a file the deploy places (PGPASSWORD=\"$DB_PASSWORD\", ~/.pgpass)"))
			break
		}
	}
	return out
}
