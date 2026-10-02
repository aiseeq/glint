package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// targetRun is a go test -run that a make recipe or a script runs, with the
// variables the same shell sets for it.
type targetRun struct {
	pattern string
	env     map[string]bool
}

var (
	goTestRun  = regexp.MustCompile(`\bgo\s+test\b[^;&|]*?\s-run[=\s]+['"]?([^\s'"]+)`)
	envSetting = regexp.MustCompile(`(?:^|[\s;(])(?:export\s+)?([A-Z_][A-Z0-9_]*)=`)
)

// UseProjectFiles collects the test runs of the root's make files and
// scripts.
func (r *SkippedTestRule) UseProjectFiles(files []*core.FileContext) {
	r.runs = nil
	for _, ctx := range files {
		src, ok := readShell(ctx)
		if !ok {
			continue
		}
		for _, unit := range src.units() {
			for _, m := range goTestRun.FindAllStringSubmatchIndex(unit.text, -1) {
				pattern := unit.text[m[2]:m[3]]
				env := make(map[string]bool)
				for _, set := range envSetting.FindAllStringSubmatch(unit.text[:m[0]], -1) {
					env[set[1]] = true
				}
				if len(env) > 0 {
					r.runs = append(r.runs, targetRun{pattern: pattern, env: env})
				}
			}
		}
	}
}

// ResetState drops the test runs of the previous root.
func (r *SkippedTestRule) ResetState() { r.runs = nil }

// providedEnv reports a variable that a dedicated run of the test sets: the
// target exists to run it with that value.
func (r *SkippedTestRule) providedEnv(test, name string) bool {
	for _, run := range r.runs {
		if run.env[name] && runSelects(run.pattern, test) {
			return true
		}
	}
	return false
}

// runSelects reports a -run pattern that selects the test. A pattern that
// does not compile selects nothing: go test refuses it.
func runSelects(pattern, test string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil || !re.MatchString(test) {
		return false
	}
	return true
}

// skipsOnProvidedEnv reports the t.Skip calls of a test that skip when a
// variable its make target sets is empty: the target goes green with the
// test never run.
func (r *SkippedTestRule) skipsOnProvidedEnv(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	if len(r.runs) == 0 || !strings.HasPrefix(fn.Name.Name, "Test") {
		return nil
	}
	fromEnv := make(map[string]string) // local name -> variable it reads
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if name := getenvName(rhs); name != "" && i < len(node.Lhs) {
					if id, ok := node.Lhs[i].(*ast.Ident); ok {
						fromEnv[id.Name] = name
					}
				}
			}
		case *ast.IfStmt:
			name := emptyEnvCheck(node.Cond, fromEnv)
			if name == "" || !r.providedEnv(fn.Name.Name, name) {
				return true
			}
			if call := skipCall(node.Body); call != nil {
				violations = append(violations, r.report(ctx, ctx.LineFor(call),
					fn.Name.Name+" skips when "+name+" is empty, while the make target that runs it exists to set "+name+" — the target passes with the test never run",
					"Fail the test (t.Fatal) or the target when "+name+" is empty: the dedicated run must not go green without the check"))
			}
		}
		return true
	})
	return violations
}

// getenvName returns V of os.Getenv("V").
func getenvName(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if pkg, isIdent := sel.X.(*ast.Ident); !isIdent || pkg.Name != "os" || sel.Sel.Name != "Getenv" {
		return ""
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return ""
	}
	name, ok := goStringLiteral(lit)
	if !ok {
		return ""
	}
	return name
}

// emptyEnvCheck returns V of os.Getenv("V") == "" or of x == "" for x read
// from it.
func emptyEnvCheck(cond ast.Expr, fromEnv map[string]string) string {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return ""
	}
	for _, pair := range [][2]ast.Expr{{bin.X, bin.Y}, {bin.Y, bin.X}} {
		if lit, ok := pair[1].(*ast.BasicLit); !ok || lit.Value != `""` {
			continue
		}
		if name := getenvName(pair[0]); name != "" {
			return name
		}
		if id, ok := pair[0].(*ast.Ident); ok {
			return fromEnv[id.Name]
		}
	}
	return ""
}
