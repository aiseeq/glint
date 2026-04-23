package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNonCanonicalLoggerRule())
}

// NonCanonicalLoggerRule detects usage of non-canonical logging in production code.
//
// Rationale: projects that standardize on a single logger (slog, zerolog, or a
// project-local canonical_logger) need every production code path to route
// diagnostics through that logger so that formatting, sampling and destinations
// stay consistent. Ad-hoc calls to log.Printf, fmt.Print* or parallel logger
// libraries (zap, logrus) bypass that pipeline.
//
// Detects:
//   - Calls to log.Printf/Println/Print/Fatal/Panic and their formatted variants
//   - fmt.Print/Println/Printf used as diagnostic output (not as error construction)
//   - Imports of known parallel logger libraries (zap, logrus, glog, zerolog) in
//     projects where they are not the canonical choice
//
// Skips:
//   - Test files (*_test.go, /tests/, /testdata/)
//   - cmd/**/main.go (CLI entry points can use bare fmt/log)
//   - Files explicitly configured as exceptions in .glint.yaml
type NonCanonicalLoggerRule struct {
	*rules.BaseRule
}

// NewNonCanonicalLoggerRule creates the rule
func NewNonCanonicalLoggerRule() *NonCanonicalLoggerRule {
	return &NonCanonicalLoggerRule{
		BaseRule: rules.NewBaseRule(
			"non-canonical-logger",
			"patterns",
			"Detects non-canonical loggers (log.Printf, fmt.Print*, zap, logrus) in production code",
			core.SeverityMedium,
		),
	}
}

// forbiddenLoggerImports is the set of parallel logger libraries that should not
// coexist with the project's canonical logger. Every matched import raises a
// violation regardless of call site.
var forbiddenLoggerImports = []string{
	"go.uber.org/zap",
	"github.com/sirupsen/logrus",
	"github.com/golang/glog",
	"github.com/rs/zerolog",
}

// logPkgCalls maps callee package to forbidden function names. "log" covers
// both the stdlib log package and common project aliases. "fmt" covers
// diagnostic-oriented Print* calls (fmt.Errorf is intentionally not listed —
// it constructs errors, not log output).
var logPkgCalls = map[string]map[string]bool{
	"log": {
		"Printf": true, "Println": true, "Print": true,
		"Fatal": true, "Fatalf": true, "Fatalln": true,
		"Panic": true, "Panicf": true, "Panicln": true,
	},
	"fmt": {
		"Println": true, "Printf": true, "Print": true,
	},
}

// AnalyzeFile checks for non-canonical logger usage
func (r *NonCanonicalLoggerRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if r.shouldSkipFile(ctx) {
		return nil
	}

	var violations []*core.Violation

	// 1. Detect forbidden imports
	violations = append(violations, r.checkImports(ctx)...)

	// 2. Detect log.Printf / fmt.Println calls via AST
	if ctx.HasGoAST() {
		violations = append(violations, r.checkCalls(ctx)...)
	}

	return violations
}

// shouldSkipFile excludes entry points and CLI utilities where bare fmt/log is
// still acceptable. Production library/service code does not qualify.
func (r *NonCanonicalLoggerRule) shouldSkipFile(ctx *core.FileContext) bool {
	path := ctx.RelPath

	// cmd/**/main.go — CLI entry points. Path-based, not filename-based,
	// so that backend/shared/main.go (if any) is still checked.
	if strings.HasSuffix(path, "/main.go") &&
		(strings.Contains(path, "/cmd/") || strings.HasPrefix(path, "cmd/")) {
		return true
	}

	// main.go at project root is also a valid entry point
	if path == "main.go" {
		return true
	}

	return false
}

// checkImports flags any import of a known parallel-logger library.
func (r *NonCanonicalLoggerRule) checkImports(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	for _, imp := range ctx.GoImports {
		for _, forbidden := range forbiddenLoggerImports {
			if imp != forbidden {
				continue
			}
			lineNum := r.findImportLine(ctx, forbidden)
			v := r.CreateViolation(ctx.RelPath, lineNum,
				"Non-canonical logger library imported: "+forbidden)
			v.WithCode(`"` + forbidden + `"`)
			v.WithSuggestion("Use the project's canonical logger (slog or shared/logging). " +
				"Parallel logger libraries fragment diagnostics and formatting.")
			v.WithContext("library", forbidden)
			violations = append(violations, v)
		}
	}

	return violations
}

// findImportLine returns the 1-based line number of the import, or 1 if the
// literal is not found (defensive — GoImports is parsed from the same AST).
func (r *NonCanonicalLoggerRule) findImportLine(ctx *core.FileContext, importPath string) int {
	needle := `"` + importPath + `"`
	for idx, line := range ctx.Lines {
		if strings.Contains(line, needle) {
			return idx + 1
		}
	}
	return 1
}

// checkCalls walks the AST and flags log.Printf / fmt.Println style calls.
func (r *NonCanonicalLoggerRule) checkCalls(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		funcs, ok := logPkgCalls[pkgIdent.Name]
		if !ok || !funcs[sel.Sel.Name] {
			return true
		}

		pos := ctx.PositionFor(call)
		lineContent := ctx.GetLine(pos.Line)

		// Respect //nolint:non-canonical-logger opt-outs on the same line.
		if strings.Contains(lineContent, "nolint:non-canonical-logger") {
			return true
		}

		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Non-canonical logger call: "+pkgIdent.Name+"."+sel.Sel.Name)
		v.WithCode(strings.TrimSpace(lineContent))
		v.WithSuggestion("Route through the project's canonical logger (slog / shared/logging). " +
			"Direct " + pkgIdent.Name + "." + sel.Sel.Name + " bypasses structured logging and sampling.")
		v.WithContext("package", pkgIdent.Name)
		v.WithContext("function", sel.Sel.Name)
		violations = append(violations, v)
		return true
	})

	return violations
}
