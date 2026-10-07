package patterns

import (
	"go/ast"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
//   - cmd/**/main.go (CLI entry points can use bare fmt/log) - unless the
//     program installs a slog default (slog.SetDefault in any file of its
//     directory): the standard log package then writes through slog at INFO,
//     and log.Fatal reports a fatal failure below any ERROR alerting
//   - Files explicitly configured as exceptions in .glint.yaml
type NonCanonicalLoggerRule struct {
	*rules.BaseRule
	// slogDefaultDirs are the directories with a file calling
	// slog.SetDefault.
	slogDefaultDirs map[string]bool
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
// coexist with the project's canonical logger. An import of the module or of any
// of its packages (zerolog/log, zap/zapcore) raises a violation regardless of
// call site.
var forbiddenLoggerImports = []string{
	"go.uber.org/zap",
	"github.com/sirupsen/logrus",
	"github.com/golang/glog",
	"github.com/rs/zerolog",
}

// logPkgCalls maps a standard-library import path to its forbidden function
// names. The call's package identifier is resolved through the file's imports,
// so an alias of "log" counts and the project's own package named log does not.
// "fmt" covers diagnostic-oriented Print* calls (fmt.Errorf is intentionally not
// listed — it constructs errors, not log output).
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

// UseProjectFiles records the directories whose programs install a slog
// default.
func (r *NonCanonicalLoggerRule) UseProjectFiles(files []*core.FileContext) {
	r.slogDefaultDirs = make(map[string]bool)
	for _, ctx := range files {
		if ctx.IsGoFile() && ctx.HasGoAST() && !ctx.IsTestFile() && callsSlogSetDefault(ctx) {
			r.slogDefaultDirs[filepath.Dir(ctx.Path)] = true
		}
	}
}

// ResetState drops the directories of the previous root.
func (r *NonCanonicalLoggerRule) ResetState() { r.slogDefaultDirs = nil }

// AnalyzeFile checks for non-canonical logger usage
func (r *NonCanonicalLoggerRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	if r.shouldSkipFile(ctx) {
		if r.slogDefaultDirs[filepath.Dir(ctx.Path)] || callsSlogSetDefault(ctx) {
			return r.checkCalls(ctx, true)
		}
		return nil
	}

	var violations []*core.Violation

	// 1. Detect forbidden imports
	violations = append(violations, r.checkImports(ctx)...)

	// 2. Detect log.Printf / fmt.Println calls via AST
	violations = append(violations, r.checkCalls(ctx, false)...)

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

	// tools/** package main files are command-line programs. Their fmt output is
	// the user-facing command result, not application logging.
	if ctx.GoPackage == "main" &&
		(strings.HasPrefix(path, "tools/") || strings.Contains(path, "/tools/")) {
		return true
	}

	return false
}

// checkImports flags any import of a known parallel-logger library or of one of
// its packages.
func (r *NonCanonicalLoggerRule) checkImports(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	for _, spec := range ctx.GoAST.Imports {
		imp, ok := goStringLiteral(spec.Path)
		if !ok {
			continue
		}
		library := forbiddenLoggerLibrary(imp)
		if library == "" {
			continue
		}
		lineNum := ctx.PositionFor(spec).Line
		v := r.CreateViolation(ctx.RelPath, lineNum,
			"Non-canonical logger library imported: "+imp)
		v.WithCode(`"` + imp + `"`)
		v.WithSuggestion("Use the project's canonical logger (slog or shared/logging). " +
			"Parallel logger libraries fragment diagnostics and formatting.")
		v.WithContext("library", library)
		violations = append(violations, v)
	}

	return violations
}

// forbiddenLoggerLibrary returns the parallel logger module the import path
// belongs to, or "" when it belongs to none.
func forbiddenLoggerLibrary(importPath string) string {
	for _, forbidden := range forbiddenLoggerImports {
		if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
			return forbidden
		}
	}
	return ""
}

// callsSlogSetDefault reports a file calling slog.SetDefault.
func callsSlogSetDefault(ctx *core.FileContext) bool {
	aliases := helpers.PackageAliases(ctx.GoAST, `"log/slog"`, "slog")
	found := false
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "SetDefault" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && aliases[pkg.Name] && isPackageName(fileScopes(ctx), pkg) {
			found = true
		}
		return !found
	})
	return found
}

// checkCalls walks the AST and flags log.Printf / fmt.Println style calls.
// underSlog limits it to the log package of an entry point whose program
// installs a slog default.
func (r *NonCanonicalLoggerRule) checkCalls(ctx *core.FileContext, underSlog bool) []*core.Violation {
	var violations []*core.Violation

	// Identifier the file uses → standard-library import path it stands for.
	pkgOf := make(map[string]string, len(logPkgCalls))
	for path := range logPkgCalls {
		if underSlog && path != "log" {
			continue
		}
		for alias := range helpers.PackageAliases(ctx.GoAST, `"`+path+`"`, path) {
			pkgOf[alias] = path
		}
	}
	if len(pkgOf) == 0 {
		return nil
	}

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
		path, ok := pkgOf[pkgIdent.Name]
		if !ok || !logPkgCalls[path][sel.Sel.Name] {
			return true
		}
		// A parameter or variable named log is not the log package.
		if !isPackageName(fileScopes(ctx), pkgIdent) {
			return true
		}

		pos := ctx.PositionFor(call)
		lineContent := ctx.GetLine(pos.Line)

		// Respect suppression opt-outs on the same line (canonical core check).
		if ctx.LineSuppresses(pos.Line, "non-canonical-logger") {
			return true
		}

		message := "Non-canonical logger call: " + path + "." + sel.Sel.Name
		suggestion := "Route through the project's canonical logger (slog / shared/logging). " +
			"Direct " + path + "." + sel.Sel.Name + " bypasses structured logging and sampling."
		if underSlog {
			message = "log." + sel.Sel.Name + " in a program that calls slog.SetDefault — the log package then writes through slog at INFO, so this failure is logged below any ERROR alerting"
			suggestion = "Log the failure with slog.Error (and os.Exit(1) where log.Fatal exited)"
		}
		v := r.CreateViolation(ctx.RelPath, pos.Line, message)
		v.WithCode(strings.TrimSpace(lineContent))
		v.WithSuggestion(suggestion)
		v.WithContext("package", path)
		v.WithContext("function", sel.Sel.Name)
		violations = append(violations, v)
		return true
	})

	return violations
}
