package patterns

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewSlogDefaultNotSetRule())
}

// SlogDefaultNotSetRule detects a project that builds its configured slog
// logger and logs through the package-level functions without making the
// one the default:
//
//	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))   // level, format, fields
//	...
//	slog.Info("payment sent", "id", id)                         // the default text handler
//
// slog.Info and friends write to slog.Default(), which stays the standard
// handler until slog.SetDefault is called: those records skip the level,
// the JSON format and the fields of the configured logger, and the log
// pipeline that parses JSON drops them.
type SlogDefaultNotSetRule struct {
	*rules.BaseRule
}

// NewSlogDefaultNotSetRule creates the rule
func NewSlogDefaultNotSetRule() *SlogDefaultNotSetRule {
	return &SlogDefaultNotSetRule{BaseRule: rules.NewBaseRule(
		"slog-default-not-set",
		"patterns",
		"Detects a slog logger built while package-level slog calls go to the default, and slog.SetDefault is never called — those records skip the configured handler",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the logger and its users live in different files.
func (r *SlogDefaultNotSetRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that syntax is enough for this rule.
func (r *SlogDefaultNotSetRule) RequiresSSA() bool { return false }

// slogDefaultUsers are the package-level functions that log through
// slog.Default().
var slogDefaultUsers = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true, "Log": true, "LogAttrs": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
	"Default": true, "With": true,
}

// slogCall is a call of a log/slog function.
type slogCall struct {
	file *core.FileContext
	call *ast.CallExpr
	name string
}

// AnalyzeGoProject reports the slog.New calls of a project whose package-level
// slog calls go to a default nobody sets.
func (r *SlogDefaultNotSetRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	var constructors, defaultUsers []slogCall
	for _, file := range ctx.Files {
		if file == nil || !productionGoFile(file) {
			continue
		}
		for _, call := range slogCalls(file) {
			switch {
			case call.name == "SetDefault":
				return nil, nil
			case call.name == "New":
				constructors = append(constructors, call)
			case slogDefaultUsers[call.name]:
				defaultUsers = append(defaultUsers, call)
			}
		}
	}
	if len(constructors) == 0 || len(defaultUsers) == 0 {
		return nil, nil
	}
	first := defaultUsers[0]
	for _, user := range defaultUsers[1:] {
		if user.file.RelPath < first.file.RelPath {
			first = user
		}
	}
	firstAt := fmt.Sprintf("%s:%d", first.file.RelPath, first.file.LineFor(first.call))

	var violations []*core.Violation
	for _, c := range constructors {
		line := c.file.LineFor(c.call)
		if c.file.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(c.file.RelPath, line, fmt.Sprintf(
			"slog logger built, but slog.SetDefault is never called — %d package-level slog call(s), first slog.%s at %s, write to the standard handler instead of this one",
			len(defaultUsers), first.name, firstAt))
		v.WithCode(strings.TrimSpace(c.file.GetLine(line)))
		v.WithSuggestion("Call slog.SetDefault(logger) where the logger is configured, or log through the logger instead of the slog package functions")
		violations = append(violations, v)
	}
	return violations, nil
}

// slogCalls returns the calls of log/slog package functions in a file.
func slogCalls(file *core.FileContext) []slogCall {
	aliases := helpers.PackageAliases(file.GoAST, `"log/slog"`, "slog")
	if len(aliases) == 0 {
		return nil
	}
	var calls []slogCall
	ast.Inspect(file.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && aliases[pkg.Name] && pkg.Obj == nil {
			calls = append(calls, slogCall{file: file, call: call, name: sel.Sel.Name})
		}
		return true
	})
	return calls
}
