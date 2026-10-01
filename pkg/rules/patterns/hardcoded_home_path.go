package patterns

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewHardcodedHomePathRule())
}

// HardcodedHomePathRule detects a path into a developer's home directory
// written into code:
//
//	envPaths := []string{".env", "../.env", "/home/dev/work/shop/.env"}
//	cmd := exec.Command("node", "/home/dev/work/shop/scripts/send.js")
//
// The path exists on one machine. Anywhere else the lookup silently falls
// through to the next candidate, the script is not found, or - worse - a
// second checkout on the same machine reads the first one's files. Derive
// the path from configuration, the executable or the working directory.
// Test files are not checked: a path there is usually fixture data.
type HardcodedHomePathRule struct {
	*rules.BaseRule
}

// NewHardcodedHomePathRule creates the rule
func NewHardcodedHomePathRule() *HardcodedHomePathRule {
	return &HardcodedHomePathRule{BaseRule: rules.NewBaseRule(
		"hardcoded-home-path",
		"patterns",
		"Detects a path into a developer's home directory (/home/<user>/, /Users/<user>/, C:\\Users\\<user>\\) written into code — it exists on one machine only",
		core.SeverityHigh,
	)}
}

// homePath matches the start of a home directory with a user name and
// something below it, at the start of the text or after a separator.
var homePath = regexp.MustCompile(`(?:^|[\s"'=:;(,])(/home/[A-Za-z0-9._-]+/|/Users/[A-Za-z0-9._-]+/|[A-Za-z]:\\{1,2}Users\\{1,2}[A-Za-z0-9._-]+\\)`)

// AnalyzeFile reports the home paths in a file's string literals.
func (r *HardcodedHomePathRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.IsTestFile() {
		return nil
	}
	switch {
	case ctx.IsGoFile() && ctx.HasGoAST():
		return r.analyzeGo(ctx)
	case ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile():
		// e2e helpers run on CI too: only installed and generated code is skipped.
		if isVendoredOrGeneratedPath(ctx.RelPath) {
			return nil
		}
		return r.analyzeJS(ctx)
	}
	return nil
}

func (r *HardcodedHomePathRule) analyzeGo(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok {
			return true
		}
		text, ok := goStringLiteral(lit)
		if !ok {
			return true
		}
		if match := homePath.FindStringSubmatch(text); match != nil {
			violations = r.add(violations, ctx, ctx.LineFor(lit), match[1])
		}
		return true
	})
	return violations
}

func (r *HardcodedHomePathRule) analyzeJS(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	// Comments are blanked; literal text is kept.
	for i, line := range helpers.FileJSText(ctx) {
		if match := homePath.FindStringSubmatch(line); match != nil {
			violations = r.add(violations, ctx, i+1, match[1])
		}
	}
	return violations
}

func (r *HardcodedHomePathRule) add(violations []*core.Violation, ctx *core.FileContext, line int, home string) []*core.Violation {
	if ctx.IsSuppressed(line, r.Name()) {
		return violations
	}
	v := r.CreateViolation(ctx.RelPath, line, "Path into the home directory "+home+" — it exists on one developer's machine, and elsewhere the lookup falls through or the file is missing")
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion("Take the path from configuration or an environment variable, or derive it from the working directory or the executable")
	return append(violations, v)
}
