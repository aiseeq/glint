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
	rules.Register(NewMarkerNeverWrittenRule())
}

// MarkerNeverWrittenRule detects a check for a tag-like marker that no code
// of the project writes:
//
//	func isPromoCredit(note string) bool {
//		return strings.HasPrefix(note, "[promo_credit]")
//	}
//
// The writer dropped the prefix, the reader still looks for it, and the check
// is false for every row: promotional credits were counted as paid ones. A
// marker is a bracketed tag ([promo_credit]); it is written when another
// string literal outside tests contains it. Test data writing the marker does
// not count - it is how the dead check stays green.
type MarkerNeverWrittenRule struct {
	*rules.BaseRule
}

// NewMarkerNeverWrittenRule creates the rule
func NewMarkerNeverWrittenRule() *MarkerNeverWrittenRule {
	return &MarkerNeverWrittenRule{BaseRule: rules.NewBaseRule(
		"marker-never-written",
		"patterns",
		"Detects a check for a tag-like marker ([promo_credit]) that no code of the project writes — the check is always false",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the writers are known only from the whole project.
func (r *MarkerNeverWrittenRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that syntax is enough for this rule.
func (r *MarkerNeverWrittenRule) RequiresSSA() bool { return false }

var markerLiteral = regexp.MustCompile(`^\[[A-Za-z][\w:.-]*\]$`)

var markerChecks = map[string]bool{"HasPrefix": true, "HasSuffix": true, "Contains": true, "Index": true, "TrimPrefix": true, "CutPrefix": true}

type markerCheck struct {
	file   *core.FileContext
	lit    *ast.BasicLit
	marker string
}

// AnalyzeGoProject reports the checks for markers nothing writes.
func (r *MarkerNeverWrittenRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	var checks []markerCheck
	checked := make(map[*ast.BasicLit]bool)
	var written []string
	for _, file := range ctx.Files {
		if file == nil || file.GoAST == nil || file.IsTestFile() {
			continue
		}
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 || !isStringsCall(file, call) {
				return true
			}
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok {
				return true
			}
			if marker, ok := goStringLiteral(lit); ok && markerLiteral.MatchString(marker) {
				checks = append(checks, markerCheck{file: file, lit: lit, marker: marker})
				checked[lit] = true
			}
			return true
		})
	}
	if len(checks) == 0 {
		return nil, nil
	}
	for _, file := range ctx.Files {
		if file == nil || file.GoAST == nil || file.IsTestFile() {
			continue
		}
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && !checked[lit] {
				if text, ok := goStringLiteral(lit); ok && strings.Contains(text, "[") {
					written = append(written, text)
				}
			}
			return true
		})
	}
	var violations []*core.Violation
	for _, check := range checks {
		if markerWritten(check.marker, written) {
			continue
		}
		line := check.file.LineFor(check.lit)
		if check.file.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(check.file.RelPath, line, "Check for the marker "+check.marker+" that no code outside tests writes — the check is false for every value")
		v.WithCode(strings.TrimSpace(check.file.GetLine(line)))
		v.WithSuggestion("Check what the writer records now (a column, a flag, a type), or delete the dead check with the branch it guards")
		violations = append(violations, v)
	}
	return violations, nil
}

func markerWritten(marker string, written []string) bool {
	for _, text := range written {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// isStringsCall reports a call of the strings package's search functions.
func isStringsCall(file *core.FileContext, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !markerChecks[sel.Sel.Name] {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && helpers.PackageAliases(file.GoAST, `"strings"`, "strings")[pkg.Name]
}
