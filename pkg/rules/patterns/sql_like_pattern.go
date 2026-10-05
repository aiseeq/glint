package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewSQLLikePatternUnescapedRule())
}

// SQLLikePatternUnescapedRule detects a LIKE pattern built from a value with
// % wildcards around it and no escaping of the value's own % and _:
//
//	where += " AND reference ILIKE $3"
//	args = append(args, "%"+filter.Search+"%")
//
// A search for "100%" or "a_b" matches every row the wildcards admit — the
// user's characters act as wildcards. strings.NewReplacer(`\`, `\\`, `%`,
// `\%`, `_`, `\_`) on the value first keeps them literal.
type SQLLikePatternUnescapedRule struct {
	*rules.BaseRule
}

// NewSQLLikePatternUnescapedRule creates the rule
func NewSQLLikePatternUnescapedRule() *SQLLikePatternUnescapedRule {
	return &SQLLikePatternUnescapedRule{BaseRule: rules.NewBaseRule(
		"sql-like-pattern-unescaped",
		"patterns",
		"Detects a LIKE/ILIKE pattern built as \"%\"+value+\"%\" without escaping the value's % and _ — the user's characters act as wildcards",
		core.SeverityMedium,
	)}
}

// likeOperator matches a LIKE or ILIKE taking a bound parameter.
var likeOperator = regexp.MustCompile(`(?i)\b(?:i?like|similar\s+to)\s+(?:\$|\?|:|@|lower\s*\(|upper\s*\()`)

// AnalyzeFile reports the unescaped LIKE patterns of the functions running a
// LIKE.
func (r *SQLLikePatternUnescapedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !runsLike(fn.Body) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			expr, ok := n.(ast.Expr)
			if !ok || !unescapedLikePattern(expr) {
				return true
			}
			line := ctx.LineFor(expr)
			if ctx.IsSuppressed(line, r.Name()) {
				return false
			}
			v := r.CreateViolation(ctx.RelPath, line,
				"The LIKE pattern wraps the value in % without escaping its own % and _ — a search holding them matches rows it should not")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Escape the value first: strings.NewReplacer(`\\`, `\\\\`, `%`, `\\%`, `_`, `\\_`).Replace(s)")
			violations = append(violations, v)
			return false
		})
	}
	return violations
}

// runsLike reports a body with a string literal holding a LIKE on a bound
// parameter.
func runsLike(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && likeOperator.MatchString(lit.Value) {
			found = true
		}
		return !found
	})
	return found
}

// unescapedLikePattern reports "%" + v + "%", "%" + v, v + "%" and
// fmt.Sprintf("%%%s%%", v) with v a value that is not escaped.
func unescapedLikePattern(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return false
		}
		operands := concatOperands(e)
		wildcard, value := false, false
		for i, operand := range operands {
			if text, ok := stringLiteral(operand); ok {
				first, last := i == 0, i == len(operands)-1
				wildcard = wildcard || (first && strings.HasSuffix(text, "%")) || (last && strings.HasPrefix(text, "%"))
				continue
			}
			if escapedValue(operand) {
				return false
			}
			value = true
		}
		return wildcard && value
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Sprintf" || len(e.Args) < 2 {
			return false
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "fmt" {
			return false
		}
		format, ok := stringLiteral(e.Args[0])
		wraps := strings.HasPrefix(format, "%%%") || strings.HasSuffix(format, "%%")
		if !ok || !wraps || len(format) > 12 {
			return false
		}
		for _, arg := range e.Args[1:] {
			if escapedValue(arg) {
				return false
			}
		}
		return true
	}
	return false
}

// escapedValue reports a value passed through an escaping call: a function
// named for escaping or a Replace.
func escapedValue(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	words := helpers.IdentifierWords(callName(call))
	for _, word := range words {
		switch strings.ToLower(word) {
		case "escape", "escaped", "replace", "quote", "sanitize":
			return true
		}
	}
	for _, arg := range call.Args {
		if escapedValue(arg) {
			return true
		}
	}
	return false
}
