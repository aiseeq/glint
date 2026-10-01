package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTestValueBypassRule())
}

// TestValueBypassRule detects a validator that lets through a value marked as
// test data:
//
//	if !strings.Contains(signature, "testsignature") { ...check the format... }
//	if strings.HasPrefix(address, "TEST") { return true }
//
// The marker is a string anyone can send: in production the signature that
// contains "testsignature" is accepted unchecked, and the "TEST..." address
// passes validation. A function named for test data (isTestEmail) recognises
// it on purpose and is left out. The subject must be named as something validated (an
// address, a signature, a token, a password, a key, ...), and the branch must
// accept the value (return true or a nil error) or hold the check that the
// marked value skips.
type TestValueBypassRule struct {
	*rules.BaseRule
}

// NewTestValueBypassRule creates the rule
func NewTestValueBypassRule() *TestValueBypassRule {
	return &TestValueBypassRule{BaseRule: rules.NewBaseRule(
		"test-value-bypass",
		"patterns",
		"Detects a validator that accepts a value marked as test data (a \"test\" prefix or substring) — in production anyone can send the marker",
		core.SeverityHigh,
	)}
}

var (
	testMarker      = regexp.MustCompile(`(?i)test|fake|dummy|mock|bypass`)
	validatedName   = regexp.MustCompile(`(?i)(addr|address|signature|^sig$|token|otp|hash|password|secret|key$|wallet|email|phone|card|account|iban|nonce|proof|hmac)`)
	stringMatchFunc = map[string]bool{"Contains": true, "HasPrefix": true, "HasSuffix": true, "EqualFold": true}
)

// AnalyzeFile reports the branches of a file's validators that accept a
// test marker.
func (r *TestValueBypassRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		// A function named for test data (isTestEmail) is meant to recognise it.
		if !ok || fn.Body == nil || testMarker.MatchString(fn.Name.Name) {
			continue
		}
		violations = append(violations, r.checkFunction(ctx, fn.Body)...)
	}
	return violations
}

// checkFunction reports the branches of one function that accept a test
// marker.
func (r *TestValueBypassRule) checkFunction(ctx *core.FileContext, body *ast.BlockStmt) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(body, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		subject, negated, found := testMarkerMatch(stmt.Cond, false)
		if !found {
			return true
		}
		accepts := !negated && acceptsValue(stmt.Body)
		skipsCheck := negated && rejectsValue(stmt.Body)
		if !accepts && !skipsCheck {
			return true
		}
		line := ctx.LineFor(stmt)
		if ctx.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(ctx.RelPath, line, "Validation of "+subject+" lets a test marker through — in production anyone can send a value with it")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Remove the test bypass; give tests valid values (a real signature, a well-formed address) or a test double of the validator")
		violations = append(violations, v)
		return true
	})
	return violations
}

// testMarkerMatch finds in a condition a comparison of a validated value with
// a test marker — strings.HasPrefix(address, "TEST"), token == "fake" — and
// reports whether it is negated (!strings.Contains, !=).
func testMarkerMatch(cond ast.Expr, negated bool) (string, bool, bool) {
	switch expr := ast.Unparen(cond).(type) {
	case *ast.UnaryExpr:
		if expr.Op == token.NOT {
			return testMarkerMatch(expr.X, !negated)
		}
	case *ast.BinaryExpr:
		switch expr.Op {
		case token.LAND, token.LOR:
			if subject, neg, ok := testMarkerMatch(expr.X, negated); ok {
				return subject, neg, true
			}
			return testMarkerMatch(expr.Y, negated)
		case token.EQL, token.NEQ:
			for _, pair := range [][2]ast.Expr{{expr.X, expr.Y}, {expr.Y, expr.X}} {
				if subject, ok := markedSubject(pair[0], pair[1]); ok {
					return subject, negated != (expr.Op == token.NEQ), true
				}
			}
		}
	case *ast.CallExpr:
		sel, ok := expr.Fun.(*ast.SelectorExpr)
		if !ok || !stringMatchFunc[sel.Sel.Name] || len(expr.Args) != 2 {
			return "", false, false
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "strings" {
			return "", false, false
		}
		if subject, ok := markedSubject(expr.Args[0], expr.Args[1]); ok {
			return subject, negated, true
		}
	}
	return "", false, false
}

// markedSubject returns the name of a validated value compared with a test
// marker literal.
func markedSubject(value, marker ast.Expr) (string, bool) {
	lit, ok := marker.(*ast.BasicLit)
	if !ok {
		return "", false
	}
	text, ok := goStringLiteral(lit)
	if !ok || !testMarker.MatchString(text) {
		return "", false
	}
	var name string
	switch v := ast.Unparen(value).(type) {
	case *ast.Ident:
		name = v.Name
	case *ast.SelectorExpr:
		name = v.Sel.Name
	default:
		return "", false
	}
	return name, validatedName.MatchString(name)
}

// acceptsValue reports a branch that returns true, a nil error alone, or a
// value with a nil error — anything but false with it.
func acceptsValue(body *ast.BlockStmt) bool {
	for _, stmt := range body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			continue
		}
		last, ok := ast.Unparen(ret.Results[len(ret.Results)-1]).(*ast.Ident)
		switch {
		case !ok:
		case last.Name == "true":
			return true
		case last.Name == "nil":
			return len(ret.Results) == 1 || !isFalseLiteral(ret.Results[0])
		}
	}
	return false
}

// rejectsValue reports a branch that somewhere returns false or an error.
func rejectsValue(body *ast.BlockStmt) bool {
	rejects := false
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		last := ast.Unparen(ret.Results[len(ret.Results)-1])
		if isFalseLiteral(last) {
			rejects = true
		} else if ident, ok := last.(*ast.Ident); !ok || ident.Name != "nil" {
			_, isCall := last.(*ast.CallExpr)
			rejects = rejects || isCall || (ok && (ident.Name == "err" || strings.HasPrefix(ident.Name, "Err")))
		}
		return !rejects
	})
	return rejects
}

func isFalseLiteral(expr ast.Expr) bool {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && ident.Name == "false"
}
