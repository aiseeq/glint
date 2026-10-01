package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewEnvironmentCheckFailsOpenRule())
}

// EnvironmentCheckFailsOpenRule detects an environment check that lets
// through what it does not recognise:
//
//	if r.environment == "production" || r.environment == "staging" {
//	    return errors.New("DELETE is forbidden here")
//	}
//	// an unset, misspelled or new environment deletes
//
//	if baseDomain == "" || baseDomain == "app.local" {
//	    return // development: keep every origin
//	}
//	// a production config without the setting keeps the development origins
//
// The first refuses in the environments it lists and allows everywhere else;
// the second takes a missing setting for development and skips the
// restriction. Both fail open on configuration that is absent. List where the
// dangerous operation is allowed (test, development) and refuse otherwise;
// treat an empty setting as an error.
type EnvironmentCheckFailsOpenRule struct {
	*rules.BaseRule
}

// NewEnvironmentCheckFailsOpenRule creates the rule
func NewEnvironmentCheckFailsOpenRule() *EnvironmentCheckFailsOpenRule {
	return &EnvironmentCheckFailsOpenRule{BaseRule: rules.NewBaseRule(
		"environment-check-fails-open",
		"patterns",
		"Detects a guard that refuses only in listed production environments, or skips a restriction when a setting is empty or names development — a missing setting turns the protection off",
		core.SeverityHigh,
	)}
}

var (
	productionEnvironment  = regexp.MustCompile(`(?i)^(production|prod|staging|stage|live|mainnet)$`)
	developmentEnvironment = regexp.MustCompile(`(?i)^(dev|development|local|localhost|test|testing|127\.0\.0\.1)$|\.(local|localhost|test)$`)
)

// AnalyzeFile reports the environment checks of a file that fail open.
func (r *EnvironmentCheckFailsOpenRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	report := func(stmt *ast.IfStmt, message, suggestion string) {
		line := ctx.LineFor(stmt)
		if ctx.IsSuppressed(line, r.Name()) {
			return
		}
		v := r.CreateViolation(ctx.RelPath, line, message)
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion(suggestion)
		violations = append(violations, v)
	}
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		values, subject, ok := equalityChain(stmt.Cond)
		if !ok {
			return true
		}
		switch {
		case allMatch(values, productionEnvironment) && rejectsRequest(stmt.Body):
			report(stmt, "The guard refuses only when "+subject+" names a production environment — an unset or unknown value is allowed",
				"Allow the operation where it is meant to run ("+subject+" == \"test\" || ...) and refuse everywhere else")
		case slices.Contains(values, "") && anyMatch(values, developmentEnvironment) && skipsWithoutError(stmt.Body):
			report(stmt, "An empty "+subject+" is taken for development and the rest is skipped — a configuration without the setting loses the restriction",
				"Treat an empty setting as an error, and decide development by an explicit value")
		}
		return true
	})
	return violations
}

// equalityChain matches x == "a" || x == "b" || ... over one subject and
// returns the literals.
func equalityChain(cond ast.Expr) ([]string, string, bool) {
	switch expr := ast.Unparen(cond).(type) {
	case *ast.BinaryExpr:
		switch expr.Op {
		case token.LOR:
			left, subject, ok := equalityChain(expr.X)
			if !ok {
				return nil, "", false
			}
			right, other, ok := equalityChain(expr.Y)
			if !ok || other != subject {
				return nil, "", false
			}
			return append(left, right...), subject, true
		case token.EQL:
			lit, ok := expr.Y.(*ast.BasicLit)
			if !ok {
				return nil, "", false
			}
			text, ok := goStringLiteral(lit)
			if !ok {
				return nil, "", false
			}
			return []string{text}, types.ExprString(expr.X), true
		}
	}
	return nil, "", false
}

func allMatch(values []string, re *regexp.Regexp) bool {
	for _, value := range values {
		if !re.MatchString(value) {
			return false
		}
	}
	return len(values) > 0
}

func anyMatch(values []string, re *regexp.Regexp) bool {
	for _, value := range values {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// skipsWithoutError reports a branch that returns and reports no failure: a
// bare return, return nil, return of values with a nil error.
func skipsWithoutError(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	ret, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok {
		return false
	}
	if len(ret.Results) == 0 {
		return true
	}
	last, ok := ast.Unparen(ret.Results[len(ret.Results)-1]).(*ast.Ident)
	return ok && last.Name == "nil"
}
