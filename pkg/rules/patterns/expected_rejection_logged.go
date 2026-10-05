package patterns

import (
	"errors"
	"go/ast"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewExpectedRejectionLoggedAsErrorRule())
}

// ExpectedRejectionLoggedAsErrorRule detects an error branch that logs the
// error at ERROR before telling an expected refusal apart:
//
//	if err := a.repo.Create(ctx, pc); err != nil {
//		a.logger.Error("failed to create", "error", err)
//		if IsDomainError(err, ErrCodeConflict) {
//			a.redirect(w, r, "already exists")
//			return
//		}
//		...
//	}
//
// The conflict, the validation failure, the missing row are answered to the
// user as ordinary outcomes, yet the ERROR line is already written: alerts,
// error counters and incident logs fire on every duplicate an operator
// tries, and the real failures drown in them. The log belongs after the
// branches that pick the expected outcomes out, or at a lower level inside
// them.
type ExpectedRejectionLoggedAsErrorRule struct {
	*rules.BaseRule
}

// NewExpectedRejectionLoggedAsErrorRule creates the rule
func NewExpectedRejectionLoggedAsErrorRule() *ExpectedRejectionLoggedAsErrorRule {
	return &ExpectedRejectionLoggedAsErrorRule{BaseRule: rules.NewBaseRule(
		"expected-rejection-logged-as-error",
		"patterns",
		"Detects an error logged at ERROR before the branch that answers it as an expected refusal (conflict, validation, not found) — every ordinary refusal raises the alerts of a failure",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the error is recognized by its type.
func (r *ExpectedRejectionLoggedAsErrorRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ExpectedRejectionLoggedAsErrorRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the ERROR logs written ahead of expected refusals.
func (r *ExpectedRejectionLoggedAsErrorRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("expected rejection logged as error: nil Go project context")
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			check, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			errIdent := errNotNilIdent(info, check.Cond)
			if errIdent == nil {
				return true
			}
			errVar, ok := info.Uses[errIdent].(*types.Var)
			if !ok {
				return true
			}
			logged := loggedBeforeExpectedBranch(info, check.Body.List, errVar)
			if logged == nil {
				return true
			}
			line := file.LineFor(logged)
			if file.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(file.RelPath, line,
				"The error is logged at ERROR before the branch that answers it as an expected refusal — every conflict or invalid input raises the alerts of a real failure")
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Move the ERROR log below the branches for expected outcomes, and log those at WARN or INFO inside them")
			violations = append(violations, v)
			return true
		})
		return violations
	})
}

// expectedOutcome is how a check of an error names an outcome the caller
// answers in its stride.
var expectedOutcome = regexp.MustCompile(`(?i)conflict|duplicate|exists|notfound|not_found|norows|invalid|validation|forbidden|unauthori[sz]ed|denied|inuse|in_use|limit|expired`)

// loggedBeforeExpectedBranch returns an ERROR log of the error followed in
// the same branch by a check of the error for an expected outcome that
// returns without logging at ERROR.
func loggedBeforeExpectedBranch(info *types.Info, stmts []ast.Stmt, errVar *types.Var) *ast.CallExpr {
	for i, stmt := range stmts {
		logged := errorLogOf(info, stmt, errVar)
		if logged == nil {
			continue
		}
		for _, later := range stmts[i+1:] {
			branch, ok := later.(*ast.IfStmt)
			if !ok || !mentionsVar(info, branch.Cond, errVar) || !expectedOutcome.MatchString(types.ExprString(branch.Cond)) {
				continue
			}
			if lastIsReturn(branch.Body) && !logsAtError(branch.Body) {
				return logged
			}
		}
	}
	return nil
}

// errorLogOf returns the call of a statement logging the error at ERROR.
func errorLogOf(info *types.Info, stmt ast.Stmt, errVar *types.Var) *ast.CallExpr {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return nil
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !errorLogMethods[sel.Sel.Name] {
		return nil
	}
	for _, arg := range call.Args {
		if mentionsVar(info, arg, errVar) {
			return call
		}
	}
	return nil
}

// logsAtError reports a branch with an ERROR log call.
func logsAtError(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && errorLogMethods[sel.Sel.Name] {
				found = true
			}
		}
		return !found
	})
	return found
}
