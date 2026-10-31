package errrules

import (
	"errors"
	"go/ast"
	"go/constant"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewExpectedRejectionLoggedAsErrorRule())
}

// ExpectedRejectionLoggedAsErrorRule detects an error branch that logs the
// error at ERROR before telling an expected refusal apart:
//
//	if err := a.repo.Create(ctx, pc); err != nil {
//		a.logger.Error("failed to create", "error", err)
//		if IsBusinessError(err, ErrCodeConflict) {
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
		addViolation := func(logged *ast.CallExpr) {
			if logged == nil {
				return
			}
			line := file.LineFor(logged)
			if file.IsSuppressed(line, r.Name()) {
				return
			}
			v := r.CreateViolation(file.RelPath, line,
				"The error is logged at ERROR before the branch that answers it as an expected refusal — every conflict or invalid input raises the alerts of a real failure")
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Move the ERROR log below the branches for expected outcomes, and log those at WARN or INFO inside them")
			violations = append(violations, v)
		}
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			check, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			errIdent := patternkit.ErrNotNilIdent(info, check.Cond)
			if errIdent == nil {
				return true
			}
			errVar, ok := info.Uses[errIdent].(*types.Var)
			if !ok {
				return true
			}
			addViolation(loggedBeforeExpectedBranch(info, check.Body.List, errVar))
			return true
		})
		return violations
	})
}

// expectedOutcome is how a check of an error names an outcome the caller
// answers in its stride.
var expectedOutcome = regexp.MustCompile(`(?i)conflict|duplicate|exists|missing|notfound|not_found|norows|invalid|validation|forbidden|unauthori[sz]ed|denied|inuse|in_use|limit|expired`)

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
			switch branch := later.(type) {
			case *ast.IfStmt:
				if patternkit.MentionsVar(info, branch.Cond, errVar) && expectedOutcome.MatchString(types.ExprString(branch.Cond)) && patternkit.LastIsReturn(branch.Body) && !logsAtError(branch.Body) {
					return logged
				}
			case *ast.SwitchStmt:
				for _, clause := range switchClauses(branch) {
					if patternkit.MentionsVar(info, clause, errVar) && caseMatchesExpectedOutcome(clause) && hasClientStatus(info, clause) {
						return logged
					}
				}
			}
		}
	}
	return nil
}

// switchClauses returns the clauses of a switch statement.
func switchClauses(stmt *ast.SwitchStmt) []*ast.CaseClause {
	if stmt == nil || stmt.Body == nil {
		return nil
	}
	clauses := make([]*ast.CaseClause, 0, len(stmt.Body.List))
	for _, item := range stmt.Body.List {
		if clause, ok := item.(*ast.CaseClause); ok {
			clauses = append(clauses, clause)
		}
	}
	return clauses
}

func caseMatchesExpectedOutcome(clause *ast.CaseClause) bool {
	for _, expr := range clause.List {
		if expectedOutcome.MatchString(types.ExprString(expr)) {
			return true
		}
	}
	return false
}

func hasClientStatus(info *types.Info, node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if tv, ok := info.Types[arg]; ok && tv.Value != nil && tv.Value.Kind() == constant.Int {
				if status, exact := constant.Int64Val(tv.Value); exact && status >= 400 && status < 500 {
					found = true
					return false
				}
			}
		}
		return !found
	})
	return found
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
		if patternkit.MentionsVar(info, arg, errVar) {
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
