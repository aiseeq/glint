package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSentinelErrorReassignedRule())
}

// SentinelErrorReassignedRule detects a sentinel error assigned at run time:
//
//	var ErrNotFound = errors.New("not found")
//
//	func InitErrors(cfg Config) {
//		ErrNotFound = errors.New(cfg.NotFoundText())
//	}
//
// errors.Is and == compare the value. An error returned or wrapped before the
// assignment holds the old value and no longer matches the variable, and a
// sentinel declared without a value is nil until the setup runs: every check
// against it fails and a missing record turns into a server error. A sentinel
// is set once, where it is declared; a configurable text belongs in the error
// type, not in the identity. An assignment counts when the variable was
// declared as a sentinel (errors.New, fmt.Errorf, another sentinel) or is
// given one; a package error variable that holds the last failure of a setup
// is state, not a sentinel. Functions named init and test files are not
// checked.
type SentinelErrorReassignedRule struct {
	*rules.BaseRule
}

// NewSentinelErrorReassignedRule creates the rule
func NewSentinelErrorReassignedRule() *SentinelErrorReassignedRule {
	return &SentinelErrorReassignedRule{BaseRule: rules.NewBaseRule(
		"sentinel-error-reassigned",
		"patterns",
		"Detects a sentinel error variable reassigned at run time — errors made before the assignment no longer match errors.Is or == against it",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: a sentinel of another package is resolved through
// the project's types.
func (r *SentinelErrorReassignedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// AnalyzeGoProject reports the assignments of sentinels in production code.
func (r *SentinelErrorReassignedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	declared := declaredSentinels(ctx)
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		if file.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || (fn.Recv == nil && fn.Name.Name == "init") {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok || assign.Tok != token.ASSIGN {
					return true
				}
				for i, lhs := range assign.Lhs {
					v := reassignedSentinel(file.GoAST, info, assign, i, declared)
					if v == nil {
						continue
					}
					line := file.LineFor(lhs)
					if file.IsSuppressed(line, r.Name()) {
						continue
					}
					violation := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
						"Sentinel error %s reassigned in %s — an error made before the assignment holds the old value and no longer matches errors.Is or == against %s",
						v.Name(), fn.Name.Name, v.Name()))
					violation.WithCode(strings.TrimSpace(file.GetLine(line)))
					violation.WithSuggestion(fmt.Sprintf("Set %s once where it is declared; carry a configurable text in an error type that wraps it", v.Name()))
					violations = append(violations, violation)
				}
				return true
			})
		}
		return violations
	})
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SentinelErrorReassignedRule) RequiresSSA() bool { return false }

// reassignedSentinel returns the sentinel the i-th left side of an assignment
// replaces, if it is one.
func reassignedSentinel(file *ast.File, info *types.Info, assign *ast.AssignStmt, i int, declared map[*types.Var]bool) *types.Var {
	v, ok := variableOf(info, ast.Unparen(assign.Lhs[i])).(*types.Var)
	if !ok || !isPackageLevelVar(v) || !sentinelName(v.Name()) || !implementsError(v.Type()) {
		return nil
	}
	if declared[v] {
		return v
	}
	if len(assign.Rhs) == len(assign.Lhs) && sentinelValue(file, info, assign.Rhs[i]) {
		return v
	}
	return nil
}

// declaredSentinels returns the package error variables declared with a
// sentinel value.
func declaredSentinels(ctx *core.GoProjectContext) map[*types.Var]bool {
	declared := map[*types.Var]bool{}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Files {
			if file.GoAST != nil {
				collectDeclaredSentinels(file.GoAST, pkg.Package.TypesInfo, declared)
			}
		}
	}
	return declared
}

// collectDeclaredSentinels records a file's package variables declared with
// a sentinel value.
func collectDeclaredSentinels(file *ast.File, info *types.Info, declared map[*types.Var]bool) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Values) != len(vs.Names) {
				continue
			}
			for i, name := range vs.Names {
				if v, ok := info.Defs[name].(*types.Var); ok && sentinelValue(file, info, vs.Values[i]) {
					declared[v] = true
				}
			}
		}
	}
}

// sentinelValue reports an expression that makes or names a sentinel:
// errors.New, fmt.Errorf or another sentinel variable.
func sentinelValue(file *ast.File, info *types.Info, expr ast.Expr) bool {
	if call, ok := ast.Unparen(expr).(*ast.CallExpr); ok {
		return isPackageFuncCall(file, info, call, "errors", "New") || isPackageFuncCall(file, info, call, "fmt", "Errorf")
	}
	return sentinelVar(info, expr) != nil
}
