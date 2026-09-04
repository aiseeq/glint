package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewIgnoredDecisionResultRule())
}

// decisionVerbs start the name of a function whose bool result is a decision —
// "did it happen", "is it allowed" — rather than a description of the world.
// A prefix matches only on a name boundary, so Cancel is not a Can.
var decisionVerbs = []string{
	"acquire", "afford", "allocate", "allow", "book", "buy", "can", "charge",
	"claim", "consume", "deduct", "grant", "lock", "occupy", "permit",
	"reserve", "spend", "take", "try", "withdraw",
}

// decisionDocPhrases are the ways a doc comment promises that the caller must
// look at the result: it says what a false answer means.
var decisionDocPhrases = []string{
	"returns false", "return false", "returns ok=false",
	"false when", "false if", "false —", "false -", "false:",
	"вернул false", "вернёт false", "вернет false", "возвращает false",
}

// IgnoredDecisionResultRule detects a bool decision that the caller drops:
//
//	// Buy returns false when the money is not there.
//	func (w *Wallet) Buy(amount float64) bool
//
//	w.Buy(cost)                 // the answer is gone
//	return order(...)           // the order goes out unpaid
//
// The call compiles either way, so nothing marks the moment the guard stopped
// working: the action simply happens without the resource it asked for.
//
// Only functions whose result is a decision are considered — the name starts
// with a verb of permission or acquisition (Buy, Reserve, Acquire, Try…, Can…),
// or the doc comment states what a false answer means. A predicate that merely
// describes the world is out of scope, and so is a result the caller uses in a
// condition, an assignment or an argument.
type IgnoredDecisionResultRule struct {
	*rules.BaseRule
}

// NewIgnoredDecisionResultRule creates the rule
func NewIgnoredDecisionResultRule() *IgnoredDecisionResultRule {
	return &IgnoredDecisionResultRule{
		BaseRule: rules.NewBaseRule(
			"ignored-decision-result",
			"patterns",
			"Detects a dropped bool result of a function that decides whether the action may happen — the action then happens anyway",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile is a no-op: the decision is recognized by the callee's signature
// and doc, which live in the package, not in the calling file.
func (r *IgnoredDecisionResultRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *IgnoredDecisionResultRule) RequiresSSA() bool { return false }

// AnalyzeGoProject collects the decision functions of the project, then reports
// the call sites that throw their answer away.
func (r *IgnoredDecisionResultRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("ignored decision result: nil Go project context")
	}

	docs := make(map[*types.Func]string)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("ignored decision result: package has no typed syntax")
		}
		collectFuncDocs(pkg.Package.Syntax, pkg.Package.TypesInfo, docs)
	}

	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			violations = append(violations, r.analyzeFile(fileCtx, pkg.Package, docs)...)
		}
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

func (r *IgnoredDecisionResultRule) analyzeFile(
	fileCtx *core.FileContext,
	pkg *packages.Package,
	docs map[*types.Func]string,
) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ExprStmt:
			call, ok := ast.Unparen(node.X).(*ast.CallExpr)
			if !ok {
				return true
			}
			if fn, ok := r.decisionCallee(call, pkg, docs); ok {
				violations = append(violations, r.report(fileCtx, call, fn))
			}
		case *ast.AssignStmt:
			violations = append(violations, r.checkAssign(fileCtx, node, pkg, docs)...)
		}
		return true
	})

	return violations
}

// checkAssign reports a call whose bool answer lands in the blank identifier,
// both for `_ = Buy()` and for `value, _ := TryGet()`.
func (r *IgnoredDecisionResultRule) checkAssign(
	fileCtx *core.FileContext,
	assign *ast.AssignStmt,
	pkg *packages.Package,
	docs map[*types.Func]string,
) []*core.Violation {
	if len(assign.Rhs) != 1 {
		return nil
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return nil
	}
	fn, ok := r.decisionCallee(call, pkg, docs)
	if !ok {
		return nil
	}
	signature, ok := fn.Type().(*types.Signature)
	if !ok || signature.Results().Len() != len(assign.Lhs) {
		return nil
	}
	answer, ok := decisionResultIndex(signature)
	if !ok {
		return nil
	}
	if ident, ok := assign.Lhs[answer].(*ast.Ident); ok && ident.Name == "_" {
		return []*core.Violation{r.report(fileCtx, call, fn)}
	}
	return nil
}

// decisionCallee returns the called function when its bool result is a decision
// the caller is expected to act on.
func (r *IgnoredDecisionResultRule) decisionCallee(
	call *ast.CallExpr,
	pkg *packages.Package,
	docs map[*types.Func]string,
) (*types.Func, bool) {
	fn := calleeFunc(pkg, call)
	if fn == nil {
		return nil, false
	}
	signature, ok := fn.Type().(*types.Signature)
	if !ok {
		return nil, false
	}
	if _, isDecision := decisionResultIndex(signature); !isDecision {
		return nil, false
	}
	if !isDecisionName(fn.Name()) && !docPromisesFalse(docs[fn]) {
		return nil, false
	}
	return fn, true
}

func (r *IgnoredDecisionResultRule) report(fileCtx *core.FileContext, call *ast.CallExpr, fn *types.Func) *core.Violation {
	line := fileCtx.LineFor(call)
	v := r.CreateViolation(fileCtx.RelPath, line,
		fmt.Sprintf("Result of %s is discarded — the function answers whether the action is allowed, and the caller acts as if it always is", fn.Name()))
	v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Branch on the answer: if !%s(...) { … } — or stop calling it when the answer does not matter", fn.Name()))
	v.WithContext("pattern", "ignored_decision_result")
	v.WithContext("function", fn.Name())
	return v
}

// collectFuncDocs maps each declared function to its doc comment.
func collectFuncDocs(files []*ast.File, info *types.Info, docs map[*types.Func]string) {
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Doc == nil {
				continue
			}
			if obj, ok := info.Defs[fn.Name].(*types.Func); ok {
				docs[obj] = fn.Doc.Text()
			}
		}
	}
}

// decisionResultIndex returns the position of the answer in the signature: a
// lone bool, or the ok of a (value, ok) pair.
//
// A bool in any other position is not this rule's business. In (bool, error)
// the caller is already obliged to handle the error, and the bool next to it is
// routinely an "it was already done" note that idempotent code drops on
// purpose — flagging it produced only false positives on real code.
func decisionResultIndex(signature *types.Signature) (int, bool) {
	results := signature.Results()
	if results == nil {
		return 0, false
	}
	switch results.Len() {
	case 1:
		return 0, isBoolType(results.At(0).Type())
	case 2:
		return 1, isBoolType(results.At(1).Type()) && !isBoolType(results.At(0).Type())
	}
	return 0, false
}

func isBoolType(t types.Type) bool {
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.Bool
}

// isDecisionName reports whether the name starts with a verb of permission or
// acquisition. The prefix must end on a name boundary: Cancel is not a Can.
func isDecisionName(name string) bool {
	lower := strings.ToLower(name)
	for _, verb := range decisionVerbs {
		if !strings.HasPrefix(lower, verb) {
			continue
		}
		if len(name) == len(verb) {
			return true
		}
		next := rune(name[len(verb)])
		if next >= 'A' && next <= 'Z' {
			return true
		}
	}
	return false
}

// docPromisesFalse reports whether the doc comment tells the caller what a
// false answer means — a promise only a caller who reads the result can keep.
func docPromisesFalse(doc string) bool {
	lower := strings.ToLower(doc)
	for _, phrase := range decisionDocPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}
