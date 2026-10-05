package patterns

import (
	"go/ast"
	"go/types"
	"slices"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewCursorFeedBlockedByRejectedRecordRule())
}

// NewCursorFeedBlockedByRejectedRecordRule creates
// cursor-feed-blocked-by-rejected-record: a feed read page by page after a
// cursor that fails the whole page when its converter refuses one record
// never moves the cursor past that record - it is first behind the cursor on
// every run, and the feed stops for good:
//
//	func (c *Client) List(ctx context.Context, cursor string) (*Page, error) {
//		for i, w := range wire.Items {
//			item, err := w.toItem()          // "empty client"
//			if err != nil {
//				return nil, fmt.Errorf("item %d: %w", i, err)
//			}
//
// A converter whose result carries a defect mark (DataIssue, Invalid...) has
// a way to keep such a record, and is not reported.
func NewCursorFeedBlockedByRejectedRecordRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"cursor-feed-blocked-by-rejected-record",
			"patterns",
			"Detects a cursor-paged feed whose page fails as a whole when the converter refuses one record — the record stays first behind the cursor and the feed never moves on",
			core.SeverityMedium,
		),
		suggestion: "Keep a record that cannot be read fully with a defect mark (or quarantine it) and move the cursor on; fail the page only for what makes the cursor itself unknown",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil || !readsAfterCursor(scope.info, fn) {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			loop, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			for i, stmt := range loop.Body.List {
				converter, ok := refusingConverter(scope, stmt)
				if !ok || i+1 >= len(loop.Body.List) {
					continue
				}
				if abort, ok := loop.Body.List[i+1].(*ast.IfStmt); ok && isErrNotNil(abort.Cond) && endsWithReturn(abort.Body) {
					findings = append(findings, funcFinding{node: abort, message: "One record " + converter + " refuses fails the whole page of a cursor feed — the record stays first behind the cursor and the feed never moves on; keep it with a defect mark instead"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// readsAfterCursor reports a function that takes a cursor or returns a page
// carrying the next one.
func readsAfterCursor(info *types.Info, fn *ast.FuncDecl) bool {
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok {
		return false
	}
	for v := range sig.Params().Variables() {
		if slices.Contains(helpers.IdentifierWords(v.Name()), "cursor") {
			return true
		}
	}
	for v := range sig.Results().Variables() {
		if hasFieldWord(v.Type(), []string{"cursor"}) {
			return true
		}
	}
	return false
}

// defectMarkWords name a field that keeps what was wrong with a record.
var defectMarkWords = []string{"issue", "issues", "defect", "defects", "quarantine", "quarantined", "invalid", "malformed", "problem", "problems", "anomaly", "warning", "warnings", "rejected"}

// refusingConverter returns the name of the loaded function stmt calls as
// `v, err := convert(...)` when it can return an error and its result has no
// field to mark a defect.
func refusingConverter(scope funcScope, stmt ast.Stmt) (string, bool) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
		return "", false
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return "", false
	}
	decl, ok := scope.callee(call)
	if !ok || !returnsFailure(decl.decl) {
		return "", false
	}
	if hasFieldWord(scope.info.TypeOf(assign.Lhs[0]), defectMarkWords) {
		return "", false
	}
	return decl.decl.Name.Name, true
}

// returnsFailure reports a function with a return whose last result is not
// nil.
func returnsFailure(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if ret, ok := n.(*ast.ReturnStmt); ok && len(ret.Results) > 1 && !isIdentNamed(ret.Results[len(ret.Results)-1], "nil") {
			found = true
		}
		return !found
	})
	return found
}

// hasFieldWord reports a struct (or pointer to one) with a field named by
// one of words.
func hasFieldWord(t types.Type, words []string) bool {
	if t == nil {
		return false
	}
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for field := range st.Fields() {
		if slices.ContainsFunc(helpers.IdentifierWords(field.Name()), func(w string) bool { return slices.Contains(words, w) }) {
			return true
		}
	}
	return false
}
