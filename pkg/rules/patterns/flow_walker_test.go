package patterns

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flowTraceRule is a minimal flow rule for walker tests: the state is the set
// of call traces ("a,b") of the paths reaching a point, and every path that
// leaves the function (return or falling off the end) is collected in exits.
type flowTraceRule struct {
	exits []string
}

func (r *flowTraceRule) cloneState(paths []string) []string { return slices.Clone(paths) }

func (r *flowTraceRule) joinStates(left, right []string) []string {
	return joinFlowPaths(left, right, func(path string) string { return path })
}

func (r *flowTraceRule) liveState(paths []string) bool { return len(paths) > 0 }

func (r *flowTraceRule) deadState() []string { return nil }

func (r *flowTraceRule) enterScope(_ flowScopeKind, _ ast.Node, parent struct{}, paths []string) (struct{}, []string) {
	return parent, paths
}

func (r *flowTraceRule) leaveScope(flowScopeKind, struct{}, *flowEdges[[]string]) {}

func (r *flowTraceRule) simpleStmt(stmt ast.Stmt, paths []string, _ struct{}) ([]string, bool) {
	if _, isReturn := stmt.(*ast.ReturnStmt); isReturn {
		r.exits = r.joinStates(r.exits, paths)
		return nil, true
	}
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return paths, false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return paths, false
	}
	name, ok := call.Fun.(*ast.Ident)
	if !ok {
		return paths, false
	}
	next := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			next = append(next, name.Name)
			continue
		}
		next = append(next, path+","+name.Name)
	}
	return next, false
}

func (r *flowTraceRule) ifCondition(_ *ast.IfStmt, paths []string, _ struct{}) ([]string, []string) {
	return slices.Clone(paths), slices.Clone(paths)
}

func (r *flowTraceRule) flowExpr(_ ast.Expr, paths []string, _ struct{}) []string { return paths }

func (r *flowTraceRule) rangeVars(_ *ast.RangeStmt, paths []string, _ struct{}) []string {
	return paths
}

func (r *flowTraceRule) typeSwitchGuard(_ ast.Stmt, paths []string, _ struct{}) []string {
	return paths
}

func (r *flowTraceRule) caseClause(_ ast.Stmt, _ *ast.CaseClause, paths []string, parent struct{}) ([]string, struct{}) {
	return paths, parent
}

func (r *flowTraceRule) commClause(_ *ast.CommClause, paths []string, parent struct{}) ([]string, struct{}) {
	return paths, parent
}

func (r *flowTraceRule) normalize(*flowEdges[[]string]) {}

// flowTraces walks the body of function f in src and returns the traces of
// every path leaving it.
func flowTraces(t *testing.T, src string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "trace.go", "package p\n"+src, parser.SkipObjectResolution)
	require.NoError(t, err)
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "f" {
			body = fn.Body
		}
	}
	require.NotNil(t, body)
	rule := &flowTraceRule{}
	walker := &flowWalker[[]string, struct{}]{rule: rule}
	edges := walker.walk(body, []string{""}, struct{}{})
	exits := rule.joinStates(rule.exits, edges.next)
	slices.Sort(exits)
	return exits
}

func TestFlowWalker_LabeledBranchesGotoAndFallthrough(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "labeled break leaves an infinite loop from a select",
			src: `func f(ch chan int) {
outer:
	for {
		select {
		case <-ch:
			a()
			break outer
		}
	}
	b()
}`,
			want: []string{"a,b"},
		},
		{
			name: "labeled break leaves a labeled switch",
			src: `func f(k int, x bool) {
sw:
	switch k {
	case 1:
		a()
		if x {
			break sw
		}
		c()
	}
	b()
}`,
			want: []string{"a,b", "a,c,b", "b"},
		},
		{
			name: "labeled continue returns to the outer loop",
			src: `func f(xs []int) {
outer:
	for range xs {
		for {
			a()
			continue outer
		}
	}
	b()
}`,
			want: []string{"a,b", "b"},
		},
		{
			name: "fallthrough enters the next clause body",
			src: `func f(k int) {
	switch k {
	case 1:
		a()
		fallthrough
	case 2:
		b()
	}
	c()
}`,
			want: []string{"a,b,c", "b,c", "c"},
		},
		{
			name: "forward goto reaches the label after a return",
			src: `func f(x bool) {
	if x {
		a()
		goto done
	}
	return
done:
	b()
}`,
			want: []string{"", "a,b"},
		},
		{
			name: "backward goto does not end the path",
			src: `func f(x bool) {
again:
	a()
	if x {
		c()
		goto again
	}
	b()
}`,
			want: []string{"a,b", "a,c,b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, flowTraces(t, tt.src), strings.TrimSpace(tt.src))
		})
	}
}
