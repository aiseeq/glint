package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewAllocationInHotFunctionRule())
}

// hotFunctionDirective marks a function as a hot path: a line of its doc
// comment, spelled like a compiler directive (no space after the slashes).
const hotFunctionDirective = "//glint:hot"

// allocatingPackageFuncs are the library functions that return a new slice,
// map or string on every call.
var allocatingPackageFuncs = []struct {
	pkg   string
	names []string
}{
	{"slices", []string{"Clone", "Concat", "Collect", "Repeat", "Sorted", "SortedFunc", "SortedStableFunc"}},
	{"maps", []string{"Clone", "Collect"}},
	{"bytes", []string{"Clone"}},
	{"strings", []string{"Clone"}},
}

// AllocationInHotFunctionRule detects heap allocations in the body of a
// function its author marked hot with //glint:hot: make, new, a slice or map
// literal, &T{...}, slices.Clone and its kin, and append to a slice that
// starts empty in the function. A function run every tick that allocates
// leaves garbage every tick, and the collector's work grows with it; the hot
// form keeps its buffers on the receiver or takes them as parameters and
// refills them with append(buf[:0], ...).
type AllocationInHotFunctionRule struct {
	*rules.BaseRule
}

// NewAllocationInHotFunctionRule creates the rule.
func NewAllocationInHotFunctionRule() *AllocationInHotFunctionRule {
	return &AllocationInHotFunctionRule{
		BaseRule: rules.NewBaseRule(
			"allocation-in-hot-function",
			"patterns",
			"Detects an allocation in a function marked //glint:hot: make, new, a slice or map literal, &T{...}, slices.Clone and the like, append to a slice that starts empty in the function — the hot path leaves garbage on every call; reuse a buffer with append(buf[:0], ...)",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op: whether a literal is a slice needs its type.
func (r *AllocationInHotFunctionRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *AllocationInHotFunctionRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every function marked hot.
func (r *AllocationInHotFunctionRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		return analyzeGoFunctions(file, func(fn *ast.FuncDecl) []*core.Violation {
			if !hasDirective(fn.Doc, hotFunctionDirective) {
				return nil
			}
			var violations []*core.Violation
			for _, f := range hotAllocations(file.GoAST, info, fn) {
				line := file.LineFor(f.node)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, f.message)
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Keep the buffer on the receiver or take it as a parameter and refill it with append(buf[:0], ...); a deliberate allocation outside the loop takes // " + r.Name() + ": safe — <reason>")
				violations = append(violations, v)
			}
			return violations
		})
	})
}

// hasDirective reports whether a line of the comment group is the directive.
func hasDirective(doc *ast.CommentGroup, directive string) bool {
	if doc == nil {
		return false
	}
	for _, c := range doc.List {
		if strings.TrimSpace(c.Text) == directive {
			return true
		}
	}
	return false
}

// hotAllocations returns the allocations of the function body, closures
// included.
func hotAllocations(file *ast.File, info *types.Info, fn *ast.FuncDecl) []funcFinding {
	fresh := freshSlices(info, fn)
	in := " in hot function " + fn.Name.Name
	var findings []funcFinding
	report := func(node ast.Node, what string) {
		findings = append(findings, funcFinding{node: node, message: what + " allocates" + in})
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if what, ok := allocatingCall(file, info, node, fresh); ok {
				report(node, what)
			}
		case *ast.CompositeLit:
			switch info.TypeOf(node).Underlying().(type) {
			case *types.Slice:
				report(node, "a slice literal")
			case *types.Map:
				report(node, "a map literal")
			}
		case *ast.UnaryExpr:
			if lit, ok := ast.Unparen(node.X).(*ast.CompositeLit); ok && node.Op == token.AND {
				report(node, fmt.Sprintf("&%s{...}", types.ExprString(lit.Type)))
			}
		}
		return true
	})
	return findings
}

// allocatingCall describes a call that allocates: make, new, a library clone,
// append to nil or to a slice the function starts empty.
func allocatingCall(file *ast.File, info *types.Info, call *ast.CallExpr, fresh map[types.Object]bool) (string, bool) {
	switch name := builtinCallName(info, call); name {
	case "make", "new":
		return name, true
	case "append":
		return appendToFresh(info, call, fresh)
	case "":
	default:
		return "", false
	}
	for _, lib := range allocatingPackageFuncs {
		if name, ok := packageFuncName(file, info, call, lib.pkg); ok && slices.Contains(lib.names, name) {
			return lib.pkg + "." + name, true
		}
	}
	return "", false
}

// appendToFresh describes an append whose slice has no capacity to reuse:
// nil, or a local slice that every assignment leaves empty.
func appendToFresh(info *types.Info, call *ast.CallExpr, fresh map[types.Object]bool) (string, bool) {
	if len(call.Args) == 0 {
		return "", false
	}
	switch first := ast.Unparen(call.Args[0]).(type) {
	case *ast.CallExpr:
		if isNilConversion(info, first) {
			return "append to nil", true
		}
	case *ast.Ident:
		if obj := info.Uses[first]; obj != nil && fresh[obj] {
			return "append to " + first.Name + ", which starts empty in the function,", true
		}
	}
	return "", false
}

// isNilConversion reports []T(nil).
func isNilConversion(info *types.Info, call *ast.CallExpr) bool {
	if len(call.Args) != 1 || !isNilIdent(ast.Unparen(call.Args[0])) {
		return false
	}
	tv, ok := info.Types[call.Fun]
	return ok && tv.IsType()
}

// freshSlices returns the slice variables of the function - locals and named
// results - that start without capacity and are only ever assigned an empty
// value (nil, a literal) or an append to themselves. A slice assigned from a
// buffer, a parameter or a call result, or whose address is taken, has
// capacity the function cannot see and is not fresh. A make has its own
// report, so a slice made in the function is not fresh either.
func freshSlices(info *types.Info, fn *ast.FuncDecl) map[types.Object]bool {
	scan := freshSliceScan{info: info, candidate: map[types.Object]bool{}, spoiled: map[types.Object]bool{}}
	if fn.Type.Results != nil {
		for _, field := range fn.Type.Results.List {
			for _, name := range field.Names {
				scan.assign(name, nil)
			}
		}
	}
	ast.Inspect(fn.Body, scan.visit)

	fresh := map[types.Object]bool{}
	for obj := range scan.candidate {
		if !scan.spoiled[obj] {
			fresh[obj] = true
		}
	}
	return fresh
}

// freshSliceScan collects the assignments of a function's slice variables.
type freshSliceScan struct {
	info      *types.Info
	candidate map[types.Object]bool
	spoiled   map[types.Object]bool
}

// objOf returns the variable an identifier defines or uses.
func (s freshSliceScan) objOf(expr ast.Expr) types.Object {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil
	}
	if obj := s.info.Defs[ident]; obj != nil {
		return obj
	}
	return s.info.Uses[ident]
}

// spoil marks the variable of expr as holding capacity the scan cannot see.
func (s freshSliceScan) spoil(expr ast.Expr) {
	if obj := s.objOf(expr); obj != nil {
		s.spoiled[obj] = true
	}
}

// assign records lhs = rhs; a nil rhs is a declaration without a value.
func (s freshSliceScan) assign(lhs, rhs ast.Expr) {
	obj := s.objOf(lhs)
	if obj == nil {
		return
	}
	if _, isSlice := obj.Type().Underlying().(*types.Slice); !isSlice {
		return
	}
	if rhs == nil || emptySliceValue(s.info, rhs) {
		s.candidate[obj] = true
		return
	}
	if call, ok := ast.Unparen(rhs).(*ast.CallExpr); ok && builtinCallName(s.info, call) == "append" && len(call.Args) > 0 && s.objOf(call.Args[0]) == obj {
		return
	}
	s.spoiled[obj] = true
}

// visit records the assignments of one node.
func (s freshSliceScan) visit(n ast.Node) bool {
	switch node := n.(type) {
	case *ast.ValueSpec:
		for i, name := range node.Names {
			switch {
			case i < len(node.Values):
				s.assign(name, node.Values[i])
			case len(node.Values) > 0:
				s.spoil(name)
			default:
				s.assign(name, nil)
			}
		}
	case *ast.AssignStmt:
		if len(node.Lhs) != len(node.Rhs) {
			for _, lhs := range node.Lhs {
				s.spoil(lhs)
			}
			return true
		}
		for i := range node.Lhs {
			s.assign(node.Lhs[i], node.Rhs[i])
		}
	case *ast.RangeStmt:
		s.spoil(node.Key)
		s.spoil(node.Value)
	case *ast.UnaryExpr:
		if node.Op == token.AND {
			s.spoil(node.X)
		}
	}
	return true
}

// emptySliceValue reports a value with no capacity of its own to reuse: nil,
// []T(nil), a slice literal.
func emptySliceValue(info *types.Info, expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return isNilIdent(e)
	case *ast.CallExpr:
		return isNilConversion(info, e)
	case *ast.CompositeLit:
		return true
	}
	return false
}

// builtinCallName returns the name of the builtin a call invokes, "" for
// any other call.
func builtinCallName(info *types.Info, call *ast.CallExpr) string {
	ident, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return ""
	}
	if builtin, isBuiltin := info.Uses[ident].(*types.Builtin); isBuiltin {
		return builtin.Name()
	}
	return ""
}
