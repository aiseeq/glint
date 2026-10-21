package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewNilDstInLoopRule())
}

// appendStyleParams are the parameter names of the standard library's
// append-style functions (strconv.AppendInt's dst, fmt.Append's b,
// binary.Append's buf, utf8.AppendRune's p).
var appendStyleParams = []string{"dst", "buf", "b", "p", "out"}

// NewNilDstInLoopRule creates nil-dst-in-loop: an append-style call - one
// that takes a destination slice and returns it extended, like
// strconv.AppendInt, fmt.Appendf, a decoder's DecodeAll(src, dst) - gets nil
// as the destination in a loop or a //glint:hot function, while its result
// does not outlive the iteration. The API exists to reuse a buffer, and nil
// makes it allocate a new one on every call:
//
//	for _, e := range index { raw, err := dec.DecodeAll(read(e), nil); use(raw) }
//	for _, e := range index { raw, err = dec.DecodeAll(read(e), raw[:0]); use(raw) }
//
// A result kept past the iteration - stored, appended as an element,
// returned, sent, captured - needs its own memory, and nil is right there.
func NewNilDstInLoopRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"nil-dst-in-loop",
			"patterns",
			"Detects an append-style call (strconv.AppendInt, fmt.Appendf, DecodeAll(src, dst)) given nil as the destination in a loop or a //glint:hot function while the result does not outlive the iteration — every call allocates the buffer the API was built to reuse",
			core.SeverityLow,
		),
		suggestion: "Keep one buffer outside the loop (or on the receiver) and pass buf[:0]: buf = strconv.AppendInt(buf[:0], n, 10)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		hot := hasDirective(fn.Doc, hotFunctionDirective)
		loops := loopBodies(fn.Body)
		var parents map[ast.Node]ast.Node
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || (!hot && !insideNodes(loops, call)) {
				return true
			}
			result, name, ok := nilDestination(scope, call)
			if !ok {
				return true
			}
			if parents == nil {
				parents = helpers.ParentMap(fn.Body)
			}
			if !resultOutlives(scope.info, fn, parents, call, result) {
				findings = append(findings, funcFinding{node: call, message: name + " gets nil as its destination and allocates a new buffer on every call — pass a reused buffer as buf[:0]"})
			}
			return true
		})
		return findings
	}
	return r
}

// nilDestination reports an append-style call with nil as its destination:
// a slice parameter whose type a result shares, named like a destination or
// of a function named Append*. A callee whose body is loaded has to append
// to it too: a slice it only hands back is no buffer. It returns the index
// of that result and the callee's name.
func nilDestination(scope funcScope, call *ast.CallExpr) (int, string, bool) {
	info := scope.info
	if builtinCallName(info, call) != "" {
		return 0, "", false
	}
	sig, ok := info.TypeOf(call.Fun).(*types.Signature)
	if !ok {
		return 0, "", false
	}
	name := types.ExprString(call.Fun)
	if fn := staticFunc(info, call); fn != nil {
		name = fn.Name()
	}
	for i, arg := range call.Args {
		if !helpers.IsNilIdent(ast.Unparen(arg)) || i >= sig.Params().Len() || (sig.Variadic() && i == sig.Params().Len()-1) {
			continue
		}
		param := sig.Params().At(i)
		if _, isSlice := param.Type().Underlying().(*types.Slice); !isSlice {
			continue
		}
		if !slices.Contains(appendStyleParams, param.Name()) && !strings.HasPrefix(name, "Append") {
			continue
		}
		if decl, loaded := scope.callee(call); loaded && !appendsToParam(decl, i) {
			continue
		}
		for j := range sig.Results().Len() {
			if types.Identical(sig.Results().At(j).Type(), param.Type()) {
				return j, types.ExprString(call.Fun), true
			}
		}
	}
	return 0, "", false
}

// appendsToParam reports a function whose parameter i is a destination its body
// appends to: the first argument of append, or a nil-able destination of an
// append-style call (strconv.AppendInt(dst, ...), enc.AppendEncode(dst[:0], ...)).
func appendsToParam(fn typedFuncDecl, i int) bool {
	param := paramObject(fn, i)
	if param == nil || fn.decl.Body == nil {
		return false
	}
	isParam := func(arg ast.Expr) bool {
		if s, ok := ast.Unparen(arg).(*ast.SliceExpr); ok {
			arg = s.X
		}
		ident, ok := ast.Unparen(arg).(*ast.Ident)
		return ok && fn.info.Uses[ident] == param
	}
	found := false
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if builtinCallName(fn.info, call) == "append" {
			found = len(call.Args) > 0 && isParam(call.Args[0])
			return !found
		}
		sig, ok := fn.info.TypeOf(call.Fun).(*types.Signature)
		if !ok {
			return true
		}
		for j, arg := range call.Args {
			if j < sig.Params().Len() && isParam(arg) &&
				(slices.Contains(appendStyleParams, sig.Params().At(j).Name()) || strings.HasPrefix(types.ExprString(call.Fun), "strconv.Append")) {
				found = true
			}
		}
		return !found
	})
	return found
}

// resultOutlives reports whether the call's result at index result is kept
// past the statement that uses it: assigned to anything but a fresh local,
// returned, put in a literal, sent, appended as an element, or a fresh local
// that is used that way or captured by a closure.
func resultOutlives(info *types.Info, fn *ast.FuncDecl, parents map[ast.Node]ast.Node, call *ast.CallExpr, result int) bool {
	switch parent := parents[call].(type) {
	case *ast.ExprStmt:
		return false
	case *ast.CallExpr:
		return keepsArgument(info, parent, call)
	case *ast.AssignStmt:
		if parent.Tok != token.DEFINE || len(parent.Rhs) != 1 || result >= len(parent.Lhs) {
			return true
		}
		ident, ok := parent.Lhs[result].(*ast.Ident)
		if !ok {
			return true
		}
		obj := info.Defs[ident]
		return obj == nil || localKept(info, fn, parents, obj)
	}
	return true
}

// keepsArgument reports a call that keeps an argument: append adds it as an
// element. A spread append(dst, src...) copies it.
func keepsArgument(info *types.Info, call *ast.CallExpr, arg ast.Expr) bool {
	if builtinCallName(info, call) != "append" {
		return false
	}
	return call.Args[0] == arg || !call.Ellipsis.IsValid()
}

// localKept reports whether a local slice escapes the statement that uses it.
func localKept(info *types.Info, fn *ast.FuncDecl, parents map[ast.Node]ast.Node, obj types.Object) bool {
	kept := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok || kept || info.Uses[ident] != obj {
			return !kept
		}
		for node := ast.Node(ident); node != nil && !kept; node = parents[node] {
			if _, isClosure := node.(*ast.FuncLit); isClosure {
				kept = true
			}
		}
		switch parent := parents[ident].(type) {
		case *ast.AssignStmt:
			kept = kept || slices.Contains(parent.Rhs, ast.Expr(ident))
		case *ast.ReturnStmt, *ast.CompositeLit, *ast.KeyValueExpr, *ast.SendStmt:
			kept = true
		case *ast.CallExpr:
			kept = kept || keepsArgument(info, parent, ident)
		}
		return !kept
	})
	return kept
}
