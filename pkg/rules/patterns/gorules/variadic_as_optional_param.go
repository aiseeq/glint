package gorules

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() { rules.Register(NewVariadicAsOptionalParamRule()) }

// NewVariadicAsOptionalParamRule finds variadic parameters that behave as
// optional single values: the function only checks their length and reads [0].
func NewVariadicAsOptionalParamRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"variadic-as-optional-param", "patterns",
			"Detects a variadic parameter the body reads only as values[0] under a length check — an optional argument in disguise, and every value past the first is silently dropped",
			core.SeverityLow,
		),
		Suggestion: "Take an explicit parameter that may be nil, or add a second function for the call with the value",
	}
	r.ForProject = func(decls map[*types.Func]patternkit.TypedFuncDecl) func(patternkit.FuncScope, *ast.FuncDecl) []patternkit.FuncFinding {
		valueUses := variadicFunctionValueUses(decls, patternkit.CollectCallSites(decls))
		return func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
			if fn.Body == nil {
				return nil
			}
			obj := variadicParameter(scope.Info, fn)
			function, _ := scope.Info.Defs[fn.Name].(*types.Func)
			if obj == nil || function == nil || valueUses[function.Pos()] {
				return nil
			}
			valid, indexed := optionalVariadicUses(scope.Info, fn.Body, obj)
			// The interface lookup scans the package's imports, so it runs only
			// for a method that is otherwise a finding.
			if !valid || !indexed || fn.Recv != nil && methodNameInVisibleInterface(scope.Info, fn) {
				return nil
			}
			return []patternkit.FuncFinding{{Node: fn, Message: "The variadic parameter is used only as an optional first value"}}
		}
	}
	return r
}

func variadicParameter(info *types.Info, fn *ast.FuncDecl) types.Object {
	if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return nil
	}
	last := fn.Type.Params.List[len(fn.Type.Params.List)-1]
	if _, ok := last.Type.(*ast.Ellipsis); !ok || len(last.Names) != 1 || last.Names[0].Name == "_" {
		return nil
	}
	return info.Defs[last.Names[0]]
}

func optionalVariadicUses(info *types.Info, body *ast.BlockStmt, param types.Object) (bool, bool) {
	parents := make(map[ast.Node]ast.Node)
	var stack []ast.Node
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	valid, indexed := true, false
	ast.Inspect(body, func(node ast.Node) bool {
		id, ok := node.(*ast.Ident)
		if !ok || info.Uses[id] != param {
			return true
		}
		parent := parents[id]
		if index, ok := parent.(*ast.IndexExpr); ok && ast.Unparen(index.X) == id && variadicIsZeroConstant(info, index.Index) {
			indexed = true
			return true
		}
		if call, ok := parent.(*ast.CallExpr); ok && builtinLen(info, call) && len(call.Args) == 1 && ast.Unparen(call.Args[0]) == id && isLengthComparison(info, parents, call) {
			return true
		}
		valid = false
		return true
	})
	return valid, indexed
}

func builtinLen(info *types.Info, call *ast.CallExpr) bool {
	id, ok := call.Fun.(*ast.Ident)
	if !ok || id.Name != "len" {
		return false
	}
	builtin, ok := info.Uses[id].(*types.Builtin)
	return ok && builtin.Name() == "len"
}

func isLengthComparison(info *types.Info, parents map[ast.Node]ast.Node, call *ast.CallExpr) bool {
	parent := parents[call]
	for {
		paren, ok := parent.(*ast.ParenExpr)
		if !ok {
			break
		}
		parent = parents[paren]
	}
	compare, ok := parent.(*ast.BinaryExpr)
	if !ok || compare.Op < token.EQL || compare.Op > token.GEQ {
		return false
	}
	op := compare.Op
	var other ast.Expr
	if ast.Unparen(compare.X) == call {
		other = compare.Y
	} else if ast.Unparen(compare.Y) == call {
		other = compare.X
		switch op {
		case token.LSS:
			op = token.GTR
		case token.LEQ:
			op = token.GEQ
		case token.GTR:
			op = token.LSS
		case token.GEQ:
			op = token.LEQ
		}
	} else {
		return false
	}
	value, ok := variadicConstantValue(info, other)
	if !ok || value.Kind() != constant.Int {
		return false
	}
	if constant.Sign(value) == 0 {
		return op == token.GTR || op == token.NEQ || op == token.EQL || op == token.LEQ
	}
	return constant.Compare(value, token.EQL, constant.MakeInt64(1)) &&
		(op == token.GEQ || op == token.LSS || op == token.EQL)
}

func variadicIsZeroConstant(info *types.Info, expr ast.Expr) bool {
	value, ok := variadicConstantValue(info, expr)
	return ok && value.Kind() == constant.Int && constant.Sign(value) == 0
}

func variadicConstantValue(info *types.Info, expr ast.Expr) (constant.Value, bool) {
	value, ok := info.Types[ast.Unparen(expr)]
	return value.Value, ok && value.Value != nil
}

func variadicFunctionValueUses(decls map[*types.Func]patternkit.TypedFuncDecl, callers map[*types.Func][]patternkit.FuncCallSite) map[token.Pos]bool {
	usedAsValue := make(map[token.Pos]bool)
	called := make(map[token.Pos]bool)
	for _, sites := range callers {
		for _, site := range sites {
			if ident := calledFunctionIdent(site.Call); ident != nil {
				called[ident.Pos()] = true
			}
		}
	}
	seenInfo := make(map[*types.Info]bool)
	for _, decl := range decls {
		if decl.Info == nil || seenInfo[decl.Info] {
			continue
		}
		seenInfo[decl.Info] = true
		for id, object := range decl.Info.Uses {
			obj, ok := object.(*types.Func)
			if !ok {
				continue
			}
			if called[id.Pos()] {
				continue
			}
			usedAsValue[obj.Pos()] = true
		}
	}
	return usedAsValue
}

func calledFunctionIdent(call *ast.CallExpr) *ast.Ident {
	if call == nil {
		return nil
	}
	switch callee := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		return callee
	case *ast.SelectorExpr:
		return callee.Sel
	default:
		return nil
	}
}

func methodNameInVisibleInterface(info *types.Info, fn *ast.FuncDecl) bool {
	if fn.Name == nil || info == nil {
		return false
	}
	function, _ := info.Defs[fn.Name].(*types.Func)
	if function == nil || packageHasInterfaceMethod(function.Pkg(), fn.Name.Name, false) {
		return true
	}
	imports := map[*types.Package]bool{}
	for _, object := range info.Defs {
		if imported, ok := object.(*types.PkgName); ok {
			imports[imported.Imported()] = true
		}
	}
	for _, object := range info.Implicits {
		if imported, ok := object.(*types.PkgName); ok {
			imports[imported.Imported()] = true
		}
	}
	for imported := range imports {
		if packageHasInterfaceMethod(imported, fn.Name.Name, true) {
			return true
		}
	}
	return false
}

func packageHasInterfaceMethod(pkg *types.Package, name string, exportedOnly bool) bool {
	if pkg == nil || pkg.Scope() == nil {
		return false
	}
	for _, objectName := range pkg.Scope().Names() {
		if exportedOnly && !ast.IsExported(objectName) {
			continue
		}
		typeName, ok := pkg.Scope().Lookup(objectName).(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := typeName.Type().(*types.Named)
		if !ok {
			continue
		}
		iface, ok := named.Underlying().(*types.Interface)
		if !ok {
			continue
		}
		iface.Complete()
		for method := range iface.Methods() {
			if method.Name() == name {
				return true
			}
		}
	}
	return false
}
