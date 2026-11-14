package shellrules

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

type rangeFlowResult struct {
	executes bool
	unknown  bool
}

// hasSignalStringRange makes test-only package helpers available to the
// typed range analysis when a command table is present.
func hasSignalStringRange(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		loop, ok := n.(*ast.RangeStmt)
		if !ok {
			return !found
		}
		values, ok := ast.Unparen(loop.X).(*ast.CompositeLit)
		if !ok {
			return !found
		}
		array, ok := ast.Unparen(values.Type).(*ast.ArrayType)
		if !ok {
			return !found
		}
		elementType, ok := ast.Unparen(array.Elt).(*ast.Ident)
		if !ok || elementType.Name != "string" {
			return !found
		}
		for _, element := range values.Elts {
			literal, ok := ast.Unparen(element).(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			value, err := strconv.Unquote(literal.Value)
			if err == nil && strings.Contains(value, "kill") {
				found = true
				return false
			}
		}
		return !found
	})
	return found
}

func rangeStringLiterals(file *ast.File, info *types.Info, pkg *signalPackage) (data, executed map[*ast.BasicLit]bool) {
	data = make(map[*ast.BasicLit]bool)
	executed = make(map[*ast.BasicLit]bool)
	if info == nil || pkg == nil {
		return data, executed
	}
	ast.Inspect(file, func(n ast.Node) bool {
		loop, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		values, ok := ast.Unparen(loop.X).(*ast.CompositeLit)
		if !ok {
			return true
		}
		array, ok := ast.Unparen(values.Type).(*ast.ArrayType)
		if !ok {
			return true
		}
		elementType, ok := ast.Unparen(array.Elt).(*ast.Ident)
		if !ok || elementType.Name != "string" {
			return true
		}
		value, ok := ast.Unparen(loop.Value).(*ast.Ident)
		if !ok || value.Name == "_" {
			return true
		}
		object := info.ObjectOf(value)
		if object == nil {
			return true
		}
		scope := rangeEnclosingScope(file, loop)
		flow := analyzeRangeObject(scope, map[types.Object]bool{object: true}, info, pkg, 0, make(map[*types.Func]bool))
		for _, element := range values.Elts {
			ast.Inspect(element, func(child ast.Node) bool {
				literal, ok := child.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				if flow.executes || flow.unknown {
					executed[literal] = true
				} else {
					data[literal] = true
				}
				return true
			})
		}
		return true
	})
	return data, executed
}

func analyzeRangeObject(scope ast.Node, tracked map[types.Object]bool, info *types.Info, pkg *signalPackage, depth int, stack map[*types.Func]bool) rangeFlowResult {
	if depth >= 8 {
		return rangeFlowResult{unknown: true}
	}
	propagated := make(map[*ast.Ident]bool)
	for changed := true; changed; {
		changed = false
		ast.Inspect(scope, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, rhs := range n.Rhs {
					if !rangeExprDepends(rhs, tracked, info) {
						continue
					}
					for _, lhs := range n.Lhs {
						var obj types.Object
						switch lhs := ast.Unparen(lhs).(type) {
						case *ast.Ident:
							if lhs.Name != "_" {
								obj = info.ObjectOf(lhs)
							}
						case *ast.SelectorExpr:
							obj = info.Uses[lhs.Sel]
							propagated[lhs.Sel] = true
						}
						if obj == nil {
							continue
						}
						if obj != nil && !tracked[obj] {
							tracked[obj] = true
							changed = true
						}
						if obj != nil && tracked[obj] {
							ast.Inspect(rhs, func(child ast.Node) bool {
								if use, ok := child.(*ast.Ident); ok && tracked[info.Uses[use]] {
									propagated[use] = true
								}
								return true
							})
						}
					}
				}
			case *ast.ValueSpec:
				for _, rhs := range n.Values {
					if !rangeExprDepends(rhs, tracked, info) {
						continue
					}
					for _, lhs := range n.Names {
						obj := info.ObjectOf(lhs)
						if obj != nil && !tracked[obj] {
							tracked[obj] = true
							changed = true
						}
						if obj != nil && tracked[obj] {
							ast.Inspect(rhs, func(child ast.Node) bool {
								if use, ok := child.(*ast.Ident); ok && tracked[info.Uses[use]] {
									propagated[use] = true
								}
								return true
							})
						}
					}
				}
			}
			return true
		})
	}

	result := rangeFlowResult{}
	handled := make(map[*ast.Ident]bool)
	ast.Inspect(scope, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var dependent []int
		for i, arg := range call.Args {
			if rangeExprDepends(arg, tracked, info) {
				dependent = append(dependent, i)
			}
		}
		if len(dependent) == 0 {
			return true
		}
		for _, i := range dependent {
			markRangeUses(call.Args[i], tracked, info, handled)
		}
		if _, ok := shellExecutionScript(call, info); ok {
			result.executes = true
			return true
		}
		if rangeDataCall(call, info) {
			return true
		}
		fn := rangeCallFunc(call, info)
		if fn != nil && fn.Pkg() != nil && pkg.path != "" && fn.Pkg().Path() == pkg.path {
			if stack[fn] {
				result.unknown = true
				return true
			}
			decl := rangeFunctionDecl(fn, pkg, info)
			if decl == nil || decl.Body == nil {
				result.unknown = true
				return true
			}
			params := decl.Type.Params
			if params == nil {
				result.unknown = true
				return true
			}
			nextStack := make(map[*types.Func]bool, len(stack)+1)
			for active := range stack {
				nextStack[active] = true
			}
			nextStack[fn] = true
			signature, ok := fn.Type().(*types.Signature)
			if !ok {
				result.unknown = true
				return true
			}
			for _, argIndex := range dependent {
				paramIndex := argIndex
				paramList := params
				if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
					if selection := info.Selections[selector]; selection != nil && selection.Kind() == types.MethodExpr {
						if paramIndex == 0 {
							paramList = decl.Recv
						} else {
							paramIndex--
						}
					}
				}
				parameter, found := rangeParameterName(paramList, paramIndex, signature.Variadic() && paramList == params)
				if !found {
					result.unknown = true
					continue
				}
				if parameter == nil {
					continue
				}
				param := info.ObjectOf(parameter)
				if param == nil {
					result.unknown = true
					continue
				}
				nested := analyzeRangeObject(decl.Body, map[types.Object]bool{param: true}, info, pkg, depth+1, nextStack)
				result.executes = result.executes || nested.executes
				result.unknown = result.unknown || nested.unknown
			}
			return true
		}
		result.unknown = true
		return true
	})

	ast.Inspect(scope, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || !tracked[info.Uses[id]] || propagated[id] || handled[id] {
			return true
		}
		if rangeIdentInEquality(id, scope, tracked, info) {
			return true
		}
		result.unknown = true
		return true
	})
	return result
}

func rangeEnclosingScope(file *ast.File, target *ast.RangeStmt) ast.Node {
	var stack, path []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		stack = append(stack, n)
		if n == target {
			path = append(path, stack...)
			return false
		}
		return true
	})
	for i := len(path) - 1; i >= 0; i-- {
		switch function := path[i].(type) {
		case *ast.FuncDecl:
			return function.Body
		case *ast.FuncLit:
			return function.Body
		}
	}
	return target.Body
}

// rangeParameterName maps a call argument to a parameter name. AST fields may
// declare several parameters (a, b string), while variadic arguments all map
// to the last field.
func rangeParameterName(params *ast.FieldList, index int, variadic bool) (*ast.Ident, bool) {
	if params == nil || index < 0 {
		return nil, false
	}
	position := 0
	for i, field := range params.List {
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		if variadic && i == len(params.List)-1 && index >= position {
			if len(field.Names) == 0 {
				return nil, true
			}
			return field.Names[0], true
		}
		if index >= position && index < position+count {
			if len(field.Names) == 0 {
				return nil, true
			}
			return field.Names[index-position], true
		}
		position += count
	}
	return nil, false
}

func shellExecutionScript(call *ast.CallExpr, info *types.Info) (ast.Expr, bool) {
	name := ""
	if info == nil {
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Command" && selector.Sel.Name != "CommandContext" {
			return nil, false
		}
		name = selector.Sel.Name
	} else {
		fn := rangeCallFunc(call, info)
		if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "os/exec" || fn.Name() != "Command" && fn.Name() != "CommandContext" {
			return nil, false
		}
		name = fn.Name()
	}
	if name != "Command" && name != "CommandContext" {
		return nil, false
	}
	start := 0
	if name == "CommandContext" {
		start = 1
	}
	if len(call.Args) <= start {
		return nil, false
	}
	command, ok := helpers.StringLiteral(call.Args[start])
	if !ok {
		return nil, false
	}
	command = filepath.Base(command)
	if command == "sh" || command == "bash" {
		if len(call.Args) < start+3 {
			return nil, false
		}
		flag, ok := helpers.StringLiteral(call.Args[start+1])
		if !ok || flag != "-c" {
			return nil, false
		}
		return call.Args[start+2], true
	}
	if command != "env" {
		return nil, false
	}
	for i := start + 1; i < len(call.Args); i++ {
		word, literal := helpers.StringLiteral(call.Args[i])
		if !literal {
			return nil, false
		}
		if word == "--" || word == "-i" || word == "-0" || word == "-u" || strings.HasPrefix(word, "--unset=") || strings.HasPrefix(word, "--chdir=") {
			if word == "-u" {
				i++
			}
			continue
		}
		if strings.Contains(word, "=") && !strings.HasPrefix(word, "-") {
			continue
		}
		if filepath.Base(word) != "sh" && filepath.Base(word) != "bash" {
			return nil, false
		}
		if i+2 >= len(call.Args) {
			return nil, false
		}
		flag, ok := helpers.StringLiteral(call.Args[i+1])
		if !ok || flag != "-c" {
			return nil, false
		}
		return call.Args[i+2], true
	}
	return nil, false
}

func rangeCallFunc(call *ast.CallExpr, info *types.Info) *types.Func {
	if info == nil {
		return nil
	}
	var object types.Object
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		object = info.Uses[fun]
	case *ast.SelectorExpr:
		object = info.Uses[fun.Sel]
	}
	fn, _ := object.(*types.Func)
	return fn
}

func rangeExprDepends(expr ast.Node, tracked map[types.Object]bool, info *types.Info) bool {
	depends := false
	ast.Inspect(expr, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			if tracked[info.Uses[n]] {
				depends = true
			}
		case *ast.SelectorExpr:
			if tracked[info.Uses[n.Sel]] {
				depends = true
			}
		}
		return !depends
	})
	return depends
}

func markRangeUses(expr ast.Node, tracked map[types.Object]bool, info *types.Info, handled map[*ast.Ident]bool) {
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && tracked[info.Uses[id]] {
			handled[id] = true
		}
		return true
	})
}

func rangeDataCall(call *ast.CallExpr, info *types.Info) bool {
	if isSubtest(call, info) {
		return true
	}
	fn := rangeCallFunc(call, info)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	if isTextComparison(call) {
		return fn.Pkg() != nil && (fn.Pkg().Path() == "strings" || fn.Pkg().Path() == "bytes")
	}
	if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && testingReceiver(info.TypeOf(selector.X)) {
		for _, prefix := range []string{"Log", "Error", "Fatal", "Skip"} {
			if strings.HasPrefix(fn.Name(), prefix) {
				return true
			}
		}
	}
	name, path := fn.Name(), fn.Pkg().Path()
	if path == "strings" || path == "bytes" {
		return true
	}
	if path == "fmt" && (strings.HasPrefix(name, "Sprint") || strings.HasPrefix(name, "Fprint") || strings.HasPrefix(name, "Errorf")) {
		return true
	}
	if (path == "log" || path == "log/slog") && hasRangeLoggerPrefix(name) {
		return true
	}
	return (path == "strings" || path == "bytes") && textComparisons[name]
}

func hasRangeLoggerPrefix(name string) bool {
	for _, prefix := range loggerPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func rangeFunctionDecl(fn *types.Func, pkg *signalPackage, info *types.Info) *ast.FuncDecl {
	for _, file := range pkg.files {
		for _, decl := range file.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if ok && info.Defs[function.Name] == fn {
				return function
			}
		}
	}
	return nil
}

func rangeIdentInEquality(id *ast.Ident, scope ast.Node, tracked map[types.Object]bool, info *types.Info) bool {
	found := false
	ast.Inspect(scope, func(n ast.Node) bool {
		binary, ok := n.(*ast.BinaryExpr)
		if !ok || binary.Op != token.EQL && binary.Op != token.NEQ {
			return true
		}
		ast.Inspect(binary, func(child ast.Node) bool {
			if child == id && tracked[info.Uses[id]] {
				found = true
			}
			return !found
		})
		return !found
	})
	return found
}
