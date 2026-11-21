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
				switch {
				case flow.executes:
					executed[literal] = true
				case !flow.unknown:
					data[literal] = true
				}
				// An unknown use is neither: the literal keeps the verdict it
				// has without the range analysis (a lone kill stays a fixture).
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
	propagated := propagateRangeObjects(scope, tracked, info)
	result, handled := analyzeRangeCalls(scope, tracked, info, pkg, depth, stack)
	markUnknownRangeUses(scope, tracked, propagated, handled, info, &result)
	return result
}

func propagateRangeObjects(scope ast.Node, tracked map[types.Object]bool, info *types.Info) map[*ast.Ident]bool {
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
	return propagated
}

func analyzeRangeCalls(scope ast.Node, tracked map[types.Object]bool, info *types.Info, pkg *signalPackage, depth int, stack map[*types.Func]bool) (rangeFlowResult, map[*ast.Ident]bool) {
	result := rangeFlowResult{}
	handled := make(map[*ast.Ident]bool)
	ast.Inspect(scope, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok {
			analyzeRangeCall(call, tracked, info, pkg, depth, stack, handled, &result)
		}
		return true
	})
	return result, handled
}

func analyzeRangeCall(call *ast.CallExpr, tracked map[types.Object]bool, info *types.Info, pkg *signalPackage, depth int, stack map[*types.Func]bool, handled map[*ast.Ident]bool, result *rangeFlowResult) {
	var dependent []int
	for i, arg := range call.Args {
		if rangeExprDepends(arg, tracked, info) {
			dependent = append(dependent, i)
		}
	}
	for _, i := range dependent {
		markRangeUses(call.Args[i], tracked, info, handled)
	}
	if isSubtest(call, info) {
		body, receiverFields, receiverBodies, resolved := resolveRangeSubtestBody(call, tracked, info, pkg)
		if resolved {
			bodyTracked := make(map[types.Object]bool, len(tracked)+len(receiverFields))
			for object := range tracked {
				bodyTracked[object] = true
			}
			for object := range receiverFields {
				bodyTracked[object] = true
			}
			markRangeUses(body, tracked, info, handled)
			nested := analyzeRangeObject(body, bodyTracked, info, pkg, depth+1, stack)
			result.executes = result.executes || nested.executes
			result.unknown = result.unknown || nested.unknown
			for _, receiverBody := range receiverBodies {
				if receiverBody == body {
					continue
				}
				markRangeUses(receiverBody, tracked, info, handled)
				nested = analyzeRangeObject(receiverBody, bodyTracked, info, pkg, depth+1, stack)
				result.executes = result.executes || nested.executes
				result.unknown = result.unknown || nested.unknown
			}
			return
		}
	}
	if len(dependent) == 0 {
		return
	}
	if _, ok := shellExecutionScript(call, info); ok {
		result.executes = true
		return
	}
	if isSubtest(call, info) && rangeSubtestBodyOpaque(call, dependent) {
		result.unknown = true
		return
	}
	if rangeDataCall(call, info) {
		return
	}
	fn := rangeCallFunc(call, info)
	// A package containing only test files can have an empty path; its
	// functions still belong to the package checked with those files.
	if fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == pkg.path {
		analyzeProjectRangeCall(call, dependent, fn, info, pkg, depth, stack, result)
		return
	}
	result.unknown = true
}

// resolveRangeSubtestBody follows only bodies whose source is unambiguous:
// a function literal assigned once in this function, or a method value for a
// method declared in this package. Other function values remain unknown.
func resolveRangeSubtestBody(call *ast.CallExpr, tracked map[types.Object]bool, info *types.Info, pkg *signalPackage) (ast.Node, map[types.Object]bool, []ast.Node, bool) {
	if len(call.Args) < 2 {
		return nil, nil, nil, false
	}
	bodyExpr := ast.Unparen(call.Args[1])
	switch body := bodyExpr.(type) {
	case *ast.FuncLit:
		return body.Body, nil, nil, true
	case *ast.Ident:
		if body.Name == "_" {
			return nil, nil, nil, false
		}
		object := info.Uses[body]
		if object == nil {
			return nil, nil, nil, false
		}
		function, unique := uniqueRangeFuncValue(call, object, info, pkg)
		if !unique || function == nil {
			return nil, nil, nil, false
		}
		return function.Body, nil, nil, true
	case *ast.SelectorExpr:
		selection := info.Selections[body]
		if selection == nil || selection.Kind() != types.MethodVal {
			return nil, nil, nil, false
		}
		method, _ := selection.Obj().(*types.Func)
		if method == nil || method.Pkg() == nil || method.Pkg().Path() != pkg.path {
			return nil, nil, nil, false
		}
		decl := rangeFunctionDecl(method, pkg, info)
		if decl == nil || decl.Body == nil || decl.Recv == nil || len(decl.Recv.List) == 0 || len(decl.Recv.List[0].Names) == 0 {
			return nil, nil, nil, false
		}
		fields := rangeMethodValueFields(body.X, tracked, info, pkg)
		if len(fields) == 0 {
			return nil, nil, nil, false
		}
		receiverBodies, safe := receiverOnlyReadsFields(decl, info, pkg, fields)
		if !safe {
			return nil, nil, nil, false
		}
		return decl.Body, fields, receiverBodies, true
	default:
		return nil, nil, nil, false
	}
}

func uniqueRangeFuncValue(call *ast.CallExpr, object types.Object, info *types.Info, pkg *signalPackage) (*ast.FuncLit, bool) {
	var scope *ast.BlockStmt
	for _, file := range pkg.files {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil || scope != nil {
				return scope == nil
			}
			switch function := n.(type) {
			case *ast.FuncDecl:
				if function.Body != nil && function.Body.Pos() <= call.Pos() && call.End() <= function.Body.End() {
					scope = function.Body
				}
			case *ast.FuncLit:
				if function.Body.Pos() <= call.Pos() && call.End() <= function.Body.End() {
					scope = function.Body
				}
			}
			return scope == nil
		})
	}
	if scope == nil {
		return nil, false
	}
	writes := 0
	var value *ast.FuncLit
	ast.Inspect(scope, func(n ast.Node) bool {
		switch statement := n.(type) {
		case *ast.ValueSpec:
			for i, name := range statement.Names {
				if info.Defs[name] != object {
					continue
				}
				writes++
				if i < len(statement.Values) {
					value, _ = ast.Unparen(statement.Values[i]).(*ast.FuncLit)
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range statement.Lhs {
				id, ok := ast.Unparen(lhs).(*ast.Ident)
				if !ok || info.Uses[id] != object && info.Defs[id] != object {
					continue
				}
				writes++
				value = nil
				if i < len(statement.Rhs) {
					value, _ = ast.Unparen(statement.Rhs[i]).(*ast.FuncLit)
				}
			}
		}
		return true
	})
	return value, writes == 1 && value != nil
}

func rangeMethodValueFields(receiver ast.Expr, tracked map[types.Object]bool, info *types.Info, pkg *signalPackage) map[types.Object]bool {
	var literal *ast.CompositeLit
	switch receiver := ast.Unparen(receiver).(type) {
	case *ast.CompositeLit:
		literal = receiver
	case *ast.Ident:
		object := info.Uses[receiver]
		var found int
		for _, file := range pkg.files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch statement := n.(type) {
				case *ast.ValueSpec:
					for i, name := range statement.Names {
						if info.Defs[name] == object && i < len(statement.Values) {
							found++
							literal, _ = ast.Unparen(statement.Values[i]).(*ast.CompositeLit)
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range statement.Lhs {
						id, ok := ast.Unparen(lhs).(*ast.Ident)
						if ok && (info.Uses[id] == object || info.Defs[id] == object) && i < len(statement.Rhs) {
							found++
							literal, _ = ast.Unparen(statement.Rhs[i]).(*ast.CompositeLit)
						}
					}
				}
				return true
			})
		}
		if found != 1 {
			return nil
		}
	default:
		return nil
	}
	if literal == nil {
		return nil
	}
	fields := make(map[types.Object]bool)
	for _, element := range literal.Elts {
		kv, ok := element.(*ast.KeyValueExpr)
		if !ok || !rangeExprDepends(kv.Value, tracked, info) {
			continue
		}
		key, ok := ast.Unparen(kv.Key).(*ast.Ident)
		if !ok {
			continue
		}
		if field := info.Uses[key]; field != nil {
			fields[field] = true
		}
	}
	return fields
}

func analyzeProjectRangeCall(call *ast.CallExpr, dependent []int, fn *types.Func, info *types.Info, pkg *signalPackage, depth int, stack map[*types.Func]bool, result *rangeFlowResult) {
	if stack[fn] {
		result.unknown = true
		return
	}
	decl := rangeFunctionDecl(fn, pkg, info)
	if decl == nil || decl.Body == nil || decl.Type.Params == nil {
		result.unknown = true
		return
	}
	nextStack := make(map[*types.Func]bool, len(stack)+1)
	for active := range stack {
		nextStack[active] = true
	}
	nextStack[fn] = true
	signature, ok := fn.Type().(*types.Signature)
	if !ok {
		result.unknown = true
		return
	}
	for _, argIndex := range dependent {
		paramIndex, paramList := projectRangeParameter(call, argIndex, decl, info)
		parameter, found := rangeParameterName(paramList, paramIndex, signature.Variadic() && paramList == decl.Type.Params)
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
}

func projectRangeParameter(call *ast.CallExpr, index int, decl *ast.FuncDecl, info *types.Info) (int, *ast.FieldList) {
	paramList := decl.Type.Params
	if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if selection := info.Selections[selector]; selection != nil && selection.Kind() == types.MethodExpr {
			if index == 0 {
				return index, decl.Recv
			}
			index--
		}
	}
	return index, paramList
}

// rangeSubtestBodyOpaque reports a subtest body that depends on the table
// string and comes as a value: a method value bound to the string or a name
// for a function hides what the body does with it. A function literal is read
// on the spot, and a call that builds the body is followed as a call of its
// own, so neither is opaque.
func rangeSubtestBodyOpaque(call *ast.CallExpr, dependent []int) bool {
	for _, i := range dependent {
		if i == 0 {
			continue
		}
		switch ast.Unparen(call.Args[i]).(type) {
		case *ast.FuncLit, *ast.CallExpr:
		default:
			return true
		}
	}
	return false
}

func markUnknownRangeUses(scope ast.Node, tracked map[types.Object]bool, propagated map[*ast.Ident]bool, handled map[*ast.Ident]bool, info *types.Info, result *rangeFlowResult) {
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
	name, ok := shellCommandName(call, info)
	if !ok {
		return nil, false
	}
	start := 0
	if name == "CommandContext" {
		start = 1
	}
	if len(call.Args) <= start {
		return nil, false
	}
	if _, ok := helpers.StringLiteral(call.Args[start]); !ok {
		return nil, false
	}
	for index := start; index < len(call.Args); {
		command, ok := helpers.StringLiteral(call.Args[index])
		if !ok {
			return nil, false
		}
		switch filepath.Base(command) {
		case "sh", "bash":
			return shellFlagScript(call.Args, index+1)
		case "env":
			index, ok = envCommandIndex(call.Args, index+1)
		case "sudo":
			index, ok = sudoCommandIndex(call.Args, index+1)
		case "nohup":
			index++
			ok = true
		default:
			return nil, false
		}
		if !ok {
			return nil, false
		}
	}
	return nil, false
}

func shellCommandName(call *ast.CallExpr, info *types.Info) (string, bool) {
	selector, isSelector := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isSelector || selector.Sel.Name != "Command" && selector.Sel.Name != "CommandContext" {
		return "", false
	}
	name := selector.Sel.Name
	if info == nil {
		return name, true
	}
	if info != nil {
		fn := rangeCallFunc(call, info)
		if fn != nil {
			if fn.Pkg() == nil || fn.Pkg().Path() != "os/exec" || fn.Name() != name {
				return "", false
			}
			return name, true
		}
		id, ok := ast.Unparen(selector.X).(*ast.Ident)
		if !ok {
			return "", false
		}
		if object := info.Uses[id]; object != nil {
			pkgName, ok := object.(*types.PkgName)
			if !ok || pkgName.Imported() == nil || pkgName.Imported().Path() != "os/exec" {
				return "", false
			}
		} else if id.Name != "exec" {
			return "", false
		}
	}
	return name, true
}

func shellFlagScript(args []ast.Expr, flagIndex int) (ast.Expr, bool) {
	if len(args) <= flagIndex+1 {
		return nil, false
	}
	flag, ok := helpers.StringLiteral(args[flagIndex])
	if !ok || len(flag) < 2 || flag[0] != '-' || strings.HasPrefix(flag, "--") || !strings.Contains(flag[1:], "c") {
		return nil, false
	}
	for _, char := range flag[1:] {
		if char < 'a' || char > 'z' {
			return nil, false
		}
	}
	return args[flagIndex+1], true
}

func envCommandIndex(args []ast.Expr, start int) (int, bool) {
	for i := start; i < len(args); i++ {
		word, literal := helpers.StringLiteral(args[i])
		if !literal {
			return 0, false
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
		return i, true
	}
	return 0, false
}

func sudoCommandIndex(args []ast.Expr, start int) (int, bool) {
	for i := start; i < len(args); i++ {
		word, literal := helpers.StringLiteral(args[i])
		if !literal {
			return 0, false
		}
		if word == "--" {
			if i+1 < len(args) {
				return i + 1, true
			}
			return 0, false
		}
		if strings.HasPrefix(word, "-") {
			switch word {
			case "-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T":
				i++
			}
			continue
		}
		return i, true
	}
	return 0, false
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
	if isRangeTestLog(call, info) {
		return true
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if builtin, ok := info.Uses[id].(*types.Builtin); ok && builtin.Name() == "len" {
			if len(call.Args) == 1 {
				_, direct := ast.Unparen(call.Args[0]).(*ast.Ident)
				return direct
			}
		}
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

// Test imports can be incomplete when the project has no compiled Go files.
// As with isSubtest, use the receiver name only when its type is unavailable.
func isRangeTestLog(call *ast.CallExpr, info *types.Info) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Log" && selector.Sel.Name != "Logf" {
		return false
	}
	receiver := info.TypeOf(selector.X)
	if pointer, ok := receiver.(*types.Pointer); ok && pointer.Elem() == types.Typ[types.Invalid] {
		receiver = nil
	}
	if receiver != nil && receiver != types.Typ[types.Invalid] {
		return testingReceiver(receiver)
	}
	id, ok := ast.Unparen(selector.X).(*ast.Ident)
	return ok && (id.Name == "t" || id.Name == "b")
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

// receiverOnlyReadsFields reports whether a method and methods it directly
// calls on the same receiver type use that receiver only to read fields. It
// also returns their bodies so the range analysis can inspect each one.
func receiverOnlyReadsFields(decl *ast.FuncDecl, info *types.Info, pkg *signalPackage, fields map[types.Object]bool) ([]ast.Node, bool) {
	var bodies []ast.Node
	ok := receiverMethodOnlyReadsFields(decl, info, pkg, fields, make(map[*types.Func]bool), &bodies)
	return bodies, ok
}

func receiverMethodOnlyReadsFields(decl *ast.FuncDecl, info *types.Info, pkg *signalPackage, fields map[types.Object]bool, visited map[*types.Func]bool, bodies *[]ast.Node) bool {
	if decl == nil || decl.Body == nil || decl.Recv == nil || len(decl.Recv.List) == 0 || len(decl.Recv.List[0].Names) == 0 {
		return false
	}
	fn, _ := info.Defs[decl.Name].(*types.Func)
	if fn == nil || visited[fn] {
		return fn != nil
	}
	visited[fn] = true
	*bodies = append(*bodies, decl.Body)
	receiver := info.Defs[decl.Recv.List[0].Names[0]]
	receiverType := info.TypeOf(decl.Recv.List[0].Type)
	if receiver == nil || receiverType == nil {
		return false
	}

	called := make(map[*ast.SelectorExpr]bool)
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
			called[selector] = true
		}
		return true
	})

	only := true
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if !only {
			return false
		}
		switch n := n.(type) {
		case *ast.SelectorExpr:
			var handled bool
			only, handled = receiverSelectorOnlyReadsFields(n, receiver, receiverType, called[n], info, pkg, fields, visited, bodies)
			return !handled
		case *ast.Ident:
			if info.Uses[n] == receiver {
				only = false
			}
		}
		return only
	})
	return only
}

func receiverSelectorOnlyReadsFields(selector *ast.SelectorExpr, receiver types.Object, receiverType types.Type, called bool, info *types.Info, pkg *signalPackage, fields map[types.Object]bool, visited map[*types.Func]bool, bodies *[]ast.Node) (bool, bool) {
	id, ok := ast.Unparen(selector.X).(*ast.Ident)
	if !ok || info.Uses[id] != receiver {
		return true, false
	}
	selection := info.Selections[selector]
	if selection == nil {
		return false, true
	}
	if selection.Kind() == types.FieldVal {
		return true, true
	}
	method, ok := selection.Obj().(*types.Func)
	if !ok || selection.Kind() != types.MethodVal || !called || method.Pkg() == nil || method.Pkg().Path() != pkg.path {
		return false, true
	}
	signature, ok := method.Type().(*types.Signature)
	if !ok || signature.Recv() == nil || !types.Identical(signature.Recv().Type(), receiverType) {
		return false, true
	}
	callee := rangeFunctionDecl(method, pkg, info)
	return callee != nil && receiverMethodOnlyReadsFields(callee, info, pkg, fields, visited, bodies), true
}
