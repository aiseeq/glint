package shellrules

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

type rangeFlowResult struct {
	executes bool
	unknown  bool
}

// rangeTracked is what holds the table string while a body is read. In a
// method body the string reaches the command only through a field of that
// method's receiver set from the string, so a selector of a field lying in
// the receiver's value is looked up in fields, the receiver's own, and
// nowhere else; any other name — a variable, a field of another value, a
// field reached through a pointer, which every copy shares — is looked up
// in objects.
type rangeTracked struct {
	objects  map[types.Object]bool
	receiver types.Object
	fields   map[types.Object]bool
	// own holds the names of the selectors of the method body that select a
	// field lying in receiver's value; the function literals in the body
	// read it too.
	own map[*ast.Ident]bool
}

func newRangeTracked(objects map[types.Object]bool) *rangeTracked {
	return &rangeTracked{objects: objects}
}

func newReceiverTracked(objects map[types.Object]bool, method rangeSubtestBody, fields map[types.Object]bool, info *types.Info) *rangeTracked {
	return &rangeTracked{objects: objects, receiver: method.receiver, fields: fields, own: receiverFieldSelectors(method.body, method.receiver, info)}
}

func (t *rangeTracked) has(id *ast.Ident, info *types.Info) bool {
	object := info.Uses[id]
	if t.own[id] {
		return t.fields[object]
	}
	return t.objects[object]
}

// add records that the assignment target named by id holds the string and
// reports whether that is new.
func (t *rangeTracked) add(id *ast.Ident, object types.Object) bool {
	set := t.objects
	if t.own[id] {
		set = t.fields
	}
	if set[object] {
		return false
	}
	set[object] = true
	return true
}

// receiverFieldSelectors returns the names of the selectors in scope that
// select a field lying in the receiver's value itself (k.f, k.in.f). A
// field reached through a pointer — a pointer field, an embedded *T — is
// shared with every copy of the receiver, so its selector is left to
// objects like any other value's.
func receiverFieldSelectors(scope ast.Node, receiver types.Object, info *types.Info) map[*ast.Ident]bool {
	own := make(map[*ast.Ident]bool)
	ast.Inspect(scope, func(n ast.Node) bool {
		if selector, ok := n.(*ast.SelectorExpr); ok && receiverValueField(selector, receiver, info) {
			own[selector.Sel] = true
		}
		return true
	})
	return own
}

// receiverValueField reports whether a chain of selectors starts from
// receiver and dereferences no pointer on the way past the receiver itself.
func receiverValueField(selector *ast.SelectorExpr, receiver types.Object, info *types.Info) bool {
	for {
		selection := info.Selections[selector]
		if selection == nil {
			return false
		}
		base := ast.Unparen(selector.X)
		id, ok := base.(*ast.Ident)
		atReceiver := ok && info.Uses[id] == receiver
		if throughPointer(selection, !atReceiver) {
			return false
		}
		if atReceiver {
			return true
		}
		inner, ok := base.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		selector = inner
	}
}

// throughPointer reports whether reaching what selection selects
// dereferences a pointer: the value it is selected from, when that counts,
// or an embedded *T on the way.
func throughPointer(selection *types.Selection, countBase bool) bool {
	from := selection.Recv()
	if pointer, ok := from.Underlying().(*types.Pointer); ok {
		if countBase {
			return true
		}
		from = pointer.Elem()
	}
	_, _, indirect := types.LookupFieldOrMethod(from, true, selection.Obj().Pkg(), selection.Obj().Name())
	return indirect
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
		flow := analyzeRangeObject(scope, newRangeTracked(map[types.Object]bool{object: true}), info, pkg, 0, make(map[*types.Func]bool))
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

func analyzeRangeObject(scope ast.Node, tracked *rangeTracked, info *types.Info, pkg *signalPackage, depth int, stack map[*types.Func]bool) rangeFlowResult {
	if depth >= 8 {
		return rangeFlowResult{unknown: true}
	}
	propagated := propagateRangeObjects(scope, tracked, info)
	result, handled := analyzeRangeCalls(scope, tracked, info, pkg, depth, stack)
	markUnknownRangeUses(scope, tracked, propagated, handled, info, &result)
	return result
}

func propagateRangeObjects(scope ast.Node, tracked *rangeTracked, info *types.Info) map[*ast.Ident]bool {
	propagated := make(map[*ast.Ident]bool)
	markSource := func(rhs ast.Expr) {
		ast.Inspect(rhs, func(child ast.Node) bool {
			if use, ok := child.(*ast.Ident); ok && tracked.has(use, info) {
				propagated[use] = true
			}
			return true
		})
	}
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
						var target *ast.Ident
						switch lhs := ast.Unparen(lhs).(type) {
						case *ast.Ident:
							if lhs.Name != "_" {
								target = lhs
							}
						case *ast.SelectorExpr:
							target = lhs.Sel
							propagated[lhs.Sel] = true
						}
						if target == nil {
							continue
						}
						obj := info.ObjectOf(target)
						if obj == nil {
							continue
						}
						if tracked.add(target, obj) {
							changed = true
						}
						markSource(rhs)
					}
				}
			case *ast.ValueSpec:
				for _, rhs := range n.Values {
					if !rangeExprDepends(rhs, tracked, info) {
						continue
					}
					for _, lhs := range n.Names {
						obj := info.ObjectOf(lhs)
						if obj == nil {
							continue
						}
						if tracked.add(lhs, obj) {
							changed = true
						}
						markSource(rhs)
					}
				}
			}
			return true
		})
	}
	return propagated
}

func analyzeRangeCalls(scope ast.Node, tracked *rangeTracked, info *types.Info, pkg *signalPackage, depth int, stack map[*types.Func]bool) (rangeFlowResult, map[*ast.Ident]bool) {
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

func analyzeRangeCall(call *ast.CallExpr, tracked *rangeTracked, info *types.Info, pkg *signalPackage, depth int, stack map[*types.Func]bool, handled map[*ast.Ident]bool, result *rangeFlowResult) {
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
		bodies, fields, resolved := resolveRangeSubtestBody(call, tracked, info, pkg)
		if resolved {
			analyzeRangeSubtestBodies(bodies, fields, tracked, info, pkg, depth, stack, handled, result)
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

// rangeSubtestBody is a body a subtest runs: a function literal, the method
// a method value names or a method that one calls on its receiver.
type rangeSubtestBody struct {
	body ast.Node
	// receiver is nil for a function literal.
	receiver types.Object
	// pointer tells that the method shares its receiver with its caller; a
	// value receiver is a copy of the caller's.
	pointer bool
	// caller is the index of the body that calls the method, -1 for the
	// subtest body itself.
	caller int
}

// resolveRangeSubtestBody follows only bodies whose source is unambiguous:
// a function literal assigned once in this function, or a method value for a
// method declared in this package, with the methods it calls on its
// receiver. For a method value it also returns the fields of the receiver
// that hold the table string; for a function literal they are nil.
func resolveRangeSubtestBody(call *ast.CallExpr, tracked *rangeTracked, info *types.Info, pkg *signalPackage) ([]rangeSubtestBody, map[types.Object]bool, bool) {
	if len(call.Args) < 2 {
		return nil, nil, false
	}
	bodyExpr := ast.Unparen(call.Args[1])
	switch body := bodyExpr.(type) {
	case *ast.FuncLit:
		return []rangeSubtestBody{{body: body.Body, caller: -1}}, nil, true
	case *ast.Ident:
		if body.Name == "_" {
			return nil, nil, false
		}
		object := info.Uses[body]
		if object == nil {
			return nil, nil, false
		}
		function, unique := uniqueRangeFuncValue(call, object, info, pkg)
		if !unique || function == nil {
			return nil, nil, false
		}
		return []rangeSubtestBody{{body: function.Body, caller: -1}}, nil, true
	case *ast.SelectorExpr:
		selection := info.Selections[body]
		if selection == nil || selection.Kind() != types.MethodVal {
			return nil, nil, false
		}
		method, _ := selection.Obj().(*types.Func)
		if method == nil || method.Pkg() == nil || method.Pkg().Path() != pkg.path {
			return nil, nil, false
		}
		decl := rangeFunctionDecl(method, pkg, info)
		if decl == nil {
			return nil, nil, false
		}
		fields := rangeMethodValueFields(body.X, tracked, info, pkg)
		if len(fields) == 0 {
			return nil, nil, false
		}
		bodies, safe := receiverOnlyReadsFields(decl, info, pkg, fields)
		if !safe {
			return nil, nil, false
		}
		return bodies, fields, true
	default:
		return nil, nil, false
	}
}

// analyzeRangeSubtestBodies reads the bodies a subtest runs. A function
// literal sees the variables and the receiver fields of the body it is
// written in. A method sees the fields of its own receiver: the subtest's
// method those the method value was made with, a method it calls on a pointer
// receiver the very fields of its caller, and one on a value receiver a copy
// of them, so what a method sets in its copy stays out of its caller and of
// the caller's other calls. What lies behind a pointer is not copied; it is
// looked up in objects, which all the bodies share.
func analyzeRangeSubtestBodies(bodies []rangeSubtestBody, fields map[types.Object]bool, tracked *rangeTracked, info *types.Info, pkg *signalPackage, depth int, stack map[*types.Func]bool, handled map[*ast.Ident]bool, result *rangeFlowResult) {
	objects := maps.Clone(tracked.objects)
	states := make([]*rangeTracked, len(bodies))
	for i, sub := range bodies {
		switch {
		case fields == nil:
			// A function literal reads the receiver of the body it is
			// written in.
			copied := *tracked
			copied.objects = objects
			states[i] = &copied
		case sub.caller < 0:
			// A field of whichever value the caller set from the string
			// may be one of the receiver's.
			held := maps.Clone(fields)
			maps.Copy(held, objects)
			states[i] = newReceiverTracked(objects, sub, held, info)
		case sub.pointer:
			states[i] = newReceiverTracked(objects, sub, states[sub.caller].fields, info)
		default:
			states[i] = newReceiverTracked(objects, sub, maps.Clone(states[sub.caller].fields), info)
		}
		markRangeUses(sub.body, tracked, info, handled)
		nested := analyzeRangeObject(sub.body, states[i], info, pkg, depth+1, stack)
		result.executes = result.executes || nested.executes
		result.unknown = result.unknown || nested.unknown
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

func rangeMethodValueFields(receiver ast.Expr, tracked *rangeTracked, info *types.Info, pkg *signalPackage) map[types.Object]bool {
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
		nested := analyzeRangeObject(decl.Body, newRangeTracked(map[types.Object]bool{param: true}), info, pkg, depth+1, nextStack)
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

func markUnknownRangeUses(scope ast.Node, tracked *rangeTracked, propagated map[*ast.Ident]bool, handled map[*ast.Ident]bool, info *types.Info, result *rangeFlowResult) {
	ast.Inspect(scope, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || !tracked.has(id, info) || propagated[id] || handled[id] {
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

func rangeExprDepends(expr ast.Node, tracked *rangeTracked, info *types.Info) bool {
	return anyIdent(expr, func(id *ast.Ident) bool { return tracked.has(id, info) })
}

// anyIdent reports whether an identifier under node matches.
func anyIdent(node ast.Node, match func(*ast.Ident) bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && match(id) {
			found = true
		}
		return !found
	})
	return found
}

func markRangeUses(expr ast.Node, tracked *rangeTracked, info *types.Info, handled map[*ast.Ident]bool) {
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && tracked.has(id, info) {
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

func rangeIdentInEquality(id *ast.Ident, scope ast.Node, tracked *rangeTracked, info *types.Info) bool {
	found := false
	ast.Inspect(scope, func(n ast.Node) bool {
		binary, ok := n.(*ast.BinaryExpr)
		if !ok || binary.Op != token.EQL && binary.Op != token.NEQ {
			return true
		}
		ast.Inspect(binary, func(child ast.Node) bool {
			if child == id && tracked.has(id, info) {
				found = true
			}
			return !found
		})
		return !found
	})
	return found
}

// receiverOnlyReadsFields reports whether a method and methods it directly
// calls on the same receiver type use that receiver only to read and set
// fields. It also returns their bodies, each with its caller, so the range
// analysis can inspect each one.
func receiverOnlyReadsFields(decl *ast.FuncDecl, info *types.Info, pkg *signalPackage, fields map[types.Object]bool) ([]rangeSubtestBody, bool) {
	var bodies []rangeSubtestBody
	ok := receiverMethodOnlyReadsFields(decl, -1, info, pkg, fields, make(map[*types.Func]bool), &bodies)
	return bodies, ok
}

func receiverMethodOnlyReadsFields(decl *ast.FuncDecl, caller int, info *types.Info, pkg *signalPackage, fields map[types.Object]bool, visited map[*types.Func]bool, bodies *[]rangeSubtestBody) bool {
	if decl == nil || decl.Body == nil || decl.Recv == nil || len(decl.Recv.List) == 0 {
		return false
	}
	fn, _ := info.Defs[decl.Name].(*types.Func)
	if fn == nil || visited[fn] {
		return fn != nil
	}
	visited[fn] = true
	receiverType := info.TypeOf(decl.Recv.List[0].Type)
	if receiverType == nil {
		return false
	}
	names := decl.Recv.List[0].Names
	if len(names) == 0 {
		// A receiver without a name is read nowhere in the body, so no field
		// of it reaches the method.
		return true
	}
	receiver := info.Defs[names[0]]
	if receiver == nil {
		return false
	}
	_, pointer := receiverType.(*types.Pointer)
	self := len(*bodies)
	*bodies = append(*bodies, rangeSubtestBody{body: decl.Body, receiver: receiver, pointer: pointer, caller: caller})

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
			only, handled = receiverSelectorOnlyReadsFields(n, receiver, receiverType, called[n], self, info, pkg, fields, visited, bodies)
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

func receiverSelectorOnlyReadsFields(selector *ast.SelectorExpr, receiver types.Object, receiverType types.Type, called bool, caller int, info *types.Info, pkg *signalPackage, fields map[types.Object]bool, visited map[*types.Func]bool, bodies *[]rangeSubtestBody) (bool, bool) {
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
	return callee != nil && receiverMethodOnlyReadsFields(callee, caller, info, pkg, fields, visited, bodies), true
}
