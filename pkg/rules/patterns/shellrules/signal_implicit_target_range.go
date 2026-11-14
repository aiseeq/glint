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
	// limited: the depth limit cut the analysis somewhere.
	limited bool
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

func rangeStringLiterals(file *ast.File, fset *token.FileSet, info *types.Info, pkg *signalPackage) (data, executed map[*ast.BasicLit]bool) {
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
		elements, object := rangeStringTable(loop, info)
		if object == nil {
			return true
		}
		flow := analyzeRangeObject(rangeEnclosingScope(file, loop), object, info, pkg, fset)
		for _, element := range elements {
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

// rangeStringTable is the elements of the []string literal a range statement
// walks and the variable that takes its values, or nil.
func rangeStringTable(loop *ast.RangeStmt, info *types.Info) ([]ast.Expr, types.Object) {
	values, ok := ast.Unparen(loop.X).(*ast.CompositeLit)
	if !ok || values.Incomplete {
		return nil, nil
	}
	array, ok := ast.Unparen(values.Type).(*ast.ArrayType)
	if !ok {
		return nil, nil
	}
	elementType, ok := ast.Unparen(array.Elt).(*ast.Ident)
	if !ok || elementType.Name != "string" {
		return nil, nil
	}
	value, ok := ast.Unparen(loop.Value).(*ast.Ident)
	if !ok || value.Name == "_" {
		return nil, nil
	}
	return values.Elts, info.ObjectOf(value)
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
	command, ok := helpers.StringLiteral(call.Args[start])
	if !ok {
		return nil, false
	}
	command = filepath.Base(command)
	if command == "sh" || command == "bash" {
		return shellFlagScript(call.Args, start+1)
	}
	if command == "env" {
		return envShellScript(call.Args, start+1)
	}
	return nil, false
}

func shellCommandName(call *ast.CallExpr, info *types.Info) (string, bool) {
	name := ""
	if info == nil {
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Command" && selector.Sel.Name != "CommandContext" {
			return "", false
		}
		name = selector.Sel.Name
	} else {
		fn := rangeCallFunc(call, info)
		if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "os/exec" || fn.Name() != "Command" && fn.Name() != "CommandContext" {
			return "", false
		}
		name = fn.Name()
	}
	if name != "Command" && name != "CommandContext" {
		return "", false
	}
	return name, true
}

func shellFlagScript(args []ast.Expr, flagIndex int) (ast.Expr, bool) {
	if len(args) <= flagIndex+1 {
		return nil, false
	}
	flag, ok := helpers.StringLiteral(args[flagIndex])
	if !ok || flag != "-c" {
		return nil, false
	}
	return args[flagIndex+1], true
}

func envShellScript(args []ast.Expr, start int) (ast.Expr, bool) {
	for i := start; i < len(args); i++ {
		word, literal := helpers.StringLiteral(args[i])
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
		return shellFlagScript(args, i+1)
	}
	return nil, false
}

func rangeCallFunc(call *ast.CallExpr, info *types.Info) *types.Func {
	if info == nil {
		return nil
	}
	fun := ast.Unparen(call.Fun)
	switch generic := fun.(type) {
	case *ast.IndexExpr:
		fun = generic.X
	case *ast.IndexListExpr:
		fun = generic.X
	}
	var object types.Object
	switch fun := fun.(type) {
	case *ast.Ident:
		object = info.Uses[fun]
	case *ast.SelectorExpr:
		object = info.Uses[fun.Sel]
	}
	fn, _ := object.(*types.Func)
	return fn
}

// rangeDataCall reports a call that reads its arguments as text and returns
// what it computes, without running anything: the analysis follows the
// result through the expression it stands in.
func rangeDataCall(call *ast.CallExpr, info *types.Info) bool {
	if isSubtest(call, info) {
		return true
	}
	fn := rangeCallFunc(call, info)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && testingReceiver(info.TypeOf(selector.X)) {
		for _, prefix := range []string{"Log", "Error", "Fatal", "Skip"} {
			if strings.HasPrefix(fn.Name(), prefix) {
				return true
			}
		}
	}
	name, path := fn.Name(), fn.Pkg().Path()
	if path == "fmt" && strings.HasPrefix(name, "Fprint") {
		return len(call.Args) > 0 && rangeMemoryWriter(info.TypeOf(call.Args[0]))
	}
	return rangeDataFunc(fn)
}

// rangeTextPackages compute on text and values in memory; none of them starts
// a process or writes anywhere but to its own result.
var rangeTextPackages = map[string]bool{
	"strings": true, "bytes": true, "regexp": true, "regexp/syntax": true,
	"strconv": true, "unicode": true, "unicode/utf8": true, "unicode/utf16": true,
	"slices": true, "maps": true, "sort": true, "cmp": true, "errors": true,
	"path": true, "path/filepath": true,
}

// rangeDataFunc reports a function or method that only computes on its
// arguments. Writers to an io.Writer (WriteTo, fmt.Fprint) are not: the
// writer may be the stdin of a shell.
func rangeDataFunc(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	name, path := fn.Name(), fn.Pkg().Path()
	switch {
	case rangeTextPackages[path]:
		return name != "WriteTo" && name != "Walk" && name != "WalkDir"
	case path == "fmt":
		return strings.HasPrefix(name, "Sprint") || strings.HasPrefix(name, "Errorf") || strings.HasPrefix(name, "Append")
	case path == "log" || path == "log/slog":
		return hasRangeLoggerPrefix(name)
	}
	return false
}

// rangeMemoryWriter is a writer that keeps what is written in memory.
func rangeMemoryWriter(t types.Type) bool {
	if pointer, ok := t.(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	path, name := named.Obj().Pkg().Path(), named.Obj().Name()
	return path == "strings" && name == "Builder" || path == "bytes" && name == "Buffer"
}

func hasRangeLoggerPrefix(name string) bool {
	for _, prefix := range loggerPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
