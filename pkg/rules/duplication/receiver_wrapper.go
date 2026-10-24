package duplication

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewReceiverWrapperDuplicatesCallRule())
}

// ReceiverWrapperDuplicatesCallRule detects a method that only passes a
// field of its receiver to a function of the package, while the package also
// calls that function with the same field directly:
//
//	func (l *Line) arenaNamedPart(name string) *Part { return partNamed(l.Parts, name) }
//
//	func defense(l *Line) *Part { return partNamed(l.Parts, "defense") }
//
// The method adds nothing — its arguments are its parameters and the field —
// so the lookup has two spellings, and a check added to one of them is missing
// from the other. An exported method is the API other packages call, and a
// wrapper that is the only way the package takes the field to the function
// is a choice of spelling: both are left alone, and so are test files.
type ReceiverWrapperDuplicatesCallRule struct {
	*rules.BaseRule
}

// NewReceiverWrapperDuplicatesCallRule creates the rule
func NewReceiverWrapperDuplicatesCallRule() *ReceiverWrapperDuplicatesCallRule {
	return &ReceiverWrapperDuplicatesCallRule{BaseRule: rules.NewBaseRule(
		"receiver-wrapper-duplicates-call",
		"duplication",
		"Detects a method that only passes a field of its receiver to a function of the package while the package calls that function with the same field directly — two ways of one action",
		core.SeverityLow,
	)}
}

// AnalyzeFile is a no-op: the direct call may live in another file.
func (r *ReceiverWrapperDuplicatesCallRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ReceiverWrapperDuplicatesCallRule) RequiresSSA() bool { return false }

// receiverWrapper is a method whose body is one call of a package function
// with its parameters and fields of its receiver.
type receiverWrapper struct {
	file   *core.FileContext
	decl   *ast.FuncDecl
	callee *types.Func
	recv   *types.Named
	// fields maps an argument position to the field path the method passes
	// there ("Parts", "cfg.Limits").
	fields map[int]string
}

// AnalyzeGoProject reports wrappers package by package.
func (r *ReceiverWrapperDuplicatesCallRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("receiver wrapper duplicates call: nil Go project context")
	}
	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("receiver wrapper duplicates call: package has no typed syntax")
		}
		info := pkg.Package.TypesInfo
		var files []*core.FileContext
		var wrappers []receiverWrapper
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() || file.IsGenerated() {
				continue
			}
			files = append(files, file)
			for _, decl := range file.GoAST.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok {
					if w, ok := wrapperOf(fd, info); ok {
						w.file = file
						wrappers = append(wrappers, w)
					}
				}
			}
		}
		for _, w := range wrappers {
			direct := directCall(w, files, info)
			if direct == "" {
				continue
			}
			line := w.file.LineFor(w.decl.Name)
			if w.file.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(w.file.RelPath, line, fmt.Sprintf(
				"Method %s only passes %s to %s, which %s calls with that field directly — two ways of one action: a check added to one is missing from the other",
				w.decl.Name.Name, fieldList(w), w.callee.Name(), direct))
			v.WithCode(strings.TrimSpace(w.file.GetLine(line)))
			v.WithSuggestion(fmt.Sprintf("Keep one way: call %s at %s, or drop the method and call %s", w.decl.Name.Name, direct, w.callee.Name()))
			violations = append(violations, v)
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

// wrapperOf recognises a method whose one statement calls a function of its
// own package with arguments that are its parameters, each once, and fields
// of its receiver — at least one.
func wrapperOf(fd *ast.FuncDecl, info *types.Info) (receiverWrapper, bool) {
	if fd.Recv == nil || ast.IsExported(fd.Name.Name) || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 || fd.Body == nil || len(fd.Body.List) != 1 {
		return receiverWrapper{}, false
	}
	call := singleCall(fd.Body.List[0])
	if call == nil {
		return receiverWrapper{}, false
	}
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return receiverWrapper{}, false
	}
	callee, ok := info.Uses[id].(*types.Func)
	method, _ := info.Defs[fd.Name].(*types.Func)
	if !ok || method == nil || callee.Pkg() != method.Pkg() || callee.Signature().Recv() != nil {
		return receiverWrapper{}, false
	}
	recvObj := info.Defs[fd.Recv.List[0].Names[0]]
	recv := namedOf(recvObj.Type())
	if recv == nil {
		return receiverWrapper{}, false
	}
	params := make(map[types.Object]bool)
	for _, field := range fd.Type.Params.List {
		for _, name := range field.Names {
			params[info.Defs[name]] = true
		}
	}
	used := make(map[types.Object]bool)
	fields := make(map[int]string)
	for i, arg := range call.Args {
		if pid, ok := arg.(*ast.Ident); ok && params[info.Uses[pid]] && !used[info.Uses[pid]] {
			used[info.Uses[pid]] = true
			continue
		}
		root, path := fieldPath(arg, info)
		if root == nil || path == "" || info.Uses[root] != recvObj {
			return receiverWrapper{}, false
		}
		fields[i] = path
	}
	if len(fields) == 0 {
		return receiverWrapper{}, false
	}
	return receiverWrapper{decl: fd, callee: callee, recv: recv, fields: fields}, true
}

// singleCall returns the call a statement returns or makes, if that is all
// it does.
func singleCall(stmt ast.Stmt) *ast.CallExpr {
	var expr ast.Expr
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		if len(s.Results) == 1 {
			expr = s.Results[0]
		}
	case *ast.ExprStmt:
		expr = s.X
	}
	call, _ := ast.Unparen(expr).(*ast.CallExpr)
	return call
}

// fieldPath splits x.A.B, a chain of field selections, into the identifier x
// and the path "A.B"; a method value is not a field.
func fieldPath(expr ast.Expr, info *types.Info) (*ast.Ident, string) {
	var names []string
	for {
		switch e := ast.Unparen(expr).(type) {
		case *ast.SelectorExpr:
			if sel, ok := info.Selections[e]; !ok || sel.Kind() != types.FieldVal {
				return nil, ""
			}
			names = append([]string{e.Sel.Name}, names...)
			expr = e.X
		case *ast.Ident:
			return e, strings.Join(names, ".")
		default:
			return nil, ""
		}
	}
}

// directCall returns where the package, outside the wrapper, calls the
// function with the same field of a value of the receiver type at a position
// the wrapper fills with it.
func directCall(w receiverWrapper, files []*core.FileContext, info *types.Info) string {
	found := ""
	for _, file := range files {
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			if found != "" || n == w.decl {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := ast.Unparen(call.Fun).(*ast.Ident)
			if !ok || info.Uses[id] != w.callee {
				return true
			}
			for i, path := range w.fields {
				if i < len(call.Args) && sameField(call.Args[i], path, w.recv, info) {
					found = fmt.Sprintf("%s:%d", file.RelPath, file.LineFor(call))
					return false
				}
			}
			return true
		})
		if found != "" {
			return found
		}
	}
	return ""
}

// sameField reports an argument that selects the path from a value of the
// named type.
func sameField(arg ast.Expr, path string, recv *types.Named, info *types.Info) bool {
	expr := ast.Unparen(arg)
	names := strings.Split(path, ".")
	for i := len(names) - 1; i >= 0; i-- {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != names[i] {
			return false
		}
		expr = ast.Unparen(sel.X)
	}
	return namedOf(info.TypeOf(expr)) == recv
}

// namedOf returns the named type of T or *T.
func namedOf(t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, _ := types.Unalias(t).(*types.Named)
	return named
}

// fieldList names the fields the wrapper passes, in argument order.
func fieldList(w receiverWrapper) string {
	positions := make([]int, 0, len(w.fields))
	for i := range w.fields {
		positions = append(positions, i)
	}
	sort.Ints(positions)
	recv := w.decl.Recv.List[0].Names[0].Name
	names := make([]string, 0, len(positions))
	for _, i := range positions {
		names = append(names, recv+"."+w.fields[i])
	}
	return strings.Join(names, ", ")
}
