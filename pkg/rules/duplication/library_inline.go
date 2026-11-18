package duplication

import (
	"cmp"
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

type inlineFunction struct {
	libraryFunction
	Fields []string `json:"fields"`
	// Shape is the method's form: shapeCond when the result is chosen under a
	// condition, shapeOp plus an operator for arithmetic on the way to it.
	// Comparisons are left out: a copy may turn the condition around.
	Shape  []string `json:"shape,omitempty"`
	Method bool     `json:"method,omitempty"`
}

type inlinePlace struct {
	root types.Object
	path string
}
type inlineFlow map[inlinePlace]map[string]bool

const (
	shapeCond = "#cond"
	shapeOp   = "#op:"
)

func inlineArithmetic(op token.Token) bool {
	switch op {
	case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.AND, token.OR, token.XOR, token.SHL, token.SHR, token.AND_NOT:
		return true
	}
	return false
}

func inlineShape(keys map[string]bool) []string {
	var out []string
	for k := range keys {
		if strings.HasPrefix(k, "#") {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// inlineField identifies the declared field through its named receiver type.
// Package loads have distinct types.Objects, so the serialized key is resolved
// from the actual selection on each side rather than from selector spelling.
func inlineField(info *types.Info, sel *ast.SelectorExpr) string {
	s := info.Selections[sel]
	if s == nil || s.Kind() != types.FieldVal {
		return ""
	}
	t := types.Unalias(s.Recv())
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return ""
	}
	st, ok := n.Underlying().(*types.Struct)
	if !ok {
		return ""
	}
	for field := range st.Fields() {
		if field == s.Obj() {
			return n.Obj().Pkg().Path() + "." + n.Obj().Name() + "." + field.Name()
		}
	}
	return ""
}

func inlineLocation(info *types.Info, e ast.Expr) (inlinePlace, bool) {
	switch x := e.(type) {
	case *ast.Ident:
		obj := info.ObjectOf(x)
		v, ok := obj.(*types.Var)
		if !ok || v.IsField() {
			return inlinePlace{}, false
		}
		return inlinePlace{root: obj}, true
	case *ast.SelectorExpr:
		p, ok := inlineLocation(info, x.X)
		if !ok {
			return inlinePlace{}, false
		}
		s := info.Selections[x]
		if s == nil || s.Kind() != types.FieldVal {
			return inlinePlace{}, false
		}
		p.path += "/" + inlineField(info, x)
		return p, true
	case *ast.ParenExpr:
		return inlineLocation(info, x.X)
	}
	return inlinePlace{}, false
}

func inlineSources(info *types.Info, e ast.Expr, flow inlineFlow) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BinaryExpr:
			if inlineArithmetic(x.Op) {
				out[shapeOp+x.Op.String()] = true
			}
		case *ast.SelectorExpr:
			if key := inlineField(info, x); key != "" {
				out[key] = true
			}
			if p, ok := inlineLocation(info, x); ok {
				for k := range flow[p] {
					out[k] = true
				}
			}
		case *ast.Ident:
			if p, ok := inlineLocation(info, x); ok {
				for k := range flow[p] {
					out[k] = true
				}
			}
		}
		return true
	})
	return out
}

func inlineAssign(info *types.Info, a *ast.AssignStmt, flow inlineFlow, cond bool) {
	if len(a.Lhs) != len(a.Rhs) {
		return
	}
	values := make([]map[string]bool, len(a.Rhs))
	for i, rhs := range a.Rhs {
		values[i] = inlineSources(info, rhs, flow)
		if cond {
			values[i][shapeCond] = true
		}
		if a.Tok >= token.ADD_ASSIGN && a.Tok <= token.AND_NOT_ASSIGN {
			values[i][shapeOp+(token.ADD+a.Tok-token.ADD_ASSIGN).String()] = true
		}
	}
	for i, lhs := range a.Lhs {
		p, ok := inlineLocation(info, lhs)
		if !ok {
			continue
		}
		if a.Tok != token.ASSIGN && a.Tok != token.DEFINE {
			for k := range flow[p] {
				values[i][k] = true
			}
		}
		flow[p] = values[i]
	}
}

func inlineCopyFlow(flow inlineFlow) inlineFlow {
	copy := inlineFlow{}
	for p, fields := range flow {
		copy[p] = map[string]bool{}
		for field := range fields {
			copy[p][field] = true
		}
	}
	return copy
}

func inlineMergeFlow(dst, src inlineFlow) {
	for p, fields := range src {
		if dst[p] == nil {
			dst[p] = map[string]bool{}
		}
		for field := range fields {
			dst[p][field] = true
		}
	}
}

// inlineDecl records var x T as a place with nothing in it yet and var x = v
// as an assignment, so a fragment may start at its declaration.
func inlineDecl(info *types.Info, d *ast.DeclStmt, flow inlineFlow, cond bool) {
	g, ok := d.Decl.(*ast.GenDecl)
	if !ok || g.Tok != token.VAR {
		return
	}
	for _, spec := range g.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		if len(vs.Values) == 0 {
			for _, name := range vs.Names {
				if p, ok := inlineLocation(info, name); ok {
					flow[p] = map[string]bool{}
				}
			}
			continue
		}
		lhs := make([]ast.Expr, len(vs.Names))
		for i, name := range vs.Names {
			lhs[i] = name
		}
		inlineAssign(info, &ast.AssignStmt{Lhs: lhs, Tok: token.DEFINE, Rhs: vs.Values}, flow, cond)
	}
}

func inlineWalk(info *types.Info, list []ast.Stmt, flow inlineFlow, cond bool) {
	for _, st := range list {
		switch x := st.(type) {
		case *ast.AssignStmt:
			inlineAssign(info, x, flow, cond)
		case *ast.DeclStmt:
			inlineDecl(info, x, flow, cond)
		case *ast.IfStmt:
			if a, ok := x.Init.(*ast.AssignStmt); ok {
				inlineAssign(info, a, flow, cond)
			}
			branch := inlineCopyFlow(flow)
			inlineWalk(info, x.Body.List, branch, true)
			if b, ok := x.Else.(*ast.BlockStmt); ok {
				inlineWalk(info, b.List, flow, true)
			}
			inlineMergeFlow(flow, branch)
		}
	}
}

func inlineLibraryFunction(fd *ast.FuncDecl, info *types.Info, pkgPath, pkgName, modulePath string) (inlineFunction, bool) {
	if fd.Body == nil || !fd.Name.IsExported() || nodeCount(fd.Body) > 120 {
		return inlineFunction{}, false
	}
	fn, ok := info.Defs[fd.Name].(*types.Func)
	if !ok || fn.Signature().Results().Len() != 1 {
		return inlineFunction{}, false
	}
	valid := true
	returns := 0
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if !info.Types[x.Fun].IsType() {
				id, ok := x.Fun.(*ast.Ident)
				if !ok {
					valid = false
					break
				}
				if _, ok := info.Uses[id].(*types.Builtin); !ok {
					valid = false
				}
			}
		case *ast.ReturnStmt:
			if len(x.Results) != 1 {
				valid = false
			}
			returns++
		case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.FuncLit:
			valid = false
		}
		return valid
	})
	if !valid || returns == 0 {
		return inlineFunction{}, false
	}
	flow := inlineFlow{}
	inlineWalk(info, fd.Body.List, flow, false)
	fields := map[string]bool{}
	shape := map[string]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if ret, ok := n.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
			for k := range inlineSources(info, ret.Results[0], flow) {
				if strings.HasPrefix(k, "#") {
					shape[k] = true
				}
				if strings.HasPrefix(k, modulePath+"/") || strings.HasPrefix(k, modulePath+".") {
					fields[k] = true
				}
			}
		}
		return true
	})
	if len(fields) < 2 {
		return inlineFunction{}, false
	}
	keys := slices.Sorted(maps.Keys(fields))
	return inlineFunction{libraryFunction: libraryFunction{Name: fd.Name.Name, Package: pkgName, ImportPath: pkgPath}, Fields: keys, Shape: inlineShape(shape), Method: fn.Signature().Recv() != nil}, true
}

func inlineCalls(info *types.Info, block *ast.BlockStmt, fn inlineFunction) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var obj types.Object
		switch f := c.Fun.(type) {
		case *ast.SelectorExpr:
			obj = info.ObjectOf(f.Sel)
		case *ast.Ident:
			obj = info.ObjectOf(f)
		}
		if obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == fn.ImportPath && obj.Name() == fn.Name {
			found = true
		}
		return !found
	})
	return found
}

func (r *DuplicateFuncOfLibraryRule) inlineDuplicates(ctx *core.GoProjectContext, file *core.FileContext, info *types.Info, fd *ast.FuncDecl, lib *moduleLibrary) []*core.Violation {
	if len(lib.inline) == 0 {
		return nil
	}
	var out []*core.Violation
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for start := 0; start < len(block.List); {
			end := start
			for end < len(block.List) && inlineStatement(block.List[end]) {
				end++
			}
			if start == end {
				start++
				continue
			}
			flow := inlineFlow{}
			inlineWalk(info, block.List[start:end], flow, false)
			out = append(out, r.inlineBlockMatches(ctx, file, info, fd, lib, block, block.List[start:end], flow)...)
			start = end
		}
		return true
	})
	return out
}

func inlineStatement(stmt ast.Stmt) bool {
	switch stmt.(type) {
	case *ast.AssignStmt, *ast.IfStmt, *ast.DeclStmt:
		return true
	default:
		return false
	}
}

func (r *DuplicateFuncOfLibraryRule) inlineBlockMatches(ctx *core.GoProjectContext, file *core.FileContext, info *types.Info, fd *ast.FuncDecl, lib *moduleLibrary, block *ast.BlockStmt, statements []ast.Stmt, flow inlineFlow) []*core.Violation {
	var out []*core.Violation
	places := slices.Collect(maps.Keys(flow))
	slices.SortFunc(places, func(a, b inlinePlace) int {
		if order := cmp.Compare(a.root.Pos(), b.root.Pos()); order != 0 {
			return order
		}
		return strings.Compare(a.path, b.path)
	})
	for _, p := range places {
		fields := flow[p]
		for _, fn := range lib.inline {
			keys := make([]string, 0, len(fields))
			for k := range fields {
				if strings.HasPrefix(k, fn.module+"/") || strings.HasPrefix(k, fn.module+".") {
					keys = append(keys, k)
				}
			}
			slices.Sort(keys)
			if !slices.Equal(keys, fn.Fields) || !slices.Equal(inlineShape(fields), fn.Shape) || inlineCalls(info, block, fn.inlineFunction) {
				continue
			}
			line := inlineFirstLine(ctx, info, block, statements, p)
			if !file.IsSuppressed(line, r.Name()) {
				violation := r.libraryViolation(file, fd, line, libraryMatch{name: fn.Name, module: fn.module, packageName: fn.Package, importPath: fn.ImportPath}, 1, true)
				if fn.Method {
					violation.Message = "Inline code duplicates method " + fn.Name + " of library " + fn.module + " — call the method instead"
					violation.Suggestion = "Call " + fn.Name + " on the library value instead of keeping a copy"
				}
				out = append(out, violation)
			}
			break
		}
	}
	return out
}

func inlineFirstLine(ctx *core.GoProjectContext, info *types.Info, block *ast.BlockStmt, statements []ast.Stmt, target inlinePlace) int {
	for _, stmt := range statements {
		if inlineWrites(info, stmt, target) {
			return ctx.FileSet.Position(stmt.Pos()).Line
		}
	}
	return ctx.FileSet.Position(block.Lbrace).Line
}

type inlineCandidate struct {
	inlineFunction
	module string
}

// inlineWrites reports whether stmt, its branches included, declares or
// assigns the place.
func inlineWrites(info *types.Info, stmt ast.Stmt, target inlinePlace) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		var lhs []ast.Expr
		switch x := n.(type) {
		case *ast.AssignStmt:
			lhs = x.Lhs
		case *ast.ValueSpec:
			for _, name := range x.Names {
				lhs = append(lhs, name)
			}
		case *ast.FuncLit:
			return false
		}
		for _, e := range lhs {
			if place, ok := inlineLocation(info, e); ok && place == target {
				found = true
			}
		}
		return !found
	})
	return found
}
