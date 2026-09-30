package patterns

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/types/typeutil"
)

// resourceLeakCheck finds resources a function opens and neither releases nor
// hands on: the shared core of http-body-close and sql-rows-close. The rules
// differ only in what opens a resource, what releases it and which
// expressions carry it; the notion of "handed on" is the same for both.
//
// A resource is handed on when it is returned, or passed to a call whose
// callee takes over. A callee declared in the same file is inspected: when it
// never releases the parameter it received, the resource still leaks, one
// call away. A callee that cannot be inspected is trusted with it only when
// the parameter it takes the value as has a Close method.
type resourceLeakCheck struct {
	file *ast.File
	info *types.Info
	// opens reports whether the value of expr is a fresh resource the caller
	// must release.
	opens func(expr ast.Expr) bool
	// releases returns the variable whose resource call releases, or nil.
	releases func(call *ast.CallExpr) types.Object
	// carries returns the variable whose resource expr carries when handed
	// to a call or returned, or nil.
	carries func(expr ast.Expr) types.Object

	decls map[types.Object]*ast.FuncDecl
}

// openedResource is one variable a function body assigned a resource to.
type openedResource struct {
	variable types.Object
	name     string
	at       ast.Node
}

// leaks returns the resources opened in every function of the file — the
// declared functions and the function literals inside them — that are
// neither released nor handed on, in source order.
func (c *resourceLeakCheck) leaks() []openedResource {
	var leaked []openedResource
	ast.Inspect(c.file, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch fn := n.(type) {
		case *ast.FuncDecl:
			body = fn.Body
		case *ast.FuncLit:
			body = fn.Body
		}
		if body != nil {
			leaked = append(leaked, c.leaksIn(body)...)
		}
		return true
	})
	return leaked
}

// leaksIn checks the resources one function body opens on its own reachable
// statements; function literals nested in it are checked on their own.
func (c *resourceLeakCheck) leaksIn(body *ast.BlockStmt) []openedResource {
	var opened []openedResource
	seen := make(map[types.Object]bool)
	record := func(target ast.Expr, value ast.Expr, at ast.Node) {
		ident, ok := target.(*ast.Ident)
		if !ok || ident.Name == "_" || !c.opens(value) {
			return
		}
		variable := c.info.ObjectOf(ident)
		// A variable declared outside this body is released or handed on
		// where it lives, which this body does not show.
		if variable == nil || seen[variable] || variable.Pos() < body.Pos() || variable.Pos() > body.End() {
			return
		}
		seen[variable] = true
		opened = append(opened, openedResource{variable: variable, name: ident.Name, at: at})
	}
	walkReachableStatements(body.List, func(n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.AssignStmt:
				if len(node.Lhs) >= 1 && len(node.Rhs) == 1 {
					record(node.Lhs[0], node.Rhs[0], node)
				}
			case *ast.ValueSpec:
				if len(node.Names) >= 1 && len(node.Values) == 1 {
					record(node.Names[0], node.Values[0], node)
				}
			}
			return true
		})
	})
	if len(opened) == 0 {
		return nil
	}

	released := c.releasedIn(body)
	var leaked []openedResource
	for _, resource := range opened {
		if !released[resource.variable] {
			leaked = append(leaked, resource)
		}
	}
	return leaked
}

// releasedIn returns the variables the reachable statements of body release
// or hand on, including inside the function literals it defers or calls.
func (c *resourceLeakCheck) releasedIn(body *ast.BlockStmt) map[types.Object]bool {
	released := make(map[types.Object]bool)
	walkReachableStatements(body.List, func(n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if variable := c.releases(node); variable != nil {
					released[variable] = true
				}
				for index, arg := range node.Args {
					variable := c.carries(ast.Unparen(arg))
					if variable != nil && c.recipientReleases(node, index) {
						released[variable] = true
					}
				}
			case *ast.ReturnStmt:
				for _, result := range node.Results {
					if variable := c.carries(ast.Unparen(result)); variable != nil {
						released[variable] = true
					}
				}
			}
			return true
		})
	})
	return released
}

// recipientReleases reports whether the callee takes over the argIndex-th
// argument of call. A callee declared in this file is inspected: it takes over
// what it closes. Any other callee is trusted only when the parameter it
// receives the value as can be closed at all — a function taking an io.Reader
// or `any` reads or prints the resource, it does not own it.
func (c *resourceLeakCheck) recipientReleases(call *ast.CallExpr, argIndex int) bool {
	if callee := typeutil.StaticCallee(c.info, call); callee != nil {
		if decl := c.declaration(callee.Origin()); decl != nil && decl.Body != nil && !isVariadicAt(decl.Type, argIndex) {
			return c.declarationReleases(decl, argIndex)
		}
	}
	return hasCloseMethod(parameterType(c.info, call, argIndex))
}

// declarationReleases reports whether the function closes its argIndex-th
// parameter. An unnamed or blank parameter cannot be closed.
func (c *resourceLeakCheck) declarationReleases(decl *ast.FuncDecl, argIndex int) bool {
	param := paramIdentAt(decl.Type, argIndex)
	if param == nil {
		return false
	}
	variable := c.info.Defs[param]
	if variable == nil {
		return false
	}
	closes := false
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !closes
		}
		if c.releases(call) == variable {
			closes = true
		}
		// A parameter typed as the closer itself: body io.Closer, body.Close().
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" &&
			variableOf(c.info, ast.Unparen(sel.X)) == variable {
			closes = true
		}
		return !closes
	})
	return closes
}

// parameterType returns the type of the parameter the argIndex-th argument of
// call is bound to, or nil when the callee's signature is unknown.
func parameterType(info *types.Info, call *ast.CallExpr, argIndex int) types.Type {
	sig, ok := types.Unalias(info.TypeOf(call.Fun)).Underlying().(*types.Signature)
	if !ok || sig.Params().Len() == 0 {
		return nil
	}
	params := sig.Params()
	if sig.Variadic() && argIndex >= params.Len()-1 {
		last := params.At(params.Len() - 1).Type()
		if call.Ellipsis.IsValid() {
			return last
		}
		slice, ok := last.Underlying().(*types.Slice)
		if !ok {
			return nil
		}
		return slice.Elem()
	}
	if argIndex >= params.Len() {
		return nil
	}
	return params.At(argIndex).Type()
}

// hasCloseMethod reports whether a value of type t has a Close method.
func hasCloseMethod(t types.Type) bool {
	if t == nil {
		return false
	}
	obj, _, _ := types.LookupFieldOrMethod(t, true, nil, "Close")
	_, isMethod := obj.(*types.Func)
	return isMethod
}

// declaration returns the function or method of this file that declares fn.
func (c *resourceLeakCheck) declaration(fn *types.Func) *ast.FuncDecl {
	if c.decls == nil {
		c.decls = make(map[types.Object]*ast.FuncDecl)
		for _, decl := range c.file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok {
				if obj := c.info.Defs[fd.Name]; obj != nil {
					c.decls[obj] = fd
				}
			}
		}
	}
	return c.decls[fn]
}

// isVariadicAt reports whether the index-th argument lands in the variadic
// parameter of the signature.
func isVariadicAt(funcType *ast.FuncType, index int) bool {
	if funcType == nil || funcType.Params == nil || len(funcType.Params.List) == 0 {
		return false
	}
	last := funcType.Params.List[len(funcType.Params.List)-1]
	if _, variadic := last.Type.(*ast.Ellipsis); !variadic {
		return false
	}
	return index >= funcType.Params.NumFields()-1
}

// paramIdentAt returns the name of the index-th parameter, counting grouped
// names (a, b T) separately; nil when the parameter is unnamed, blank or
// absent.
func paramIdentAt(funcType *ast.FuncType, index int) *ast.Ident {
	if funcType == nil || funcType.Params == nil {
		return nil
	}
	position := 0
	for _, field := range funcType.Params.List {
		names := field.Names
		if len(names) == 0 {
			if position == index {
				return nil
			}
			position++
			continue
		}
		for _, name := range names {
			if position == index {
				if name.Name == "_" {
					return nil
				}
				return name
			}
			position++
		}
	}
	return nil
}

// variableOf returns the variable an identifier expression refers to.
func variableOf(info *types.Info, expr ast.Expr) types.Object {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return nil
	}
	variable, ok := info.ObjectOf(ident).(*types.Var)
	if !ok {
		return nil
	}
	return variable
}
