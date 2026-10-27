package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() { rules.Register(NewASTSelectorPackageResolvedByAliasRule()) }

// ASTSelectorPackageResolvedByAliasRule reports AST selector identifiers used
// as unresolved package keys.
type ASTSelectorPackageResolvedByAliasRule struct{ *rules.BaseRule }

// NewASTSelectorPackageResolvedByAliasRule creates the rule.
func NewASTSelectorPackageResolvedByAliasRule() *ASTSelectorPackageResolvedByAliasRule {
	return &ASTSelectorPackageResolvedByAliasRule{BaseRule: rules.NewBaseRule(
		"ast-selector-package-resolved-by-alias", "patterns",
		"Detects AST selector names used as package keys without resolving import aliases",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is unused because this rule needs package type information.
func (r *ASTSelectorPackageResolvedByAliasRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that this rule uses typed syntax without SSA.
func (r *ASTSelectorPackageResolvedByAliasRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports unresolved AST selector package lookups.
func (r *ASTSelectorPackageResolvedByAliasRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, nil
	}
	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		violations = append(violations, analyzeSelectorAliasPackage(ctx, pkg, r)...)
	}
	return violations, nil
}

func analyzeSelectorAliasPackage(ctx *core.GoProjectContext, pkg *core.GoPackageContext, rule *ASTSelectorPackageResolvedByAliasRule) []*core.Violation {
	info := pkg.Package.TypesInfo
	if resolvesPackageImports(pkg.Package.Syntax, info) {
		return nil
	}
	funcs := make(map[*types.Func]*ast.FuncDecl)
	var decls []*ast.FuncDecl
	for _, file := range pkg.Package.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			decls = append(decls, fn)
			if obj, ok := info.Defs[fn.Name].(*types.Func); ok {
				funcs[obj] = fn
			}
		}
	}
	sources := make(map[ast.Expr]bool)
	for _, fn := range decls {
		collectSelectorNameSources(fn.Body, info, sources)
	}
	if len(sources) == 0 {
		return nil
	}
	tainted := make(map[types.Object]bool)
	propagateSelectorAliasTaint(decls, funcs, sources, tainted, info)
	return reportSelectorAliasSinks(ctx, pkg, rule, decls, sources, tainted, info)
}

func propagateSelectorAliasTaint(decls []*ast.FuncDecl, funcs map[*types.Func]*ast.FuncDecl, sources map[ast.Expr]bool, tainted map[types.Object]bool, info *types.Info) {
	for changed := true; changed; {
		changed = false
		for _, fn := range decls {
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				switch n := node.(type) {
				case *ast.AssignStmt:
					for i, rhs := range n.Rhs {
						if i >= len(n.Lhs) || !selectorAliasTainted(rhs, sources, tainted, info) {
							continue
						}
						if id, ok := n.Lhs[i].(*ast.Ident); ok {
							changed = addSelectorAliasTaint(tainted, info.ObjectOf(id)) || changed
						}
					}
				case *ast.ValueSpec:
					for i, rhs := range n.Values {
						if i < len(n.Names) && selectorAliasTainted(rhs, sources, tainted, info) {
							changed = addSelectorAliasTaint(tainted, info.ObjectOf(n.Names[i])) || changed
						}
					}
				case *ast.CallExpr:
					callee := selectorAliasCallee(info, n)
					decl := funcs[callee]
					if decl != nil {
						changed = taintSelectorAliasParams(decl, n, sources, tainted, info) || changed
					}
				}
				return true
			})
		}
	}
}

func taintSelectorAliasParams(decl *ast.FuncDecl, call *ast.CallExpr, sources map[ast.Expr]bool, tainted map[types.Object]bool, info *types.Info) bool {
	if decl.Type.Params == nil {
		return false
	}
	params := decl.Type.Params.List
	changed := false
	paramIndex := 0
	for argIndex, arg := range call.Args {
		if !selectorAliasTainted(arg, sources, tainted, info) {
			paramIndex++
			continue
		}
		for paramIndex < len(params) {
			param := params[paramIndex]
			if len(param.Names) == 0 {
				paramIndex++
				continue
			}
			changed = addSelectorAliasTaint(tainted, info.ObjectOf(param.Names[0])) || changed
			break
		}
		if argIndex < len(call.Args)-1 {
			paramIndex++
		}
	}
	return changed
}

func reportSelectorAliasSinks(ctx *core.GoProjectContext, pkg *core.GoPackageContext, rule *ASTSelectorPackageResolvedByAliasRule, decls []*ast.FuncDecl, sources map[ast.Expr]bool, tainted map[types.Object]bool, info *types.Info) []*core.Violation {
	analyzed := make(map[*core.FileContext]bool)
	for _, file := range pkg.Files {
		if file.GoAST != nil && !file.IsTestFile() {
			analyzed[file] = true
		}
	}
	var violations []*core.Violation
	for _, fn := range decls {
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			sink := selectorAliasSink(node, fn.Body, sources, tainted, info)
			if sink == nil {
				return true
			}
			file, err := ctx.FileForPosition(sink.Pos())
			if err != nil || !analyzed[file] {
				return true
			}
			line := file.LineFor(sink)
			if file.IsSuppressed(line, rule.Name()) {
				return true
			}
			v := rule.CreateViolation(file.RelPath, line, "AST selector identifier reaches a package lookup without import resolution")
			v.WithCode(file.GetLine(line))
			v.WithSuggestion("Resolve the identifier through the file imports or package type information")
			violations = append(violations, v)
			return true
		})
	}
	return violations
}

func selectorAliasSink(node ast.Node, body *ast.BlockStmt, sources map[ast.Expr]bool, tainted map[types.Object]bool, info *types.Info) ast.Node {
	switch n := node.(type) {
	case *ast.IndexExpr:
		if selectorAliasTainted(n.Index, sources, tainted, info) && !selectorAliasIndexWrites(body, n) {
			if typ := info.TypeOf(n.X); typ != nil {
				if _, ok := typ.Underlying().(*types.Map); ok {
					return n
				}
			}
		}
	case *ast.BinaryExpr:
		if (n.Op == token.EQL || n.Op == token.NEQ) && (selectorAliasTainted(n.X, sources, tainted, info) || selectorAliasTainted(n.Y, sources, tainted, info)) {
			if typ := info.TypeOf(n.X); typ != nil {
				if basic, ok := typ.Underlying().(*types.Basic); ok && basic.Kind() == types.String {
					return n
				}
			}
		}
	}
	return nil
}

func selectorAliasIndexWrites(body *ast.BlockStmt, index *ast.IndexExpr) bool {
	writes := false
	ast.Inspect(body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if lhs == index {
				writes = true
			}
		}
		return !writes
	})
	return writes
}

func addSelectorAliasTaint(tainted map[types.Object]bool, obj types.Object) bool {
	if obj == nil || tainted[obj] {
		return false
	}
	tainted[obj] = true
	return true
}

func selectorAliasTainted(expr ast.Expr, sources map[ast.Expr]bool, tainted map[types.Object]bool, info *types.Info) bool {
	if expr == nil {
		return false
	}
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		if candidate, ok := node.(ast.Expr); ok && sources[candidate] {
			found = true
			return false
		}
		if ident, ok := node.(*ast.Ident); ok && tainted[info.ObjectOf(ident)] {
			found = true
			return false
		}
		return !found
	})
	return found
}

func selectorAliasCallee(info *types.Info, call *ast.CallExpr) *types.Func {
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		obj, _ := info.Uses[fn].(*types.Func)
		return obj
	case *ast.SelectorExpr:
		obj, _ := info.Uses[fn.Sel].(*types.Func)
		return obj
	}
	return nil
}

func collectSelectorNameSources(body *ast.BlockStmt, info *types.Info, sources map[ast.Expr]bool) {
	collect := func(node ast.Node) {
		ast.Inspect(node, func(inner ast.Node) bool {
			sel, ok := inner.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Name" {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || !selectorAliasType(info.TypeOf(ident), "go/ast", "Ident") {
				return true
			}
			sources[sel] = true
			return true
		})
	}
	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.TypeSwitchStmt:
			ast.Inspect(n.Body, func(inner ast.Node) bool {
				clause, ok := inner.(*ast.CaseClause)
				if !ok {
					return true
				}
				matched := false
				for _, typ := range clause.List {
					if selectorAliasType(info.TypeOf(typ), "go/ast", "SelectorExpr") {
						matched = true
					}
				}
				if matched {
					for _, stmt := range clause.Body {
						collect(stmt)
					}
				}
				return false
			})
		case *ast.IfStmt:
			if selectorAliasAssertionSucceeded(n, info) && n.Body != nil {
				collect(n.Body)
			}
		}
		return true
	})
}

func selectorAliasAssertionSucceeded(stmt *ast.IfStmt, info *types.Info) bool {
	assign, ok := stmt.Init.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
		return false
	}
	assertion, ok := assign.Rhs[0].(*ast.TypeAssertExpr)
	if !ok || !selectorAliasType(info.TypeOf(assertion.Type), "go/ast", "SelectorExpr") {
		return false
	}
	okIdent, ok := assign.Lhs[1].(*ast.Ident)
	if !ok || info.ObjectOf(okIdent) == nil {
		return false
	}
	condition, ok := ast.Unparen(stmt.Cond).(*ast.Ident)
	return ok && info.ObjectOf(condition) == info.ObjectOf(okIdent)
}

func selectorAliasType(typ types.Type, pkgPath, name string) bool {
	ptr, ok := typ.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := ptr.Elem().(*types.Named)
	return ok && named.Obj().Name() == name && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == pkgPath
}

// resolvesPackageImports reports whether the package uses import metadata or
// package-name type checks to resolve selector names.
func resolvesPackageImports(files []*ast.File, info *types.Info) bool {
	for _, file := range files {
		resolved := false
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.SelectorExpr:
				if n.Sel.Name == "Imports" && selectorAliasType(info.TypeOf(n.X), "go/ast", "File") {
					resolved = true
				}
			case *ast.TypeAssertExpr:
				if selectorAliasType(info.TypeOf(n.Type), "go/types", "PkgName") {
					resolved = true
				}
			case *ast.IndexExpr:
				if sel, ok := n.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Uses" && selectorAliasType(info.TypeOf(sel.X), "go/types", "Info") {
					resolved = true
				}
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ObjectOf" && selectorAliasType(info.TypeOf(sel.X), "go/types", "Info") {
					resolved = true
				}
			}
			return true
		})
		if resolved {
			return true
		}
	}
	return false
}
