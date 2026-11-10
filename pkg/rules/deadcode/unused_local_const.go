package deadcode

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
)

// unusedLocalConstants reports the constants declared in a function body that
// nothing after their declaration names. The compiler rejects an unused local
// variable but not an unused local constant. A constant's scope is the rest
// of its block, the later constants of its group included, so a name is
// looked for there only. Any identifier of that name counts as a use, a
// shadowing declaration or a field selector too: the check may miss, it does
// not report a constant something reads. A group counting with iota or
// repeating an expression is one unit: its constants are reported only when
// none of them is read, as removing one would shift or break the rest.
func (r *UnusedSymbolsRule) unusedLocalConstants(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	report := func(name *ast.Ident) {
		v := r.CreateViolation(ctx.RelPath, ctx.LineFor(name),
			"Constant '"+name.Name+"' declared in a function is never used")
		v.WithCode(ctx.GetLine(ctx.LineFor(name)))
		v.WithSuggestion("Remove the constant, or use it where its value was meant to go")
		v.WithContext("symbol", name.Name)
		v.WithContext("kind", "local constant")
		violations = append(violations, v)
	}
	check := func(stmts []ast.Stmt) {
		for i, stmt := range stmts {
			gen := localConstDecl(stmt)
			if gen == nil {
				continue
			}
			rest := stmts[i+1:]
			if linkedConstGroup(gen) {
				// Each constant of the group takes its value from its place
				// in it, or repeats the expression above: removing one read
				// by none changes or breaks the others, so the group is one
				// unit, used when any of its constants is.
				var names []*ast.Ident
				used := false
				for _, spec := range constSpecs(gen) {
					for _, name := range spec.Names {
						if name.Name == "_" {
							continue
						}
						names = append(names, name)
						used = used || namedIn(name.Name, nil, rest)
					}
				}
				if !used {
					for _, name := range names {
						report(name)
					}
				}
				continue
			}
			for j, spec := range constSpecs(gen) {
				for _, name := range spec.Names {
					if name.Name != "_" && !namedIn(name.Name, gen.Specs[j+1:], rest) {
						report(name)
					}
				}
			}
		}
	}
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BlockStmt:
			check(node.List)
		case *ast.CaseClause:
			check(node.Body)
		case *ast.CommClause:
			check(node.Body)
		}
		return true
	})
	return violations
}

// localConstDecl returns the constant declaration a statement makes, under
// its labels too; nil for any other statement.
func localConstDecl(stmt ast.Stmt) *ast.GenDecl {
	for {
		labeled, ok := stmt.(*ast.LabeledStmt)
		if !ok {
			break
		}
		stmt = labeled.Stmt
	}
	decl, ok := stmt.(*ast.DeclStmt)
	if !ok {
		return nil
	}
	gen, ok := decl.Decl.(*ast.GenDecl)
	if !ok || gen.Tok != token.CONST {
		return nil
	}
	return gen
}

// linkedConstGroup reports a constant group whose values depend on the
// constants' places in it: a spec without values repeats the expression
// above it, and iota counts the specs.
func linkedConstGroup(gen *ast.GenDecl) bool {
	for _, spec := range constSpecs(gen) {
		if len(spec.Values) == 0 {
			return true
		}
		for _, value := range spec.Values {
			if identIn("iota", value) {
				return true
			}
		}
	}
	return false
}

// constSpecs returns the specs of a constant declaration; the parser gives
// every one as a value spec.
func constSpecs(gen *ast.GenDecl) []*ast.ValueSpec {
	specs := make([]*ast.ValueSpec, 0, len(gen.Specs))
	for _, spec := range gen.Specs {
		if valueSpec, ok := spec.(*ast.ValueSpec); ok {
			specs = append(specs, valueSpec)
		}
	}
	return specs
}

// namedIn reports an identifier called name in the later specs of a constant
// group or in the statements after it.
func namedIn(name string, specs []ast.Spec, stmts []ast.Stmt) bool {
	for _, spec := range specs {
		if identIn(name, spec) {
			return true
		}
	}
	for _, stmt := range stmts {
		if identIn(name, stmt) {
			return true
		}
	}
	return false
}

// identIn reports an identifier called name in node.
func identIn(name string, node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			found = true
		}
		return !found
	})
	return found
}
