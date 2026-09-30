package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewShadowVariableRule())
}

// ShadowVariableRule detects a local variable declared in a nested scope with
// the name of a variable of the same function that is still visible there -
// a receiver, a parameter, a result or an outer local - when the function
// reads the outer variable again after the inner declaration. Scopes are the
// ones the type checker builds, so switch and select cases, closures and
// if/for/switch headers are all seen, and a name declared in an if header does
// not leak past the if statement.
type ShadowVariableRule struct {
	*rules.BaseRule
	// Common Go variable names that are safe to shadow
	safeToShadow map[string]bool
}

// NewShadowVariableRule creates the rule
func NewShadowVariableRule() *ShadowVariableRule {
	return &ShadowVariableRule{
		BaseRule: rules.NewBaseRule(
			"shadow-variable",
			"patterns",
			"Detects a variable redeclared in a nested scope while the function still reads the outer one afterwards",
			core.SeverityMedium,
		),
		safeToShadow: map[string]bool{
			"err": true, // Very common in Go error handling
			"ok":  true, // Common in map/type assertion checks
			"i":   true, // Loop counter
			"j":   true, // Nested loop counter
			"k":   true, // Third loop counter
			"v":   true, // Common value placeholder
			"n":   true, // Common count variable
		},
	}
}

// AnalyzeFile checks one file without the type information of its package.
// Shadowing is lexical: the file is type-checked on its own to get its
// scopes, and names it cannot resolve (imports, other files of the package)
// stay unresolved, which does not change the scopes of its local variables.
func (r *ShadowVariableRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ShadowVariableRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file with the scopes of its package.
func (r *ShadowVariableRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

func (r *ShadowVariableRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	if info == nil {
		if ctx.GoFileSet == nil {
			return nil
		}
		info = fileScopes(ctx)
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch stmt := n.(type) {
			case *ast.AssignStmt:
				if stmt.Tok != token.DEFINE {
					return true
				}
				for i, lhs := range stmt.Lhs {
					var rhs ast.Expr
					if len(stmt.Rhs) == len(stmt.Lhs) {
						rhs = stmt.Rhs[i]
					}
					violations = r.check(ctx, info, fn, lhs, rhs, stmt.End(), violations)
				}
			case *ast.ValueSpec:
				for i, name := range stmt.Names {
					var rhs ast.Expr
					if len(stmt.Values) == len(stmt.Names) {
						rhs = stmt.Values[i]
					}
					violations = r.check(ctx, info, fn, name, rhs, stmt.End(), violations)
				}
			case *ast.RangeStmt:
				if stmt.Tok == token.DEFINE {
					violations = r.check(ctx, info, fn, stmt.Key, nil, stmt.X.End(), violations)
					violations = r.check(ctx, info, fn, stmt.Value, nil, stmt.X.End(), violations)
				}
			}
			return true
		})
	}
	return violations
}

// check reports the variable declared by expr when it hides a variable of the
// same function that the function still reads once the declaration is done.
// rhs is its initializer, when it has its own; declEnd is where the
// declaration ends.
//
// Hiding a variable nobody reads any more cannot mix the two up: the if/else-if
// lookup, the double-checked lock and the loop over candidates after the first
// guess are all written that way on purpose. The bug is a later read of the
// outer variable that expected the inner assignment to reach it, and so is a
// bare return of a named result the branch meant to set. Variables of
// different types are two different things, as the shadow analyzer of the Go
// tools has it.
func (r *ShadowVariableRule) check(
	ctx *core.FileContext,
	info *types.Info,
	fn *ast.FuncDecl,
	expr, rhs ast.Expr,
	declEnd token.Pos,
	violations []*core.Violation,
) []*core.Violation {
	name, ok := expr.(*ast.Ident)
	if !ok || name.Name == "_" || r.safeToShadow[name.Name] {
		return violations
	}
	obj, ok := info.Defs[name].(*types.Var)
	if !ok || obj.Parent() == nil || obj.Parent().Parent() == nil {
		return violations
	}
	_, outer := obj.Parent().Parent().LookupParent(name.Name, name.Pos())
	shadowed, ok := outer.(*types.Var)
	if !ok || shadowed.IsField() || shadowed.Pos() < fn.Pos() || shadowed.Pos() >= fn.End() {
		return violations
	}
	// `name := name` copies the outer variable on purpose - the capture
	// idiom for closures and goroutines.
	if ident, ok := ast.Unparen(rhs).(*ast.Ident); ok && info.Uses[ident] == shadowed {
		return violations
	}
	if typesDiffer(obj.Type(), shadowed.Type()) || !readAfter(fn, info, shadowed, declEnd) {
		return violations
	}

	line := ctx.LineFor(name)
	v := r.CreateViolation(ctx.RelPath, line, "Variable '"+name.Name+"' shadows declaration from line "+strconv.Itoa(ctx.LineForPos(shadowed.Pos())))
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion("Use a different variable name to avoid confusion")
	v.WithContext("pattern", "shadow_variable")
	v.WithContext("shadowed_name", name.Name)
	return append(violations, v)
}

// typesDiffer reports whether both types are known and not the same. A file
// checked on its own leaves the types of unresolved names invalid, and those
// say nothing.
func typesDiffer(a, b types.Type) bool {
	if !isValidType(a) || !isValidType(b) {
		return false
	}
	return !types.Identical(a, b)
}

func isValidType(t types.Type) bool {
	return t != nil && t != types.Typ[types.Invalid]
}

// readAfter reports whether the function reads the variable after pos: a use
// of the name, or a bare return of the function literal or declaration whose
// named result it is.
func readAfter(fn *ast.FuncDecl, info *types.Info, variable *types.Var, pos token.Pos) bool {
	found := false
	var walk func(body ast.Node, results *ast.FieldList)
	walk = func(body ast.Node, results *ast.FieldList) {
		ast.Inspect(body, func(n ast.Node) bool {
			if found {
				return false
			}
			switch node := n.(type) {
			case *ast.FuncLit:
				walk(node.Body, node.Type.Results)
				return false
			case *ast.Ident:
				found = node.Pos() > pos && info.Uses[node] == variable
			case *ast.ReturnStmt:
				found = node.Pos() > pos && len(node.Results) == 0 && declaresVar(results, variable, info)
			}
			return !found
		})
	}
	walk(fn.Body, fn.Type.Results)
	return found
}

// declaresVar reports whether the field list declares the variable.
func declaresVar(fields *ast.FieldList, variable *types.Var, info *types.Info) bool {
	if fields == nil {
		return false
	}
	for _, field := range fields.List {
		for _, name := range field.Names {
			if info.Defs[name] == variable {
				return true
			}
		}
	}
	return false
}

// fileScopes type-checks one file on its own and returns its definitions and
// scopes. Imports are not resolved and names from other files of the package
// are missing, so the checker reports errors; they are expected and ignored:
// they concern types, not the lexical scopes the rule reads.
func fileScopes(ctx *core.FileContext) *types.Info {
	info := &types.Info{
		Defs:   make(map[*ast.Ident]types.Object),
		Uses:   make(map[*ast.Ident]types.Object),
		Scopes: make(map[ast.Node]*types.Scope),
	}
	conf := types.Config{
		Importer: unresolvedImporter{},
		Error:    func(error) {},
	}
	_, _ = conf.Check(ctx.GoAST.Name.Name, ctx.GoFileSet, []*ast.File{ctx.GoAST}, info) // ignored-error: safe — the first of the expected unresolved-name errors; the scopes are complete regardless
	return info
}

// unresolvedImporter refuses every import: a file checked on its own has no
// access to the packages it imports.
type unresolvedImporter struct{}

func (unresolvedImporter) Import(path string) (*types.Package, error) {
	return nil, fmt.Errorf("import %q: not resolved in a single-file check", path)
}

var _ types.Importer = unresolvedImporter{}
