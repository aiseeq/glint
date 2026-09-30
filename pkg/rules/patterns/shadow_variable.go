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
// the name of a variable of the same function that is still visible there:
// a receiver, a parameter, a result or an outer local. Scopes are the ones the
// type checker builds, so switch and select cases, closures and if/for/switch
// headers are all seen, and a name declared in an if header does not leak
// past the if statement.
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
			"Detects variable shadowing (same name in nested scope)",
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
					violations = r.check(ctx, info, fn, lhs, rhs, violations)
				}
			case *ast.ValueSpec:
				for i, name := range stmt.Names {
					var rhs ast.Expr
					if len(stmt.Values) == len(stmt.Names) {
						rhs = stmt.Values[i]
					}
					violations = r.check(ctx, info, fn, name, rhs, violations)
				}
			case *ast.RangeStmt:
				if stmt.Tok == token.DEFINE {
					violations = r.check(ctx, info, fn, stmt.Key, nil, violations)
					violations = r.check(ctx, info, fn, stmt.Value, nil, violations)
				}
			}
			return true
		})
	}
	return violations
}

// check reports the variable declared by expr when it hides a variable of the
// same function. rhs is its initializer, when it has its own.
func (r *ShadowVariableRule) check(
	ctx *core.FileContext,
	info *types.Info,
	fn *ast.FuncDecl,
	expr, rhs ast.Expr,
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

	line := ctx.LineFor(name)
	v := r.CreateViolation(ctx.RelPath, line, "Variable '"+name.Name+"' shadows declaration from line "+strconv.Itoa(ctx.LineForPos(shadowed.Pos())))
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion("Use a different variable name to avoid confusion")
	v.WithContext("pattern", "shadow_variable")
	v.WithContext("shadowed_name", name.Name)
	return append(violations, v)
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
