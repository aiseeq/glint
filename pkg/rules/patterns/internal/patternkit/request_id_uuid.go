package patternkit

import (
	"errors"
	"fmt"
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

// AnalyzeAgainstSchema runs a typed check of every function of a project
// that needs the schema of its migrations; a project without migrations, or
// with one that does not load (the schema rules report it), is not checked.
func AnalyzeAgainstSchema(ctx *core.GoProjectContext, rule *rules.BaseRule, suggestion string,
	check func(FuncScope, *sqlschema.Schema, *ast.FuncDecl) []FuncFinding) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", rule.Name())
	}
	schema, err := sqlschema.LoadCached(ctx.ProjectRoot, MigrationDirs(rule))
	var migrationErr *sqlschema.MigrationError
	if errors.As(err, &migrationErr) {
		return nil, nil // the schema rules report the migration; nothing to check against
	}
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	if schema == nil {
		return nil, nil
	}
	inner := &TypedFuncRule{
		BaseRule:   rule,
		Suggestion: suggestion,
		Check: func(scope FuncScope, fn *ast.FuncDecl) []FuncFinding {
			return check(scope, schema, fn)
		},
	}
	return inner.AnalyzeGoProject(ctx)
}
