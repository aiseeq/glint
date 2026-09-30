package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSQLUnsupportedArgRule())
}

// SQLUnsupportedArgRule detects a slice or a map passed as a query argument
// through database/sql (or sqlx) when the project's driver is lib/pq:
//
//	db.ExecContext(ctx, `UPDATE sessions SET permissions = $1 WHERE id = $2`, session.Permissions, id)
//
// lib/pq encodes no Go slice but []byte: the call fails at run time with
// "sql: converting argument $1 type: unsupported type []string". Wrap it
// (pq.Array(v)) or encode it (json.Marshal). pgx accepts slices, so a
// project on pgx's database/sql driver is not checked.
type SQLUnsupportedArgRule struct {
	*rules.BaseRule
}

// NewSQLUnsupportedArgRule creates the rule
func NewSQLUnsupportedArgRule() *SQLUnsupportedArgRule {
	return &SQLUnsupportedArgRule{BaseRule: rules.NewBaseRule(
		"sql-unsupported-arg",
		"patterns",
		"Detects a slice or a map passed as a query argument to lib/pq, which cannot encode it — the query fails at run time",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the argument's type and the driver decide.
func (r *SQLUnsupportedArgRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SQLUnsupportedArgRule) RequiresSSA() bool { return false }

var queryMethods = map[string]bool{
	"Exec": true, "ExecContext": true, "Query": true, "QueryContext": true, "QueryRow": true, "QueryRowContext": true,
	"Queryx": true, "QueryxContext": true, "QueryRowx": true, "QueryRowxContext": true,
	"Get": true, "GetContext": true, "Select": true, "SelectContext": true, "MustExec": true, "MustExecContext": true,
}

// AnalyzeGoProject reports the slice and map arguments of queries in a
// project on lib/pq.
func (r *SQLUnsupportedArgRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if !onLibPQ(ctx) {
		return nil, nil
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !queryMethods[sel.Sel.Name] || !sqlHandle(info.TypeOf(sel.X)) {
				return true
			}
			args := call.Args
			if call.Ellipsis.IsValid() {
				args = args[:len(args)-1] // the spread argument list itself
			}
			for _, arg := range args {
				if !unencodable(info.TypeOf(arg)) {
					continue
				}
				line := file.LineFor(arg)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, "Query argument of type "+types.TypeString(info.TypeOf(arg), types.RelativeTo(nil))+" — lib/pq cannot encode a slice or a map, and the query fails at run time")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Wrap the slice in pq.Array(...), or encode the value (json.Marshal) for a json column")
				violations = append(violations, v)
			}
			return true
		})
		return violations
	})
}

// onLibPQ reports a project importing lib/pq and not pgx's database/sql
// driver.
func onLibPQ(ctx *core.GoProjectContext) bool {
	pq := false
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		for path := range pkg.Package.Imports {
			switch {
			case path == "github.com/lib/pq":
				pq = true
			case strings.HasPrefix(path, "github.com/jackc/pgx") && strings.HasSuffix(path, "/stdlib"):
				return false
			}
		}
	}
	return pq
}

// sqlHandle reports a database/sql or sqlx handle: DB, Tx, Conn, Stmt.
func sqlHandle(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	path := named.Obj().Pkg().Path()
	return path == "database/sql" || path == "github.com/jmoiron/sqlx"
}

// unencodable reports a slice other than []byte, or a map, that does not
// encode itself (no Value method).
func unencodable(t types.Type) bool {
	if t == nil {
		return false
	}
	if ms := types.NewMethodSet(t); ms.Lookup(nil, "Value") != nil {
		return false
	}
	if ms := types.NewMethodSet(types.NewPointer(t)); ms.Lookup(nil, "Value") != nil {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Slice:
		basic, ok := u.Elem().Underlying().(*types.Basic)
		return !ok || basic.Kind() != types.Byte
	case *types.Map:
		return true
	}
	return false
}
