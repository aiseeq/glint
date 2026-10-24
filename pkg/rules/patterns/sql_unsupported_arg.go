package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSQLUnsupportedArgRule())
}

// SQLUnsupportedArgRule detects a slice, an array or a map passed as a query
// argument through database/sql (or sqlx) when the project's driver is lib/pq:
//
//	db.ExecContext(ctx, `UPDATE sessions SET permissions = $1 WHERE id = $2`, session.Permissions, id)
//
// lib/pq encodes no Go slice but []byte, and no array or map: the call fails
// at run time with "sql: converting argument $1 type: unsupported type
// []string". A pointer to one fails the same way, as database/sql
// dereferences it; a driver.Valuer encodes itself. Wrap it (pq.Array(v)) or
// encode it (json.Marshal). pgx accepts slices, so a project on pgx's
// database/sql driver is not checked.
type SQLUnsupportedArgRule struct {
	*rules.BaseRule
}

// NewSQLUnsupportedArgRule creates the rule
func NewSQLUnsupportedArgRule() *SQLUnsupportedArgRule {
	return &SQLUnsupportedArgRule{BaseRule: rules.NewBaseRule(
		"sql-unsupported-arg",
		"patterns",
		"Detects a slice other than []byte, an array or a map (or a pointer to one) passed without a driver.Valuer as a query argument to lib/pq, which cannot encode it — the query fails at run time",
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

// AnalyzeGoProject reports the slice, array and map arguments of queries in
// a project on lib/pq.
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
			args, isQuery := sqlQueryArgs(call, info)
			if !isQuery {
				return true
			}
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
				v := r.CreateViolation(file.RelPath, line, "Query argument of type "+types.TypeString(info.TypeOf(arg), types.RelativeTo(nil))+" — lib/pq cannot encode a slice, an array or a map, and the query fails at run time")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Wrap the slice in pq.Array(...), or encode the value (json.Marshal) for a json column")
				violations = append(violations, v)
			}
			return true
		})
		return violations
	})
}

// sqlQueryArgs returns the query arguments of a call to a database/sql or
// sqlx query method, or to an sqlx package-level helper that passes them on
// (sqlx.Get, sqlx.Select): the variadic tail of the callee. A destination,
// the query string, and the single argument of a named query (NamedStmt.Exec,
// sqlx.NamedExec: a map or a struct bound by parameter names) are not.
func sqlQueryArgs(call *ast.CallExpr, info *types.Info) ([]ast.Expr, bool) {
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok || !queryMethods[fn.Name()] {
		return nil, false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || !sig.Variadic() {
		return nil, false
	}
	if recv := sig.Recv(); recv != nil {
		if !sqlHandle(recv.Type()) {
			return nil, false
		}
	} else if fn.Pkg() == nil || fn.Pkg().Path() != sqlxPath {
		return nil, false
	}
	fixed := sig.Params().Len() - 1
	if len(call.Args) < fixed {
		return nil, false
	}
	return call.Args[fixed:], true
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

// sqlHandle reports a receiver of a database/sql or sqlx type: DB, Tx, Conn,
// Stmt, and the sqlx interfaces over them (Queryer, Ext). A method promoted
// from an embedded handle, or called through an alias of the pointer type,
// has the handle as its receiver.
func sqlHandle(t types.Type) bool {
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	path := named.Obj().Pkg().Path()
	return path == "database/sql" || path == sqlxPath
}

// unencodable reports what database/sql's default converter rejects, as
// lib/pq leaves it the conversion: a slice other than []byte, an array (of
// bytes too), a map, or a pointer to one of them, unless the type is a
// driver.Valuer.
func unencodable(t types.Type) bool {
	if t == nil || driverValuer(t) {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return unencodable(u.Elem())
	case *types.Slice:
		basic, ok := u.Elem().Underlying().(*types.Basic)
		return !ok || basic.Kind() != types.Byte
	case *types.Map, *types.Array:
		return true
	}
	return false
}

// driverValuer reports a method set with Value() (driver.Value, error), the
// one database/sql calls. A Value method of another signature is not called,
// and one on *T does not serve a T passed by value: database/sql does not
// take the argument's address.
func driverValuer(t types.Type) bool {
	method := types.NewMethodSet(t).Lookup(nil, "Value")
	if method == nil {
		return false
	}
	sig, ok := method.Type().(*types.Signature)
	return ok && sig.Params().Len() == 0 && sig.Results().Len() == 2 &&
		isNamedType(sig.Results().At(0).Type(), "database/sql/driver", "Value") && isErrorType(sig.Results().At(1).Type())
}
