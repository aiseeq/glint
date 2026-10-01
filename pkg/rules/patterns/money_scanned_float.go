package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMoneyScannedIntoFloatRule())
}

// MoneyScannedIntoFloatRule detects an amount read from the database into a
// float:
//
//	var totalDeposits, totalWithdrawals float64
//	db.QueryRowContext(ctx, query, id).Scan(&totalDeposits, &totalWithdrawals)
//	balance := totalDeposits - totalWithdrawals
//
// The column is NUMERIC, exact to the last digit; the driver parses it into
// the nearest float, and the arithmetic after it works on approximations: a
// balance off by a fraction of a cent, a comparison with zero that fails on
// an empty wallet. Read the amount into a decimal type, or a string to parse.
// The destination is judged by its name (money_context.go): a float named
// as an amount, a balance, a total.
type MoneyScannedIntoFloatRule struct {
	*rules.BaseRule
}

// NewMoneyScannedIntoFloatRule creates the rule
func NewMoneyScannedIntoFloatRule() *MoneyScannedIntoFloatRule {
	return &MoneyScannedIntoFloatRule{BaseRule: rules.NewBaseRule(
		"money-scanned-into-float",
		"patterns",
		"Detects an amount read from the database (Scan, sqlx Get/Select) into a float64 — the exact NUMERIC becomes an approximation",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the destination's type decides.
func (r *MoneyScannedIntoFloatRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *MoneyScannedIntoFloatRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the money-named float destinations of database
// reads.
func (r *MoneyScannedIntoFloatRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		if file.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, dest := range databaseDestinations(info, call) {
				name, ok := floatMoneyDestination(info, dest)
				if !ok {
					continue
				}
				line := file.LineFor(dest)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, "Amount "+name+" is read from the database into a float — the exact NUMERIC becomes an approximation, and every sum and comparison after it inherits the error")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Scan into decimal.Decimal (or the project's decimal type), or into a string parsed with decimal.NewFromString")
				violations = append(violations, v)
			}
			return true
		})
		return violations
	})
}

// databaseDestinations returns the destination arguments of a row Scan on a
// database/sql, sqlx or pgx value, or the destination of a sqlx Get/Select.
func databaseDestinations(info *types.Info, call *ast.CallExpr) []ast.Expr {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if sel.Sel.Name == "Scan" && databaseRowType(info.TypeOf(sel.X)) {
		return call.Args
	}
	if destIdx, _, ok := sqlxReadArgs(info, call); ok {
		return call.Args[destIdx : destIdx+1]
	}
	return nil
}

// databaseRowType reports a value of database/sql, sqlx or pgx: the types a
// row is scanned from.
func databaseRowType(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	path := named.Obj().Pkg().Path()
	return path == "database/sql" || path == "github.com/jmoiron/sqlx" || strings.HasPrefix(path, "github.com/jackc/pgx")
}

// floatMoneyDestination returns the name of &x, &s.X, when it is a float (a
// slice of floats, a sql.NullFloat64) named as money.
func floatMoneyDestination(info *types.Info, dest ast.Expr) (string, bool) {
	unary, ok := ast.Unparen(dest).(*ast.UnaryExpr)
	if !ok || unary.Op != token.AND {
		return "", false
	}
	var name string
	switch target := ast.Unparen(unary.X).(type) {
	case *ast.Ident:
		name = target.Name
	case *ast.SelectorExpr:
		name = target.Sel.Name
	default:
		return "", false
	}
	if !floatValue(info.TypeOf(unary.X)) || !looksLikeMoney(name) {
		return "", false
	}
	return name, true
}

// floatValue reports a float, a pointer to one, a slice of them or a
// sql.NullFloat64.
func floatValue(t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return floatValue(u.Elem())
	case *types.Slice:
		return floatValue(u.Elem())
	case *types.Basic:
		return u.Info()&types.IsFloat != 0
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "database/sql" && named.Obj().Name() == "NullFloat64"
}
