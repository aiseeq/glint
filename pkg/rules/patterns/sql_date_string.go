package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"reflect"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSQLDateStringParsedAsDateRule())
}

// SQLDateStringParsedAsDateRule detects a DATE or TIMESTAMP column scanned
// into a string field and parsed with a date-only layout:
//
//	type Round struct{ CloseDate *string `db:"close_date"` } // close_date DATE
//	day, err := time.Parse("2006-01-02", *round.CloseDate)
//
// database/sql hands the driver's time.Time to a string destination as
// RFC 3339 ("2024-03-01T00:00:00Z"): the date-only parse fails on every row,
// and whatever depends on the date never happens.
type SQLDateStringParsedAsDateRule struct {
	*rules.BaseRule
}

// NewSQLDateStringParsedAsDateRule creates the rule
func NewSQLDateStringParsedAsDateRule() *SQLDateStringParsedAsDateRule {
	return &SQLDateStringParsedAsDateRule{BaseRule: rules.NewBaseRule(
		"sql-date-string-parsed-as-date",
		"patterns",
		"Detects a string field scanned from a DATE or TIMESTAMP column parsed with a date-only layout — database/sql renders the value as RFC 3339, and the parse fails on every row",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the check needs types and the migrations.
func (r *SQLDateStringParsedAsDateRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *SQLDateStringParsedAsDateRule) RequiresSSA() bool { return false }

// ReadsOtherFiles reports that the findings depend on the migrations' columns.
func (r *SQLDateStringParsedAsDateRule) ReadsOtherFiles() bool { return true }

// dateColumnTypes are the column types database/sql hands over as time.Time.
var dateColumnTypes = map[string]bool{"date": true, "timestamp": true, "timestamptz": true}

// AnalyzeGoProject reports the date-only parses of date columns read as text.
func (r *SQLDateStringParsedAsDateRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		schema, ok := fileSchema(file, r.BaseRule)
		if !ok || schema == nil {
			return nil
		}
		return analyzeGoFunctions(file, func(fn *ast.FuncDecl) []*core.Violation {
			var violations []*core.Violation
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) < 2 {
					return true
				}
				callee := staticFunc(info, call)
				if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "time" || (callee.Name() != "Parse" && callee.Name() != "ParseInLocation") {
					return true
				}
				if !dateOnlyLayout(info, call.Args[0]) {
					return true
				}
				column := scannedColumn(info, fn, call.Args[1])
				if column == "" {
					return true
				}
				columnTypes := schema.ColumnTypes(column)
				if len(columnTypes) == 0 {
					return true
				}
				for _, columnType := range columnTypes {
					if !dateColumnTypes[columnType] {
						return true
					}
				}
				line := file.LineFor(call)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(file.RelPath, line, "The string parsed here is scanned from the "+columnTypes[0]+" column "+column+
					" — database/sql renders it as RFC 3339 (2006-01-02T15:04:05Z), and the date-only layout fails on every row")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Scan the column into time.Time (or *time.Time), or select it as text in the query (col::text, to_char)")
				violations = append(violations, v)
				return true
			})
			return violations
		})
	})
}

// scannedColumn returns the column of the db tag of the string field a value
// reads: the field itself, through * of a pointer field, or through a local
// variable assigned once from it.
func scannedColumn(info *types.Info, fn *ast.FuncDecl, expr ast.Expr) string {
	expr = ast.Unparen(expr)
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = ast.Unparen(star.X)
	}
	if id, ok := expr.(*ast.Ident); ok {
		v, ok := info.ObjectOf(id).(*types.Var)
		if !ok {
			return ""
		}
		value := singleAssignment(info, fn, v)
		if value == nil {
			return ""
		}
		return scannedColumn(info, fn, value)
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	selection := info.Selections[sel]
	if selection == nil || selection.Kind() != types.FieldVal {
		return ""
	}
	field, ok := selection.Obj().(*types.Var)
	if !ok || !stringOrPointer(field.Type()) {
		return ""
	}
	owner := selection.Recv()
	if ptr, ok := owner.Underlying().(*types.Pointer); ok {
		owner = ptr.Elem()
	}
	st, ok := owner.Underlying().(*types.Struct)
	if !ok {
		return ""
	}
	for i := range st.NumFields() {
		if st.Field(i) == field {
			name, _, _ := strings.Cut(reflect.StructTag(st.Tag(i)).Get("db"), ",")
			if name == "-" {
				return ""
			}
			return name
		}
	}
	return ""
}

func stringOrPointer(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.String
}

// singleAssignment returns the value of a local variable assigned exactly
// once in the function, nil otherwise.
func singleAssignment(info *types.Info, fn *ast.FuncDecl, v *types.Var) ast.Expr {
	var value ast.Expr
	count := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && info.ObjectOf(id) == v {
				count++
				if len(assign.Lhs) == len(assign.Rhs) {
					value = assign.Rhs[i]
				}
			}
		}
		return true
	})
	if count != 1 {
		return nil
	}
	return value
}
