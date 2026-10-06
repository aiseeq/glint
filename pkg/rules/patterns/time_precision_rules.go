package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewSubMicrosecondOffsetStoredRule())
	rules.Register(NewDateOnlyValueSetOnTimestampColumnRule())
}

// NewSubMicrosecondOffsetStoredRule creates sub-microsecond-offset-stored: a
// time moved by nanoseconds and then handed to the database.
//
//	endOfDay := next.Add(-time.Nanosecond)
//	filter.CreatedBefore = &endOfDay           // "created_at <= $1"
//	order.CreatedAt = now.Add(time.Duration(i) * time.Nanosecond)
//
// PostgreSQL keeps microseconds: the driver sends 23:59:59.999999999, the
// server rounds it to the next midnight, and the inclusive bound takes in the
// next day's rows; offsets meant to order rows collapse into one moment.
func NewSubMicrosecondOffsetStoredRule() *typedFuncRule {
	return newFuncRule("sub-microsecond-offset-stored",
		"Detects a time moved by nanoseconds and stored or used as a query bound — the database keeps microseconds, so the offset rounds away (end - 1ns becomes the next midnight)",
		core.SeverityMedium,
		"Move by whole microseconds: end.Add(-time.Microsecond), offsets in time.Microsecond steps",
		subMicrosecondOffsetStored)
}

func subMicrosecondOffsetStored(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	if fn.Body == nil {
		return nil
	}
	info := scope.info
	parents := helpers.ParentMap(fn.Body)
	var findings []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !subMicrosecondShift(info, call) {
			return true
		}
		if sink := storedTimeSink(scope, fn.Body, parents, call, 1); sink != "" {
			findings = append(findings, funcFinding{node: call,
				message: "A time moved by nanoseconds reaches " + sink + " — the database keeps microseconds and rounds the offset away"})
		}
		return true
	})
	return findings
}

// subMicrosecondShift reports t.Add(d) of a time.Time by a duration that is
// not whole microseconds: -time.Nanosecond, 24*time.Hour - time.Nanosecond,
// time.Duration(i) * time.Nanosecond.
func subMicrosecondShift(info *types.Info, call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Add" || len(call.Args) != 1 || !isTimeTimeType(info.TypeOf(sel.X)) {
		return false
	}
	shift := call.Args[0]
	if tv, ok := info.Types[shift]; ok && tv.Value != nil {
		v := constant.ToInt(tv.Value)
		if v.Kind() != constant.Int {
			return false
		}
		n, exact := constant.Int64Val(v)
		return exact && n%1000 != 0
	}
	nanos := false
	ast.Inspect(shift, func(n ast.Node) bool {
		s, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if c, ok := info.Uses[s.Sel].(*types.Const); ok && c.Pkg() != nil && c.Pkg().Path() == "time" && c.Name() == "Nanosecond" {
			nanos = true
		}
		return !nanos
	})
	return nanos
}

// storedTimeSink names where a time value is stored: a field the database
// reads (a db-tagged field, a field of a query filter), directly or through a
// local variable, its address, or a parameter of a project function it is
// passed to (depth levels deep). An empty name means the value stays in
// memory.
func storedTimeSink(scope funcScope, body *ast.BlockStmt, parents map[ast.Node]ast.Node, expr ast.Expr, depth int) string {
	info := scope.info
	node := ast.Node(expr)
	if unary, ok := parents[node].(*ast.UnaryExpr); ok && unary.Op == token.AND {
		node = unary
	}
	if paren, ok := parents[node].(*ast.ParenExpr); ok {
		node = paren
	}
	switch parent := parents[node].(type) {
	case *ast.KeyValueExpr:
		if parent.Value != node {
			return ""
		}
		key, ok := parent.Key.(*ast.Ident)
		lit, isLit := parents[parent].(*ast.CompositeLit)
		if !ok || !isLit {
			return ""
		}
		return storedField(info.TypeOf(lit), key.Name)
	case *ast.AssignStmt:
		for i, rhs := range parent.Rhs {
			if rhs != node || len(parent.Lhs) != len(parent.Rhs) {
				continue
			}
			switch lhs := parent.Lhs[i].(type) {
			case *ast.SelectorExpr:
				if selection, ok := info.Selections[lhs]; ok && selection.Kind() == types.FieldVal {
					return storedField(selection.Recv(), lhs.Sel.Name)
				}
			case *ast.Ident:
				// One hop through a local: the shifted value itself, not a
				// variable copied again.
				if _, shifted := expr.(*ast.CallExpr); shifted && node == expr {
					return storedVariable(scope, body, info.ObjectOf(lhs), depth)
				}
			}
		}
	case *ast.CallExpr:
		if depth == 0 || node != expr {
			return ""
		}
		decl, ok := scope.callee(parent)
		if !ok || decl.decl.Body == nil {
			return ""
		}
		for i, arg := range parent.Args {
			if arg != node {
				continue
			}
			param := paramObject(decl, i)
			if param == nil {
				return ""
			}
			inner := funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}
			if sink := storedVariable(inner, decl.decl.Body, param, depth-1); sink != "" {
				return sink + " in " + decl.decl.Name.Name
			}
		}
	}
	return ""
}

// storedVariable returns where a use of the variable stores it.
func storedVariable(scope funcScope, body *ast.BlockStmt, obj types.Object, depth int) string {
	if obj == nil {
		return ""
	}
	parents := helpers.ParentMap(body)
	sink := ""
	ast.Inspect(body, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok || sink != "" || scope.info.Uses[ident] != obj {
			return sink == ""
		}
		sink = storedTimeSink(scope, body, parents, ident, depth)
		return sink == ""
	})
	return sink
}

// paramObject returns the parameter of a declaration at an argument index,
// nil past the last fixed parameter.
func paramObject(decl typedFuncDecl, index int) types.Object {
	i := 0
	for _, field := range decl.decl.Type.Params.List {
		if _, variadic := field.Type.(*ast.Ellipsis); variadic {
			return nil
		}
		for _, name := range field.Names {
			if i == index {
				return decl.info.Defs[name]
			}
			i++
		}
	}
	return nil
}

// storedField names the field of a type the database reads: one with a db
// tag, or one of a query filter (ListFilter, SearchCriteria).
func storedField(holder types.Type, field string) string {
	if holder == nil {
		return ""
	}
	if ptr, ok := holder.Underlying().(*types.Pointer); ok {
		holder = ptr.Elem()
	}
	st, ok := holder.Underlying().(*types.Struct)
	if !ok {
		return ""
	}
	name := ""
	if named, ok := types.Unalias(holder).(*types.Named); ok {
		name = named.Obj().Name()
	}
	for i := 0; i < st.NumFields(); i++ {
		if st.Field(i).Name() != field {
			continue
		}
		if strings.Contains(st.Tag(i), `db:"`) {
			return "the db field " + name + "." + field
		}
		if hasWordFrom(name, map[string]bool{"filter": true, "filters": true, "criteria": true}) {
			return "the query filter " + name + "." + field
		}
	}
	return ""
}

// timestampColumn matches a column named for a moment: created_at, paid_at.
var timestampColumn = regexp.MustCompile(`^[a-z][a-z0-9_]*_at$`)

// NewDateOnlyValueSetOnTimestampColumnRule creates
// date-only-value-set-on-timestamp-column: a column builder handed a
// timestamp column and a date-only string.
//
//	if req.OperationDate != nil {
//		u.set("created_at", *req.OperationDate)  // "2026-07-29"
//	}
//
// The database reads "2026-07-29" as midnight: every edit resets the time of
// the moment the row records, and whatever is matched or aged by that time
// breaks.
func NewDateOnlyValueSetOnTimestampColumnRule() *typedFuncRule {
	return newFuncRule("date-only-value-set-on-timestamp-column",
		"Detects a date-only string (a field named …Date or …Day) written to a timestamp column (…_at) — the database reads it as midnight and the time of day is lost",
		core.SeverityMedium,
		"Change only the calendar day and keep the time: created_at = ($1::date + created_at::time), or pass a full time.Time",
		dateOnlyValueSetOnTimestampColumn)
}

func dateOnlyValueSetOnTimestampColumn(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	if fn.Body == nil {
		return nil
	}
	info := scope.info
	var findings []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		column := ""
		for _, arg := range call.Args {
			if text, ok := stringLiteral(arg); ok && timestampColumn.MatchString(text) {
				column = text
			}
		}
		if column == "" {
			return true
		}
		for _, arg := range call.Args {
			if name := dateOnlyStringName(info, arg); name != "" {
				findings = append(findings, funcFinding{node: call,
					message: "The date-only " + name + " is written to the timestamp column " + column + " — the database reads it as midnight and the time of day is lost"})
				break
			}
		}
		return true
	})
	return findings
}

// dateOnlyStringName returns the name of a string (or *string) value named
// for a calendar date: req.OperationDate, *effectiveDay.
func dateOnlyStringName(info *types.Info, expr ast.Expr) string {
	expr = ast.Unparen(expr)
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = ast.Unparen(star.X)
	}
	typ := info.TypeOf(expr)
	if typ == nil {
		return ""
	}
	if ptr, ok := typ.Underlying().(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	if basic, ok := typ.Underlying().(*types.Basic); !ok || basic.Kind() != types.String {
		return ""
	}
	var name string
	switch e := expr.(type) {
	case *ast.Ident:
		name = e.Name
	case *ast.SelectorExpr:
		name = e.Sel.Name
	default:
		return ""
	}
	words := helpers.IdentifierWords(name)
	if len(words) == 0 {
		return ""
	}
	last := strings.ToLower(words[len(words)-1])
	if last != "date" && last != "day" || hasWordFrom(name, map[string]bool{"time": true}) {
		return ""
	}
	return types.ExprString(expr)
}
