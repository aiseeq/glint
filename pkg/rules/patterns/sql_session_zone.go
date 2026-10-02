package patterns

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewSQLSessionTimeZoneRule())
}

// SQLSessionTimeZoneRule detects SQL taking a date from a moment in the
// session's time zone when the connection string the code builds does not
// pin that zone:
//
//	"host=%s port=%d user=%s dbname=%s sslmode=%s"
//	... WHERE user_id = $1 AND created_at::date = $2
//
// The zone comes from the server's or the client's settings, so the same
// row falls on another day on a machine with another zone: a lookup misses
// the row it wrote and writes it again. Reported: CURRENT_DATE, now()::date,
// a timestamptz column of the migrations cast to date, passed to date() or
// truncated by date_trunc. Not reported when no Go code builds a connection
// string (it then comes from the environment), or when any code pins the
// zone: timezone= in a DSN, a "timezone" runtime parameter, SET TIME ZONE.
type SQLSessionTimeZoneRule struct {
	*rules.BaseRule
	// found are the root's connection strings and the statements taking
	// dates in the session's zone, by file, when no code pins the zone and
	// both exist.
	found map[string][]sessionZoneSite
	// dsns and dates count them for the messages; firstDSN and firstDate
	// are where the first of each is.
	dsns, dates         int
	firstDSN, firstDate string
}

type sessionZoneSite struct {
	line int
	dsn  bool
}

// NewSQLSessionTimeZoneRule creates the rule
func NewSQLSessionTimeZoneRule() *SQLSessionTimeZoneRule {
	return &SQLSessionTimeZoneRule{BaseRule: rules.NewBaseRule(
		"sql-session-timezone",
		"patterns",
		"Detects SQL taking a date in the session's time zone while the connection string leaves that zone to the server",
		core.SeverityMedium,
	)}
}

var (
	connectionString = regexp.MustCompile(`(?i)\b(?:sslmode|dbname)=|^["` + "`" + `]postgres(?:ql)?://`)
	pinnedZone       = regexp.MustCompile(`(?i)\btimezone=|\bset\s+(?:time\s+zone|timezone)\b`)
)

// UseProjectFiles finds the root's connection strings, whether any code
// pins the session's zone, and the statements taking dates in it.
func (r *SQLSessionTimeZoneRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	found := make(map[string][]sessionZoneSite)
	for _, ctx := range files {
		if !productionGoFile(ctx) {
			continue
		}
		pinned := false
		ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.IndexExpr:
				pinned = pinned || zoneParameter(node.Index)
			case *ast.KeyValueExpr:
				pinned = pinned || zoneParameter(node.Key)
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					break
				}
				if pinnedZone.MatchString(node.Value) {
					pinned = true
				} else if connectionString.MatchString(node.Value) {
					found[ctx.RelPath] = append(found[ctx.RelPath], sessionZoneSite{line: ctx.GoFileSet.Position(node.Pos()).Line, dsn: true})
				}
			}
			return !pinned
		})
		if pinned {
			return
		}
	}
	if len(found) == 0 {
		return
	}
	storedTimes := storedTimeFields(files)
	for _, ctx := range files {
		if productionGoFile(ctx) {
			for _, line := range storedTimeDateCuts(ctx, storedTimes) {
				found[ctx.RelPath] = append(found[ctx.RelPath], sessionZoneSite{line: line})
			}
		}
	}
	for _, ctx := range files {
		if !productionGoFile(ctx) {
			continue
		}
		schema, ok := fileSchema(ctx, r.BaseRule)
		if !ok {
			break
		}
		for _, literal := range sqlLiterals(ctx.GoAST) {
			for _, offset := range schema.SessionDates(literal.text) {
				found[ctx.RelPath] = append(found[ctx.RelPath], sessionZoneSite{line: literal.lineAt(ctx, offset)})
			}
		}
	}
	for _, path := range slices.Sorted(maps.Keys(found)) {
		for _, site := range found[path] {
			at := fmt.Sprintf("%s:%d", path, site.line)
			if site.dsn {
				r.dsns++
				r.firstDSN = cmp.Or(r.firstDSN, at)
			} else {
				r.dates++
				r.firstDate = cmp.Or(r.firstDate, at)
			}
		}
	}
	if r.dates > 0 {
		r.found = found
	}
}

// storedTimeFields returns the names of the time.Time fields of the
// project's structs tagged db: timestamps scanned in the session's zone.
func storedTimeFields(files []*core.FileContext) map[string]bool {
	names := make(map[string]bool)
	for _, ctx := range files {
		if !productionGoFile(ctx) {
			continue
		}
		ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
			field, ok := n.(*ast.Field)
			if !ok || field.Tag == nil || !strings.Contains(field.Tag.Value, `db:"`) {
				return true
			}
			typ := field.Type
			if star, ok := typ.(*ast.StarExpr); ok {
				typ = star.X
			}
			if sel, ok := typ.(*ast.SelectorExpr); ok && sel.Sel.Name == "Time" && isIdentNamed(sel.X, "time") {
				for _, name := range field.Names {
					names[name.Name] = true
				}
			}
			return true
		})
	}
	return names
}

// storedTimeDateCuts returns the lines of a file that cut a calendar date
// from a stored timestamp with no UTC() or In(loc): tx.Timestamp.Format("2006-01-02").
// A date only glued into text or printed is left out.
func storedTimeDateCuts(ctx *core.FileContext, stored map[string]bool) []int {
	var lines []int
	parents := helpers.ParentMap(ctx.GoAST)
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		format, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || format.Sel.Name != "Format" || !dateOnlyLayoutSyntax(call.Args[0]) {
			return true
		}
		if field, ok := ast.Unparen(format.X).(*ast.SelectorExpr); ok && stored[field.Sel.Name] && !textOperand(parents, call) {
			lines = append(lines, ctx.GoFileSet.Position(call.Pos()).Line)
		}
		return true
	})
	return lines
}

// textOperand reports an expression glued into a string or handed to fmt or
// a logger, judged by syntax.
func textOperand(parents map[ast.Node]ast.Node, expr ast.Expr) bool {
	switch parent := parents[expr].(type) {
	case *ast.ParenExpr:
		return textOperand(parents, parent)
	case *ast.BinaryExpr:
		return parent.Op == token.ADD
	case *ast.CallExpr:
		if helpers.IsLoggerCall(parent) {
			return true
		}
		// fmt's formatting, a slog attribute (slog.String("day", d)).
		sel, ok := parent.Fun.(*ast.SelectorExpr)
		return ok && (isIdentNamed(sel.X, "fmt") || isIdentNamed(sel.X, "slog"))
	}
	return false
}

// zoneParameter reports the key "timezone" of a connection's runtime
// parameters: RuntimeParams["timezone"] = "UTC".
func zoneParameter(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && strings.EqualFold(lit.Value, `"timezone"`)
}

// ResetState drops the findings of the previous root.
func (r *SQLSessionTimeZoneRule) ResetState() {
	*r = SQLSessionTimeZoneRule{BaseRule: r.BaseRule}
}

// AnalyzeFile reports the connection strings and the session-zone dates of
// a file.
func (r *SQLSessionTimeZoneRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	for _, site := range r.found[ctx.RelPath] {
		if ctx.IsSuppressed(site.line, r.Name()) {
			continue
		}
		if site.dsn {
			violations = append(violations, sqlViolation(r.BaseRule, ctx, site.line,
				fmt.Sprintf("Connection string leaves the session's time zone to the server; statements taking dates in it: %d, the first at %s", r.dates, r.firstDate),
				"Pin the zone in the connection string: timezone=UTC"))
			continue
		}
		violations = append(violations, sqlViolation(r.BaseRule, ctx, site.line,
			fmt.Sprintf("Date taken in the session's time zone, and no connection string pins it (connection strings in the code: %d, the first at %s) — on another zone the same moment falls on another day", r.dsns, r.firstDSN),
			"Pin the zone in the connection string (timezone=UTC), or compare the moment with a bounded range: created_at >= $1 AND created_at < $2"))
	}
	return violations
}
