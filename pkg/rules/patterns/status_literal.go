package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewStatusLiteralRule())
}

// StatusLiteralRule detects a status written as a string literal in a project
// that declares its statuses as constants of a string type (type
// LedgerStatus string):
//
//	confirmedStatus := "confirmed" // the ledger's statuses say "completed"
//	entry.Status = &confirmedStatus
//
//	count := repo.Count(ctx, "confirmed", "withdrawal")
//
// A literal does not follow a constant that is renamed, and it does not say
// which set it belongs to: "confirmed" is a deposit status, and written into
// the ledger it makes every sum over completed entries miss the row. A status
// is a literal assigned to, compared with or switched on a name ending in
// status, a key or element of a set named ...statuses, an argument of a
// parameter named status, a result of a function whose name says Status. Only
// a value some status constant has is reported: other values are a
// provider's statuses or labels, not a member of the project's sets.
type StatusLiteralRule struct {
	*rules.BaseRule
}

// NewStatusLiteralRule creates the rule
func NewStatusLiteralRule() *StatusLiteralRule {
	return &StatusLiteralRule{BaseRule: rules.NewBaseRule(
		"status-literal",
		"patterns",
		"Detects a status written as a string literal where the project declares its statuses as constants — the literal drifts from the set",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the status constants are known only from the whole project.
func (r *StatusLiteralRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *StatusLiteralRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the status literals.
func (r *StatusLiteralRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	constants := statusConstants(ctx)
	if len(constants) == 0 {
		return nil, nil
	}
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		if fileCtx.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		byLine := make(map[int][]string)
		var lines []int
		for _, lit := range statusLiterals(fileCtx.GoAST, info) {
			value, _ := goStringLiteral(lit)
			if len(constants[value]) == 0 {
				continue // a value no status constant has: a provider's status, a label
			}
			line := fileCtx.LineFor(lit)
			if len(byLine[line]) == 0 {
				lines = append(lines, line)
			}
			byLine[line] = append(byLine[line], value)
		}
		sort.Ints(lines)
		for _, line := range lines {
			if fileCtx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(fileCtx.RelPath, line, statusLiteralMessage(byLine[line], constants))
			v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
			v.WithSuggestion("Use the constant of the status set the value belongs to (string(models.XStatusDone) where a string is needed)")
			violations = append(violations, v)
		}
		return violations
	})
}

// statusLiteralMessage names the literals of a line and the constants that
// have their values.
func statusLiteralMessage(values []string, constants map[string][]string) string {
	named := make([]string, 0, len(values))
	for _, value := range values {
		named = append(named, fmt.Sprintf("%q (%s)", value, strings.Join(constants[value], ", ")))
	}
	return "Status written as a literal: " + strings.Join(named, ", ") + " — the literal does not follow the constant and does not say which status set it belongs to"
}

// statusConstants maps each value of a status constant — a string constant
// declared with a type whose name ends in Status — to the constants that have
// it. The declarations are read from the syntax, so that a package that does
// not compile still lends its constants.
func statusConstants(ctx *core.GoProjectContext) map[string][]string {
	constants := make(map[string][]string)
	for _, fileCtx := range ctx.Files {
		if fileCtx == nil || fileCtx.GoAST == nil || fileCtx.IsTestFile() {
			continue
		}
		for _, decl := range fileCtx.GoAST.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || !strings.HasSuffix(exprName(vs.Type), "Status") || len(vs.Names) != len(vs.Values) {
					continue
				}
				for i, name := range vs.Names {
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok {
						continue
					}
					if value, ok := goStringLiteral(lit); ok {
						constants[value] = append(constants[value], name.Name)
					}
				}
			}
		}
	}
	for value, names := range constants {
		sort.Strings(names)
		constants[value] = slices.Compact(names)
	}
	return constants
}

// statusLiterals returns the string literals of a file that stand for a status.
func statusLiterals(file *ast.File, info *types.Info) []*ast.BasicLit {
	c := &statusCollector{info: info}
	ast.Inspect(file, c.visit)
	for _, fn := range c.funcs {
		c.addResults(fn)
	}
	return c.found
}

// statusCollector gathers the status literals of a file.
type statusCollector struct {
	info  *types.Info
	found []*ast.BasicLit
	funcs []*ast.FuncDecl
}

func (c *statusCollector) add(expr ast.Expr) {
	if lit, ok := ast.Unparen(expr).(*ast.BasicLit); ok && lit.Kind == token.STRING {
		c.found = append(c.found, lit)
	}
}

// addSet adds the members of a set literal: the keys of a map, the elements
// of a list.
func (c *statusCollector) addSet(expr ast.Expr) {
	composite, ok := ast.Unparen(expr).(*ast.CompositeLit)
	if !ok {
		return
	}
	for _, elt := range composite.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			c.add(kv.Key)
			continue
		}
		c.add(elt)
	}
}

func (c *statusCollector) visit(n ast.Node) bool {
	switch n := n.(type) {
	case *ast.FuncDecl:
		c.funcs = append(c.funcs, n)
	case *ast.AssignStmt:
		if len(n.Lhs) == len(n.Rhs) {
			for i, lhs := range n.Lhs {
				c.addTarget(lhs, n.Rhs[i])
			}
		}
	case *ast.ValueSpec:
		if len(n.Names) == len(n.Values) {
			for i, name := range n.Names {
				c.addTarget(name, n.Values[i])
			}
		}
	case *ast.KeyValueExpr:
		if key, ok := n.Key.(*ast.Ident); ok && statusName(key.Name) {
			c.add(n.Value)
		}
	case *ast.BinaryExpr:
		if n.Op == token.EQL || n.Op == token.NEQ {
			if statusExpr(n.X) {
				c.add(n.Y)
			}
			if statusExpr(n.Y) {
				c.add(n.X)
			}
		}
	case *ast.SwitchStmt:
		if n.Tag != nil && statusExpr(n.Tag) {
			for _, stmt := range n.Body.List {
				if clause, ok := stmt.(*ast.CaseClause); ok {
					for _, expr := range clause.List {
						c.add(expr)
					}
				}
			}
		}
	case *ast.CallExpr:
		c.addArguments(n)
	}
	return true
}

// addArguments adds the literals passed to a parameter named status; the
// names are known only with types.
func (c *statusCollector) addArguments(call *ast.CallExpr) {
	if c.info == nil {
		return
	}
	sig, ok := c.info.TypeOf(call.Fun).(*types.Signature)
	if !ok {
		return
	}
	params := sig.Params()
	for i, arg := range call.Args {
		if i < params.Len() && (!sig.Variadic() || i < params.Len()-1) && statusName(params.At(i).Name()) {
			c.add(arg)
		}
	}
}

// addResults adds the literals a function whose name says Status returns.
func (c *statusCollector) addResults(fn *ast.FuncDecl) {
	if fn.Body == nil || !strings.Contains(fn.Name.Name, "Status") || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if ret, ok := n.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
			c.add(ret.Results[0])
		}
		return true
	})
}

// addTarget adds the literal assigned to a status name, or the members of
// a set assigned to a name of statuses.
func (c *statusCollector) addTarget(lhs, rhs ast.Expr) {
	name := exprName(lhs)
	switch {
	case statusName(name):
		c.add(rhs)
	case strings.HasSuffix(strings.ToLower(name), "statuses"):
		c.addSet(rhs)
	}
}

// statusExpr is a status name, possibly converted or case-folded:
// o.Status, string(o.Status), strings.ToLower(status).
func statusExpr(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) == 1 {
		return statusExpr(call.Args[0])
	}
	return statusName(exprName(expr))
}

func exprName(expr ast.Expr) string {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.StarExpr:
		return exprName(e.X)
	}
	return ""
}

func statusName(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), "status")
}
