package dbrules

import (
	"go/ast"
	"go/constant"
	"go/token"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() { rules.Register(NewGoFilterCopiesSQLPredicateRule()) }

// GoFilterCopiesSQLPredicateRule detects Go filters that repeat SQL predicates.
type GoFilterCopiesSQLPredicateRule struct {
	*rules.BaseRule
	predicates map[string][]predicateConstant
	sources    []sqlPredicateSource
	constants  map[string]string
	columns    map[string]string
}

// NewGoFilterCopiesSQLPredicateRule creates the Go filter duplication rule.
func NewGoFilterCopiesSQLPredicateRule() *GoFilterCopiesSQLPredicateRule {
	return &GoFilterCopiesSQLPredicateRule{BaseRule: rules.NewBaseRule("go-filter-copies-sql-predicate", "duplication", "Detects Go filters that repeat a project's SQL predicate", core.SeverityMedium)}
}

// UseProjectFiles indexes SQL predicate sources and Go field metadata.
func (r *GoFilterCopiesSQLPredicateRule) UseProjectFiles(files []*core.FileContext) {
	values := collectGoConstantValues(files)
	collectGoStringValues(values, files)
	r.predicates = collectSQLPredicateIndex(files, values)
	r.sources = sqlPredicateSources(r.predicates)
	r.constants = collectGoConstantValues(files)
	r.columns = collectDBColumns(files)
}

// ResetState drops the index from the previous project root.
func (r *GoFilterCopiesSQLPredicateRule) ResetState() {
	r.predicates = nil
	r.sources = nil
	r.constants = nil
	r.columns = nil
}

// AnalyzeFile reports Go conditions that repeat a project's SQL predicate.
func (r *GoFilterCopiesSQLPredicateRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !patternkit.ProductionGoFile(ctx) || ctx.GoAST == nil {
		return nil
	}
	var violations []*core.Violation
	inspect := func(expr ast.Expr) {
		terms := make([]goSQLTerm, 0)
		var variable string
		if !collectGoSQLTerms(expr, &variable, r.constants, r.columns, &terms) || len(terms) < 2 {
			return
		}
		conditions := make(map[string]bool, len(terms))
		for _, term := range terms {
			conditions[term.norm] = true
		}
		var best *sqlPredicateSource
		for _, source := range r.sources {
			if source.path == ctx.RelPath || len(source.norms) < 2 {
				continue
			}
			match := true
			for norm := range source.norms {
				if !conditions[norm] {
					match = false
					break
				}
			}
			if match {
				if best == nil || len(source.norms) > len(best.norms) || len(source.norms) == len(best.norms) && source.name < best.name {
					candidate := source
					best = &candidate
				}
			}
		}
		if best == nil {
			return
		}
		source := *best
		line := ctx.LineFor(expr)
		if ctx.IsSuppressed(line, r.Name()) {
			return
		}
		violations = append(violations, r.CreateViolation(ctx.RelPath, line, "This filter repeats the SQL predicate "+source.name+" ("+source.path+":"+strconv.Itoa(source.line)+") in Go — filter in the query or derive the check from one definition"))
	}
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch x := node.(type) {
			case *ast.IfStmt:
				inspect(x.Cond)
			case *ast.ReturnStmt:
				for _, result := range x.Results {
					inspect(result)
				}
			}
			return true
		})
	}
	return violations
}

type goSQLTerm struct{ norm string }

func collectGoSQLTerms(expr ast.Expr, variable *string, constants, columns map[string]string, terms *[]goSQLTerm) bool {
	if chain, ok := expr.(*ast.BinaryExpr); ok && chain.Op == token.LAND {
		return collectGoSQLTerms(chain.X, variable, constants, columns, terms) && collectGoSQLTerms(chain.Y, variable, constants, columns, terms)
	}
	comparison, ok := expr.(*ast.BinaryExpr)
	if !ok || comparison.Op != token.EQL && comparison.Op != token.NEQ {
		return true
	}
	selector, ok := comparison.X.(*ast.SelectorExpr)
	if !ok {
		return true
	}
	object, ok := selector.X.(*ast.Ident)
	if !ok {
		return true
	}
	if *variable == "" {
		*variable = object.Name
	} else if *variable != object.Name {
		return false
	}
	value, ok := scalarGoValue(comparison.Y, constants)
	if !ok {
		return true
	}
	column := columns[selector.Sel.Name]
	if column == "" {
		column = strings.Join(patternkit.IdentifierWords(selector.Sel.Name), "_")
	}
	norm := normalizeGoSQLComparison(column, comparison.Op, value)
	if norm != "" {
		*terms = append(*terms, goSQLTerm{norm: norm})
	}
	return true
}

func scalarGoValue(expr ast.Expr, constants map[string]string) (string, bool) {
	switch x := expr.(type) {
	case *ast.BasicLit:
		v := constant.MakeFromLiteral(x.Value, x.Kind, 0)
		if v.Kind() == constant.Unknown {
			return "", false
		}
		if v.Kind() == constant.String {
			return "'" + strings.ReplaceAll(constant.StringVal(v), "'", "''") + "'", true
		}
		return v.ExactString(), true
	case *ast.Ident:
		value, ok := constants[x.Name]
		if !ok {
			return "", false
		}
		if _, err := strconv.ParseInt(value, 0, 64); err == nil {
			return value, true
		}
		return "'" + strings.ReplaceAll(value, "'", "''") + "'", true
	}
	return "", false
}

func collectDBColumns(files []*core.FileContext) map[string]string {
	columns := make(map[string]string)
	for _, ctx := range files {
		if ctx.GoAST == nil || !patternkit.ProductionGoFile(ctx) {
			continue
		}
		ast.Inspect(ctx.GoAST, func(node ast.Node) bool {
			field, ok := node.(*ast.Field)
			if !ok || field.Tag == nil {
				return true
			}
			dbColumns := helpers.TagKeys(helpers.FieldTag(field), []string{"db"})
			if len(dbColumns) == 0 {
				return true
			}
			column := dbColumns[0]
			for _, name := range field.Names {
				columns[name.Name] = strings.ToLower(column)
			}
			return true
		})
	}
	return columns
}
