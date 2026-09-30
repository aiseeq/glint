package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"strconv"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSQLLiteralCopiesConstantRule())
}

// SQLLiteralCopiesConstantRule detects an identifier (a UUID) written into
// SQL text that a Go constant of the project already holds:
//
//	const SystemUserID = "00000000-0000-0000-0000-000000000001"
//	... AND user_id NOT IN ('00000000-0000-0000-0000-000000000001', ...)
//
// The query keeps a copy of the constant: when the constant changes or a
// sibling is added, the query still filters by the old list. Pass the
// constant as a parameter (user_id <> ALL($1)).
type SQLLiteralCopiesConstantRule struct {
	*rules.BaseRule
	// constants maps a UUID value to the constant holding it, "Name
	// (path:line)", over the production Go files of the root.
	constants map[string]string
}

// NewSQLLiteralCopiesConstantRule creates the rule
func NewSQLLiteralCopiesConstantRule() *SQLLiteralCopiesConstantRule {
	return &SQLLiteralCopiesConstantRule{BaseRule: rules.NewBaseRule(
		"sql-literal-copies-constant",
		"patterns",
		"Detects a UUID written into SQL text that a Go constant already holds — the query keeps a copy that drifts",
		core.SeverityMedium,
	)}
}

var uuidText = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// UseProjectFiles indexes the UUID constants of the root.
func (r *SQLLiteralCopiesConstantRule) UseProjectFiles(files []*core.FileContext) {
	r.constants = make(map[string]string)
	for _, ctx := range files {
		if !productionGoFile(ctx) {
			continue
		}
		for _, decl := range ctx.GoAST.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, value := range vs.Values {
					lit, ok := value.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING || i >= len(vs.Names) {
						continue
					}
					text, err := strconv.Unquote(lit.Value)
					if err != nil || !uuidText.MatchString(text) || len(text) != 36 {
						continue
					}
					if _, seen := r.constants[text]; !seen {
						r.constants[text] = fmt.Sprintf("%s (%s:%d)", vs.Names[i].Name, ctx.RelPath, ctx.LineFor(lit))
					}
				}
			}
		}
	}
}

// ResetState drops the constants of the previous root.
func (r *SQLLiteralCopiesConstantRule) ResetState() { r.constants = nil }

// AnalyzeFile reports the UUIDs of a file's SQL that copy a constant.
func (r *SQLLiteralCopiesConstantRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if len(r.constants) == 0 || !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, literal := range sqlLiterals(ctx.GoAST) {
		for _, loc := range uuidText.FindAllStringIndex(literal.text, -1) {
			constant, ok := r.constants[literal.text[loc[0]:loc[1]]]
			if !ok {
				continue
			}
			line := literal.lineAt(ctx, loc[0])
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"SQL text copies the value of the constant "+constant+" — the query keeps its own copy, which stays behind when the constant changes",
				"Pass the constant as a query parameter (user_id <> ALL($1) with the list of constants)"))
		}
	}
	return violations
}
