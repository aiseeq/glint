package frontendrules

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// analyzeGo reports the CSV rows of a Go file that reach an encoding/csv
// Write or WriteAll as they are, with a free-text field in a cell: the writer
// quotes it and keeps a leading =, which the spreadsheet runs as a formula. A
// row handed to a helper of the project is left to that helper.
func (r *CSVFormulaInjectionRule) analyzeGo(ctx *core.FileContext) []*core.Violation {
	if !patternkit.ImportsPackage(ctx.GoAST, "encoding/csv") {
		return nil
	}
	sources := patternkit.RowSources(ctx.GoAST)
	var violations []*core.Violation
	reported := make(map[int]bool)
	report := func(row *ast.CompositeLit) {
		for _, elt := range row.Elts {
			name := patternkit.RawFieldName(elt)
			if !patternkit.CsvTextField.MatchString(name) {
				continue
			}
			line := ctx.LineFor(row)
			if reported[line] || ctx.IsSuppressed(line, r.Name()) {
				return
			}
			reported[line] = true
			violations = patternkit.JsReport(violations, r.BaseRule, ctx, line,
				"CSV cell takes "+name+" as is — encoding/csv quotes it but keeps a leading =, +, - or @, and the spreadsheet runs it as a formula",
				"Prefix a cell that starts with =, +, -, @, tab or CR with a single quote before writing it")
			return
		}
	}
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		for _, lit := range patternkit.RawRows(fn, sources[fn.Name.Name]) {
			for _, row := range patternkit.CsvRows(lit) {
				report(row)
			}
		}
	}
	return violations
}
