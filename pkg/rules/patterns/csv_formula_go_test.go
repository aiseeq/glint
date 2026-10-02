package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// encoding/csv quotes a cell but leaves a leading = alone: an account named
// =HYPERLINK(...) runs as a formula when the export is opened.
func TestCSVFormulaInjectionGoExport(t *testing.T) {
	file := rulestest.GoFile(t, "report/export.go", `package report

import (
	"encoding/csv"
	"strconv"
)

type Line struct {
	AccountName string
	Description string
	Amount      int
}

func summaryRows(owner string, l Line) [][]string {
	return [][]string{{"Report"}, {"Account", l.AccountName}, {"Count", strconv.Itoa(l.Amount)}}
}

func write(w *csv.Writer, lines []Line) error {
	for _, l := range lines {
		row := []string{l.Description, strconv.Itoa(l.Amount)}
		if err := w.Write(row); err != nil {
			return err
		}
		safe := []string{cell(l.AccountName), strconv.Itoa(l.Amount)}
		if err := w.Write(safe); err != nil {
			return err
		}
	}
	return nil
}

func cell(v string) string { return v }

func writeSummary(w *csv.Writer, l Line) error {
	return w.WriteAll(summaryRows("x", l))
}

type sheetCell struct {
	value string
	kind  int
}

func workbook(l Line) []sheetCell {
	return []sheetCell{{l.AccountName, 1}, {l.Description, 2}}
}

func writeSafe(w *csv.Writer, row []string) error {
	return w.Write(row)
}

func export(w *csv.Writer, l Line) error {
	rec := []string{l.AccountName}
	return writeSafe(w, rec)
}
`)
	assert.Equal(t, []string{"report/export.go:15", "report/export.go:20"},
		foundLines(NewCSVFormulaInjectionRule().AnalyzeFile(file)))
}
