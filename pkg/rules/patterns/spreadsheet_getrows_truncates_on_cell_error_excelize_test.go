package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func excelizeRuleFiles(source string) map[string]string {
	return map[string]string{
		"go.mod": `module example.com/sheet

go 1.24

require github.com/xuri/excelize/v2 v2.0.0
replace github.com/xuri/excelize/v2 => ./third_party/excelize
`,
		"third_party/excelize/go.mod": "module github.com/xuri/excelize/v2\n\ngo 1.24\n",
		"third_party/excelize/excelize.go": `package excelize

type File struct{}
type Options struct{}
type Rows struct{}

func (*File) GetRows(string, Options) ([][]string, error) { return nil, nil }
func (*File) GetCellValue(string, string, Options) (string, error) { return "", nil }
func (*File) Rows(string) (*Rows, error) { return nil, nil }
func (*Rows) Next() bool { return false }
func (*Rows) Columns() ([]string, error) { return nil, nil }
func (*Rows) Error() error { return nil }
func (*Rows) Close() error { return nil }
`,
		"sheet/sheet.go": source,
	}
}

func TestSpreadsheetGetRowsTruncatesOnCellErrorReportsAssignedResult(t *testing.T) {
	violations := runRuleOnFiles(t, NewSpreadsheetGetRowsTruncatesOnCellErrorRule(), excelizeRuleFiles(`package sheet

import "github.com/xuri/excelize/v2"

func Read(book *excelize.File, name string) ([][]string, error) {
	rows, err := book.GetRows(name, excelize.Options{})
	if err != nil { return nil, err }
	return rows, nil
}
`))

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
}

func TestSpreadsheetGetRowsTruncatesOnCellErrorReportsDirectResult(t *testing.T) {
	violations := runRuleOnFiles(t, NewSpreadsheetGetRowsTruncatesOnCellErrorRule(), excelizeRuleFiles(`package sheet

import "github.com/xuri/excelize/v2"

func Read(book *excelize.File, name string) ([][]string, error) {
	return book.GetRows(name, excelize.Options{})
}
`))

	require.Len(t, violations, 1)
}

func TestSpreadsheetGetRowsTruncatesOnCellErrorAllowsCellReadCheck(t *testing.T) {
	violations := runRuleOnFiles(t, NewSpreadsheetGetRowsTruncatesOnCellErrorRule(), excelizeRuleFiles(`package sheet

import "github.com/xuri/excelize/v2"

func Read(book *excelize.File, name string) ([][]string, error) {
	rows, err := book.GetRows(name, excelize.Options{})
	if err != nil { return nil, err }
	if _, err := book.GetCellValue(name, "A1", excelize.Options{}); err != nil { return nil, err }
	return rows, nil
}
`))

	assert.Empty(t, violations)
}

func TestSpreadsheetGetRowsTruncatesOnCellErrorAllowsCheckedIterator(t *testing.T) {
	violations := runRuleOnFiles(t, NewSpreadsheetGetRowsTruncatesOnCellErrorRule(), excelizeRuleFiles(`package sheet

import "github.com/xuri/excelize/v2"

func Read(book *excelize.File, name string) ([][]string, error) {
	rows, err := book.Rows(name)
	if err != nil { return nil, err }
	defer rows.Close()
	var result [][]string
	for rows.Next() {
		cols, err := rows.Columns()
		if err != nil { return nil, err }
		result = append(result, cols)
	}
	if err := rows.Error(); err != nil { return nil, err }
	return result, nil
}
`))

	assert.Empty(t, violations)
}

func TestSpreadsheetGetRowsTruncatesOnCellErrorAllowsCellCheckInCallee(t *testing.T) {
	violations := runRuleOnFiles(t, NewSpreadsheetGetRowsTruncatesOnCellErrorRule(), excelizeRuleFiles(`package sheet

import "github.com/xuri/excelize/v2"

func Read(book *excelize.File, name string) ([][]string, error) {
	rows, err := book.GetRows(name, excelize.Options{})
	if err != nil { return nil, err }
	if err := checkCells(book, name, rows); err != nil { return nil, err }
	return rows, nil
}

func checkCells(book *excelize.File, name string, rows [][]string) error {
	for range rows {
		if _, err := book.GetCellValue(name, "A1", excelize.Options{}); err != nil { return err }
	}
	return nil
}
`))

	assert.Empty(t, violations)
}

func TestSpreadsheetGetRowsTruncatesOnCellErrorReportsCalleeWithoutCellRead(t *testing.T) {
	violations := runRuleOnFiles(t, NewSpreadsheetGetRowsTruncatesOnCellErrorRule(), excelizeRuleFiles(`package sheet

import "github.com/xuri/excelize/v2"

func Read(book *excelize.File, name string) ([][]string, error) {
	rows, err := book.GetRows(name, excelize.Options{})
	if err != nil { return nil, err }
	trimRows(rows)
	return rows, nil
}

func trimRows(rows [][]string) {}
`))

	require.Len(t, violations, 1)
}
