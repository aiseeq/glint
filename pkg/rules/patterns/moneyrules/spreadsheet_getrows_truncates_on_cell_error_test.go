package moneyrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
)

func TestSpreadsheetGetRowsTruncatesOnCellErrorIgnoresProjectWrapper(t *testing.T) {
	violations := patterntest.RunRuleOnFiles(t, NewSpreadsheetGetRowsTruncatesOnCellErrorRule(), map[string]string{
		"sheet/sheet.go": `package sheet

type Workbook struct{}
func (*Workbook) GetRows(string) ([][]string, error) { return nil, nil }
func Read(book *Workbook, name string) ([][]string, error) {
	return book.GetRows(name)
}
`,
	})

	assert.Empty(t, violations)
}

func TestSpreadsheetGetRowsTruncatesOnCellErrorAllowsCheckedRead(t *testing.T) {
	violations := patterntest.RunRuleOnFiles(t, NewSpreadsheetGetRowsTruncatesOnCellErrorRule(), map[string]string{
		"sheet/sheet.go": `package sheet

type Workbook struct{}
type Options struct{}

func (*Workbook) GetRows(string, Options) ([][]string, error) { return nil, nil }
func (*Workbook) GetCellValue(string, string, Options) (string, error) { return "", nil }

func Read(book *Workbook, name string) ([][]string, error) {
	rows, err := book.GetRows(name, Options{})
	if err != nil { return nil, err }
	if err := checkCells(book, name, rows); err != nil { return nil, err }
	return rows, nil
}

func checkCells(book *Workbook, name string, rows [][]string) error {
	_, err := book.GetCellValue(name, "A1", Options{})
	return err
}
`,
	})

	assert.Empty(t, violations)
}

func TestSpreadsheetGetRowsTruncatesOnCellErrorIgnoresUntypedIterator(t *testing.T) {
	violations := patterntest.RunRuleOnFiles(t, NewSpreadsheetGetRowsTruncatesOnCellErrorRule(), map[string]string{
		"sheet/sheet.go": `package sheet

type Workbook struct{}
type RowIterator struct{}

func (*Workbook) Rows(string) (*RowIterator, error) { return nil, nil }
func (*RowIterator) Next() bool { return false }
func (*RowIterator) Columns() ([]string, error) { return nil, nil }
func (*RowIterator) Error() error { return nil }

func Read(book *Workbook, name string) ([][]string, error) {
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
func (*RowIterator) Close() error { return nil }
`,
	})

	assert.Empty(t, violations)
}

func TestSpreadsheetGetRowsTruncatesOnCellErrorIgnoresOtherMethod(t *testing.T) {
	violations := patterntest.RunRuleOnFiles(t, NewSpreadsheetGetRowsTruncatesOnCellErrorRule(), map[string]string{
		"sheet/sheet.go": `package sheet

type Workbook struct{}
func (*Workbook) GetRows() ([]int, error) { return nil, nil }
func Read(book *Workbook) ([]int, error) { return book.GetRows() }
`,
	})

	assert.Empty(t, violations)
}
