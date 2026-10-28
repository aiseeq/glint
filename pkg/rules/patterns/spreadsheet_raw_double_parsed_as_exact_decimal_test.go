package patterns

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestSpreadsheetRawDoubleParsedAsExactDecimalDetectsReturnedRows(t *testing.T) {
	assert.Equal(t, []string{"sheet/read.go:8"}, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(book *excelize.File) [][]string {
	shown, _ := book.GetRows("Data")
	rows, _ := book.GetRows("Data", excelize.Options{RawCellValue: true})
	shown[1][2] = rows[1][2]
	_ = decimal.RequireFromString("1")
	return shown
}
func parse(value string) { _ = decimal.RequireFromString(value) }
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalDetectsRiskyFlows(t *testing.T) {
	assert.ElementsMatch(t, []string{"sheet/read.go:7", "sheet/read.go:13", "sheet/read.go:18"}, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func readForHelper(book *excelize.File) {
	value, _ := book.GetCellValue("Data", "A1", excelize.Options{RawCellValue: true})
	parseWrapper(value)
}
func parseValue(value string) { _ = decimal.RequireFromString(value) }
func parseWrapper(value string) { parseValue(value) }
func readForParse(book *excelize.File) {
	value, _ := book.GetCellValue("Data", "A1", excelize.Options{RawCellValue: true})
	_, _ = decimal.NewFromString(value)
}
func readForRows(book *excelize.File) [][]string {
	shown, _ := book.GetRows("Data")
	stored, _ := book.GetRows("Data", excelize.Options{RawCellValue: true})
	shown[1][2] = stored[1][2]
	return shown
}
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalIgnoresNonRiskyReads(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func open(book *excelize.File) { _, _ = excelize.OpenFile("data.xlsx", excelize.Options{RawCellValue: true}) }
func probe(book *excelize.File) {
	_, err := book.GetCellValue("Data", "A1", excelize.Options{RawCellValue: true})
	_ = err
}
func parseSomewhere() { _ = decimal.RequireFromString("1") }
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalIsPackageScopedAndNeedsRiskyFlow(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import "github.com/xuri/excelize/v2"
func checkHeader(book *excelize.File) {
	rows, _ := book.GetRows("Data", excelize.Options{RawCellValue: true})
	_ = matchesHeader(rows[0][0])
}
func matchesHeader(value string) bool { return value == "Amount" }
`,
		"finance/parse.go": `package finance
import "github.com/shopspring/decimal"
func parse(value string) { _ = decimal.RequireFromString(value) }
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalDetectsDecimalConsumerFlow(t *testing.T) {
	assert.Equal(t, []string{"sheet/read.go:8"}, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func consume(value string) { _, _ = decimal.NewFromString(value) }
func read(book *excelize.File) {
	value, _ := book.GetCellValue("Data", "A1", excelize.Options{RawCellValue: true})
	consume(value)
}
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalIgnoresNormalizedValues(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"strconv"
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func normalize(value string) string {
	n, _ := strconv.ParseFloat(value, 64)
	return strconv.FormatFloat(n, 'G', 15, 64)
}

func read(book *excelize.File) {
	rows, _ := book.GetRows("Data", excelize.Options{RawCellValue: true})
	_ = normalize(rows[0][0])
	_ = decimal.RequireFromString("1")
}
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalGetCellTypeIsNormalization(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"strconv"
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(book *excelize.File) {
	value, _ := book.GetCellValue("Data", "A1", excelize.Options{RawCellValue: true})
	_, _ = book.GetCellType("Data", "A1")
	_ = decimal.RequireFromString(value)
	n, _ := strconv.ParseFloat(value, 64)
	text := strconv.FormatFloat(n, 'G', 15, 64)
	_ = decimal.RequireFromString(text)
}
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalFMinusOneIsNotNormalization(t *testing.T) {
	assert.Equal(t, []string{"sheet/read.go:8"}, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"strconv"
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(book *excelize.File) {
	value, _ := book.GetCellValue("Data", "A1", excelize.Options{RawCellValue: true})
	n, _ := strconv.ParseFloat(value, 64)
	text := strconv.FormatFloat(n, 'f', -1, 64)
	_ = decimal.RequireFromString(text)
}
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalFalseOptionIsSilent(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(book *excelize.File) {
	rows, _ := book.GetRows("Data", excelize.Options{RawCellValue: false})
	_ = decimal.RequireFromString(rows[0][0])
}
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalRecognizesExcelizeReadForms(t *testing.T) {
	assert.Len(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(book *excelize.File) {
	rows, _ := book.GetRows("Data", excelize.Options{RawCellValue: true})
	_ = decimal.RequireFromString(rows[0][0])
	cols, _ := book.GetCols("Data", excelize.Options{RawCellValue: true})
	_ = decimal.RequireFromString(cols[0][0])
	value, _ := book.GetCellValue("Data", "A1", excelize.Options{RawCellValue: true})
	_ = decimal.RequireFromString(value)
	values, _ := new(excelize.Rows).Columns(excelize.Options{RawCellValue: true})
	_ = decimal.RequireFromString(values[0])
}
`,
	}), 4)
}

func spreadsheetFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	all := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n\n" +
			"require (\n github.com/shopspring/decimal v0.0.0\n github.com/xuri/excelize/v2 v2.0.0\n)\n\n" +
			"replace github.com/shopspring/decimal => ./third_party/decimal\n" +
			"replace github.com/xuri/excelize/v2 => ./third_party/excelize\n",
		"third_party/decimal/go.mod":  "module github.com/shopspring/decimal\n\ngo 1.24\n",
		"third_party/excelize/go.mod": "module github.com/xuri/excelize/v2\n\ngo 1.24\n",
		"third_party/excelize/excelize.go": `package excelize

type Options struct { RawCellValue bool }
type CellType int
type File struct{}
type Rows struct{}
func (*File) GetRows(string, ...Options) ([][]string, error) { return nil, nil }
func (*File) GetCols(string, ...Options) ([][]string, error) { return nil, nil }
func (*File) GetCellValue(string, string, ...Options) (string, error) { return "", nil }
func (*File) GetCellType(string, string) (CellType, error) { return 0, nil }
func (*Rows) Columns(...Options) ([]string, error) { return nil, nil }
func OpenFile(string, ...Options) (*File, error) { return nil, nil }
`,
		"third_party/decimal/decimal.go": decimalStub,
	}
	maps.Copy(all, files)
	violations, err := NewSpreadsheetRawDoubleParsedAsExactDecimalRule().AnalyzeGoProject(rulestest.Project(t, all))
	require.NoError(t, err)
	return foundLines(violations)
}
