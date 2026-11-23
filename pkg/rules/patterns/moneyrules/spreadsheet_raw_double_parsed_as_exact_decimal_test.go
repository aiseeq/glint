package moneyrules

import (
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	project := spreadsheetProject(t, files)
	violations, err := NewSpreadsheetRawDoubleParsedAsExactDecimalRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	return patterntest.FoundLines(violations)
}

func spreadsheetProject(t *testing.T, files map[string]string) *core.GoProjectContext {
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
		"third_party/decimal/decimal.go": patterntest.DecimalStub,
	}
	maps.Copy(all, files)
	return rulestest.Project(t, all)
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalAcceptsPackageNormalizer(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import "github.com/xuri/excelize/v2"
func readRow(rows *excelize.Rows) []string {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	return cells
}
`,
		"sheet/amount.go": `package sheet
import (
	"strconv"
	"github.com/shopspring/decimal"
)
func amount(value string) (decimal.Decimal, error) {
	return decimal.NewFromString(roundedNumber(value))
}
func roundedNumber(value string) string {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil { return value }
	return strconv.FormatFloat(f, 'G', significantDigits, 64)
}
const significantDigits = 15
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalDetectsGridAssertions(t *testing.T) {
	assert.Equal(t, []string{"sheet/read.go:10", "sheet/read.go:17"}, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import "github.com/shopspring/decimal"
type Grid interface { Values() ([][]any, error) }
func read(g Grid) {
	rows, _ := g.Values()
	for _, row := range rows {
		for _, v := range row {
			switch x := v.(type) {
			case float64:
				_ = decimal.NewFromFloat(x)
			}
		}
	}
}
func direct(v any) {
	x, ok := v.(float64)
	if ok { _ = decimal.NewFromFloat(x) }
}
func rounded(v any) {
	x := v.(float64)
	d := decimal.NewFromFloat(x).Round(2)
	_ = d
}
func roundedVariable(v any) {
	x := v.(float64)
	d := decimal.NewFromFloat(x)
	d = d.Round(2)
	_ = d
}
func typedField(v struct{ Amount float64 }) { _ = decimal.NewFromFloat(v.Amount) }
func constant() { _ = decimal.NewFromFloat(2.5) }
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalIgnoresAnyWithoutGridAPI(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import "github.com/shopspring/decimal"
func parse(v any) {
	x := v.(float64)
	_ = decimal.NewFromFloat(x)
}
`,
	}))
}

func TestSpreadsheetRawDoubleParsedAsExactDecimalAcceptsRoundingHelperOfAnotherPackage(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
	"example.com/rulestest/numfmt"
)
func readRow(rows *excelize.Rows) []string {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	return cells
}
func amount(value string) (decimal.Decimal, error) {
	return numfmt.Number(value)
}
func label(value string) (decimal.Decimal, error) {
	return decimal.NewFromString(value)
}
`,
		"numfmt/number.go": `package numfmt
import (
	"strconv"
	"github.com/shopspring/decimal"
)
func Number(value string) (decimal.Decimal, error) {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil { return decimal.Decimal{}, err }
	return decimal.NewFromString(strconv.FormatFloat(f, 'g', 15, 64))
}
`,
	}))
}

func TestSpreadsheetRawDoubleSignificantRoundingInCalledParserIsNormalization(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"strings"
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
const significantDigits = 15
func read(rows *excelize.Rows) {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	_, _ = parseAmount(cells[0])
}
func parseAmount(text string) (decimal.Decimal, error) {
	value, err := decimal.NewFromString(strings.TrimSpace(text))
	if err != nil { return decimal.Decimal{}, err }
	return trimDoubleNoise(value), nil
}
func trimDoubleNoise(value decimal.Decimal) decimal.Decimal {
	digits := value.NumDigits()
	if digits <= significantDigits { return value }
	places := significantDigits - (int(value.Exponent()) + digits)
	return value.Round(int32(places))
}
`,
		"third_party/decimal/decimal.go": spreadsheetDecimalStub(),
	}))
}

func TestSpreadsheetRawDoubleSignificantRoundingInReadFunctionIsNormalization(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
const significantDigits = 15
func read(rows *excelize.Rows) {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	value, _ := decimal.NewFromString(cells[0])
	digits := value.NumDigits()
	if digits > significantDigits {
		places := significantDigits - (int(value.Exponent()) + digits)
		value = value.Round(int32(places))
	}
	_ = value
}
`,
		"third_party/decimal/decimal.go": spreadsheetDecimalStub(),
	}))
}

func TestSpreadsheetRawDoubleSignificantParsingWithoutRoundingStillFinds(t *testing.T) {
	assert.Equal(t, []string{"sheet/read.go:7"}, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(rows *excelize.Rows) {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	_, _ = decimal.NewFromString(cells[0])
}
`,
	}))
}

func TestSpreadsheetRawDoubleSignificantDecimalPlacesAreNotNormalization(t *testing.T) {
	assert.Equal(t, []string{"sheet/read.go:7"}, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(rows *excelize.Rows) {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	value, _ := decimal.NewFromString(cells[0])
	_ = value.Round(2)
}
`,
	}))
}

func TestSpreadsheetRawDoubleSignificantDigitCountWithoutRoundingIsNotNormalization(t *testing.T) {
	assert.Equal(t, []string{"sheet/read.go:7"}, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(rows *excelize.Rows) {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	value, _ := decimal.NewFromString(cells[0])
	_ = value.NumDigits()
}
`,
		"third_party/decimal/decimal.go": spreadsheetDecimalStub(),
	}))
}

func TestSpreadsheetRawDoubleSignificantDirectNumDigitsIsNormalization(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(rows *excelize.Rows) {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	value, _ := decimal.NewFromString(cells[0])
	_ = trimDoubleNoise(value)
}
func trimDoubleNoise(value decimal.Decimal) decimal.Decimal {
	if value.NumDigits() > 15 {
		return value.Round(int32(15 - int(value.Exponent()) - value.NumDigits()))
	}
	return value
}
`,
		"third_party/decimal/decimal.go": spreadsheetDecimalStub(),
	}))
}

func TestSpreadsheetRawDoubleSignificantRoundArgumentMustUseDigitCount(t *testing.T) {
	for name, body := range map[string]string{
		"L1 comparison only": `digits := value.NumDigits()
	if digits > 15 { return decimal.Decimal{}, nil }
	return value.Round(2), nil`,
		"L3 result only": `width := value.NumDigits()
	value.Round(2)
	_ = []int{width + 1}
	return value, nil`,
		"L6 return only": `n := value.NumDigits()
	value.Round(2)
	_ = n <= 12
	return value, nil`,
		"no Round": `digits := value.NumDigits()
	if digits > 15 { return decimal.Decimal{}, nil }
	return value, nil`,
		"unrelated decimal method": `var digits = value.NumDigits()
	value.StringFixed(int32(15 - digits))
	return value, nil`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, []string{"sheet/read.go:7"}, spreadsheetFindings(t, map[string]string{
				"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(rows *excelize.Rows) {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	_, _ = parseAmount(cells[0])
}
func parseAmount(text string) (decimal.Decimal, error) {
	value, _ := decimal.NewFromString(text)
	` + body + `
}
`,
				"third_party/decimal/decimal.go": spreadsheetDecimalStub(),
			}))
		})
	}
}

func TestSpreadsheetRawDoubleSignificantLimitMustNotExceed15(t *testing.T) {
	assert.Equal(t, []string{"sheet/read.go:8"}, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
const significantDigits = 17
func read(rows *excelize.Rows) {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	value, _ := decimal.NewFromString(cells[0])
	_ = value.Round(int32(significantDigits - value.NumDigits()))
}
`,
		"third_party/decimal/decimal.go": spreadsheetDecimalStub(),
	}))
}

func TestSpreadsheetRawDoubleSignificantVarSpecAndReversedLimit(t *testing.T) {
	assert.Empty(t, spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(rows *excelize.Rows) {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	value, _ := decimal.NewFromString(cells[0])
	_ = trimDoubleNoise(value)
}
func trimDoubleNoise(value decimal.Decimal) decimal.Decimal {
	var digits = value.NumDigits()
	if 15 > digits {
		return value.Round(int32(15 - int(value.Exponent()) - digits))
	}
	return value
}
`,
		"third_party/decimal/decimal.go": spreadsheetDecimalStub(),
	}))
}

func TestSpreadsheetRawDoubleSignificantExactFormsNormalize(t *testing.T) {
	for name, body := range map[string]string{
		"real form through variables": `digits := x.NumDigits()
	places := 15 - (int(x.Exponent()) + digits)
	return x.Round(int32(places))`,
		"direct calls":                `return x.Round(int32(15 - (int(x.Exponent()) + x.NumDigits())))`,
		"addition terms reordered":    `return x.Round(int32(15 - (x.NumDigits() + int(x.Exponent()))))`,
		"subtraction terms reordered": `return x.Round(int32(15 - x.NumDigits() - int(x.Exponent())))`,
		"named constant":              `return x.Round(int32(significantDigits - (int(x.Exponent()) + x.NumDigits())))`,
		"RoundBank":                   `return x.RoundBank(int32(15 - (int(x.Exponent()) + x.NumDigits())))`,
		"inner subtraction through a variable": `top := 15 - int(x.Exponent())
	places := top - x.NumDigits()
	return x.Round(int32(places))`,
		"sum through a variable": `magnitude := int(x.Exponent()) + x.NumDigits()
	places := 15 - magnitude
	return x.Round(int32(places))`,
		"chain of five variables": `a := x.NumDigits()
	b := a
	c := b
	d := c
	places := 15 - (int(x.Exponent()) + d)
	return x.Round(int32(places))`,
	} {
		t.Run(name, func(t *testing.T) {
			decls := ""
			if name == "named constant" {
				decls = "const significantDigits = 15\n"
			}
			assert.Empty(t, spreadsheetSignificantRoundFindings(t, decls, body))
		})
	}
}

func TestSpreadsheetRawDoubleSignificantNearMatchesStillFind(t *testing.T) {
	tests := []struct {
		name  string
		decls string
		body  string
	}{
		{name: "Truncate", body: `return x.Truncate(int32(15 - (int(x.Exponent()) + x.NumDigits())))`},
		{name: "RoundFloor", body: `return x.RoundFloor(int32(15 - (int(x.Exponent()) + x.NumDigits())))`},
		{name: "StringFixed", body: `_ = x.StringFixed(int32(15 - (int(x.Exponent()) + x.NumDigits())))
	return x`},
		{name: "extra one", body: `return x.Round(int32(15 - (int(x.Exponent()) + x.NumDigits()) + 1))`},
		{name: "missing exponent", body: `return x.Round(int32(15 - x.NumDigits()))`},
		{name: "different value", body: `scale := decimal.NewFromInt(1)
	return x.Round(int32(15 - (int(scale.Exponent()) + scale.NumDigits())))`},
		{name: "constant 14", body: `return x.Round(int32(14 - (int(x.Exponent()) + x.NumDigits())))`},
		{name: "constant 16", body: `return x.Round(int32(16 - (int(x.Exponent()) + x.NumDigits())))`},
		{name: "variable is not a constant", body: `limit := 15
	return x.Round(int32(limit - (int(x.Exponent()) + x.NumDigits())))`},
		{name: "wrong operator between terms", body: `return x.Round(int32(15 - (int(x.Exponent()) - x.NumDigits())))`},
		{name: "15 minus exponent plus digits", body: `return x.Round(int32(15 - int(x.Exponent()) + x.NumDigits()))`},
		{name: "15 plus exponent minus digits", body: `return x.Round(int32(15 + int(x.Exponent()) - x.NumDigits()))`},
		{name: "min", body: `return x.Round(int32(min(x.NumDigits(), 2)))`},
		{name: "second assignment", body: `places := 15 - (int(x.Exponent()) + x.NumDigits())
	places = 2
	return x.Round(int32(places))`},
		{name: "Round(2) beside digit count", body: `_ = x.NumDigits()
	return x.Round(2)`},
		{name: "digits minus one", body: `return x.Round(int32(x.NumDigits() - 1))`},
		{name: "compound assignment gives no value", body: `var places int32
	places -= int32(15 - (int(x.Exponent()) + x.NumDigits()))
	return x.Round(places)`},
		{name: "remainder", body: `return x.Round(int32(x.NumDigits() % 2))`},
		{name: "digits times two", body: `return x.Round(int32(x.NumDigits() * 2))`},
		{name: "other round receiver", body: `scale := decimal.NewFromInt(1)
	return scale.Round(int32(15 - (int(x.Exponent()) + x.NumDigits())))`},
		{name: "precision four suppresses no package findings", decls: "const significantDigits = 4\n", body: `return x.Round(int32(significantDigits - (int(x.Exponent()) + x.NumDigits())))`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := "sheet/read.go:8"
			if test.name == "precision four suppresses no package findings" {
				want = "sheet/read.go:9"
			}
			assert.Equal(t, []string{want}, spreadsheetSignificantRoundFindings(t, test.decls, test.body))
		})
	}
}

func spreadsheetSignificantRoundFindings(t *testing.T, declarations, roundBody string) []string {
	t.Helper()
	return spreadsheetFindings(t, map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
` + declarations + `
func read(rows *excelize.Rows) {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	value, _ := decimal.NewFromString(cells[0])
	_ = roundAmount(value)
}
func roundAmount(x decimal.Decimal) decimal.Decimal {
	` + roundBody + `
}
`,
		"third_party/decimal/decimal.go": spreadsheetDecimalStub(),
	})
}

func TestSpreadsheetRawDoubleSignificantIncrementedPlacesStillFind(t *testing.T) {
	assert.Equal(t, []string{"sheet/read.go:8"}, spreadsheetSignificantRoundFindings(t, "", `places := 15 - (int(x.Exponent()) + x.NumDigits())
	places++
	return x.Round(int32(places))`))
}

func TestSpreadsheetRawDoubleSignificantRangeAssignedPlacesStillFind(t *testing.T) {
	assert.Equal(t, []string{"sheet/read.go:8"}, spreadsheetSignificantRoundFindings(t, "", `places := 15 - (int(x.Exponent()) + x.NumDigits())
	for places = range []int{2} {}
	return x.Round(int32(places))`))
}

func TestSpreadsheetRawDoubleSignificantLocalConst15IsNormalization(t *testing.T) {
	assert.Empty(t, spreadsheetSignificantRoundFindings(t, "", `const significantDigits = 15
	return x.Round(int32(significantDigits - (int(x.Exponent()) + x.NumDigits())))`))
}

func TestSpreadsheetRawDoubleSignificantExpansionDoesNotBranch(t *testing.T) {
	var chain strings.Builder
	chain.WriteString("v0 := 1\n")
	for i := 1; i <= 10; i++ {
		terms := make([]string, 10)
		for j := range terms {
			terms[j] = fmt.Sprintf("v%d", i-1)
		}
		fmt.Fprintf(&chain, "v%d := %s\n", i, strings.Join(terms, " + "))
	}
	files := map[string]string{
		"sheet/read.go": `package sheet
import (
	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"
)
func read(rows *excelize.Rows) {
	cells, _ := rows.Columns(excelize.Options{RawCellValue: true})
	value, _ := decimal.NewFromString(cells[0])
` + chain.String() + `	_ = value.Round(int32(v10))
}
`,
		"third_party/decimal/decimal.go": spreadsheetDecimalStub(),
	}
	project := spreadsheetProject(t, files)
	start := time.Now()
	violations, err := NewSpreadsheetRawDoubleParsedAsExactDecimalRule().AnalyzeGoProject(project)
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.NotEmpty(t, patterntest.FoundLines(violations))
	t.Logf("rule analysis for k=10 expansion: %s", elapsed)
	assert.Less(t, elapsed, 100*time.Millisecond)
}

func spreadsheetDecimalStub() string {
	return patterntest.DecimalStub + `
func (d Decimal) NumDigits() int { return 1 }
func (d Decimal) Exponent() int32 { return 0 }
`
}
