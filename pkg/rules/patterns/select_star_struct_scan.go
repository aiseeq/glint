package patterns

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSelectStarStructScanRule())
}

// selectStar ловит `SELECT *` и `SELECT alias.*` — начало выборки всех колонок.
var selectStar = regexp.MustCompile(`(?is)\bselect\s+(?:[a-z_][a-z0-9_]*\.)?\*`)

// tableName — имя таблицы сразу после FROM. Скобка означает производную таблицу.
var tableName = regexp.MustCompile(`(?is)^\s*([a-z_][a-z0-9_]*)`)

// SelectStarStructScanRule detects `SELECT *` against a real table in Go SQL literals.
//
// Родилось из SI-410. sqlx без Unsafe() требует, чтобы каждой колонке ответа нашлось поле
// в структуре назначения. Поэтому `SELECT *` привязывает чтение к текущему набору колонок:
// миграция, добавляющая колонку, ломает выборку на рантайме с "missing destination name",
// хотя Go-код не менялся и сборка прошла. Явный список колонок снимает эту связь.
//
// Производные таблицы (`SELECT * FROM (...) t`) правилом не считаются нарушением: там
// звёздочка берёт колонки подзапроса, а их набор задан тут же в коде.
type SelectStarStructScanRule struct {
	*rules.BaseRule
}

// NewSelectStarStructScanRule creates the rule.
func NewSelectStarStructScanRule() *SelectStarStructScanRule {
	return &SelectStarStructScanRule{
		BaseRule: rules.NewBaseRule(
			"select-star-struct-scan",
			"patterns",
			"Detects `SELECT *` against a table in Go SQL literals (a new column breaks the scan at runtime)",
			core.SeverityMedium,
		),
	}
}

// starredTable возвращает имя таблицы, все колонки которой выбирает звёздочка.
// Пустая строка — звёздочки нет либо она относится к производной таблице.
func starredTable(sql string) string {
	loc := selectStar.FindStringIndex(sql)
	if loc == nil {
		return ""
	}
	rest := sql[loc[1]:]
	lower := strings.ToLower(rest)
	// Первый FROM после звёздочки — именно тот, к которому она относится.
	for i := 0; i+4 <= len(lower); i++ {
		if lower[i:i+4] != "from" {
			continue
		}
		if i > 0 && isSQLWordByte(lower[i-1]) {
			continue
		}
		if i+4 < len(lower) && isSQLWordByte(lower[i+4]) {
			continue
		}
		m := tableName.FindStringSubmatch(rest[i+4:])
		if m == nil {
			return "" // производная таблица или подставляемый фрагмент
		}
		return m[1]
	}
	return ""
}

func isSQLWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// AnalyzeFile walks string literals looking for SELECT * over a table.
func (r *SelectStarStructScanRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind.String() != "STRING" {
			return true
		}
		table := starredTable(lit.Value)
		if table == "" {
			return true
		}
		line := lineFromNode(ctx, lit)
		v := r.CreateViolation(ctx.RelPath, line,
			// select-star-struct-scan: safe — the rule's own message text, not a query
			"`SELECT *` from table '"+table+"' — a column added by a migration breaks the scan at runtime")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("List the columns the destination struct actually has, so the query no longer depends on the table's column set")
		v.WithContext("pattern", "select_star_struct_scan")
		v.WithContext("table", table)
		violations = append(violations, v)
		return true
	})
	return violations
}
