package patterns

import (
	"go/ast"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTestSchemaMutationWithoutCleanupRule())
}

// TestSchemaMutationWithoutCleanupRule detects a test that changes the database schema and
// leaves the change behind.
//
// Тестовые базы обычно переиспользуются между прогонами (пул с TRUNCATE, шаблонная база,
// общий контейнер). Строки такой тест за собой чистит, а колонку или таблицу — нет:
// TRUNCATE структуру не трогает. Дальше своя же колонка ломает следующий прогон
// («column already exists»), а чужие тесты получают базу, не совпадающую со схемой из
// миграций, и падают в стороне от причины.
//
// Правило требует, чтобы рядом с DDL стояла отмена: t.Cleanup или defer. Что именно там
// написано, правило не проверяет — важно, что автор про возврат схемы подумал.
type TestSchemaMutationWithoutCleanupRule struct {
	*rules.BaseRule

	ddl           *regexp.Regexp
	sessionScoped *regexp.Regexp
}

// NewTestSchemaMutationWithoutCleanupRule creates the rule.
func NewTestSchemaMutationWithoutCleanupRule() *TestSchemaMutationWithoutCleanupRule {
	return &TestSchemaMutationWithoutCleanupRule{
		BaseRule: rules.NewBaseRule(
			"test-schema-mutation-without-cleanup",
			"patterns",
			"Detects a test that alters the database schema without undoing the change",
			core.SeverityHigh,
		),
		ddl: regexp.MustCompile(`(?is)\b(?:alter\s+table\b|drop\s+table\b|create\s+(?:unlogged\s+)?table\b|create\s+(?:unique\s+)?index\b|drop\s+index\b|alter\s+type\b)`),
		// CREATE TEMP/TEMPORARY живёт до конца сессии и общую базу не портит
		sessionScoped: regexp.MustCompile(`(?is)\bcreate\s+(?:global\s+|local\s+)?(?:temp|temporary|unlogged\s+temp)\b`),
	}
}

// undoRegistered reports whether the function registers any deferred undo: t.Cleanup(...) или
// defer. Содержимое не разбирается: наличие отмены — уже решение автора, а её правильность
// проверяет сам прогон.
func undoRegistered(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.DeferStmt:
			found = true
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Cleanup" {
				found = true
			}
		}
		return !found
	})
	return found
}

// executors — методы, которые действительно отправляют запрос в базу. Смотреть на любой
// строковый литерал нельзя: security-тесты держат «'; DROP TABLE users; --» как полезную
// нагрузку инъекции, и такая строка до базы не доезжает.
var executors = map[string]bool{
	"Exec": true, "ExecContext": true, "MustExec": true, "MustExecContext": true,
	"Query": true, "QueryContext": true, "QueryRow": true, "QueryRowContext": true,
	"Select": true, "Get": true,
}

// ddlLiteral returns the first schema-changing SQL literal the function actually executes.
func (r *TestSchemaMutationWithoutCleanupRule) ddlLiteral(fn *ast.FuncDecl) (node ast.Node, text string) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if node != nil {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !executors[sel.Sel.Name] {
			return true
		}
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind.String() != "STRING" {
				continue
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				value = lit.Value
			}
			if r.ddl.MatchString(value) && !r.sessionScoped.MatchString(value) {
				node, text = lit, value
				return false
			}
		}
		return true
	})
	return node, text
}

// AnalyzeFile reports test functions that run DDL with no undo registered.
func (r *TestSchemaMutationWithoutCleanupRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil {
			continue
		}
		if !strings.HasPrefix(fn.Name.Name, "Test") && !strings.HasPrefix(fn.Name.Name, "Benchmark") {
			continue
		}
		lit, sql := r.ddlLiteral(fn)
		if lit == nil || undoRegistered(fn) {
			continue
		}
		line := ctx.LineFor(lit)
		v := r.CreateViolation(ctx.RelPath, line,
			"Test '"+fn.Name.Name+"' changes the database schema and never undoes it — the next run reuses the same database and hits the leftover")
		v.WithCode(strings.TrimSpace(collapseSQL(sql)))
		v.WithSuggestion("Register the reverse statement with t.Cleanup right after the change, so the database goes back to the schema the migrations describe")
		v.WithContext("pattern", "test_schema_mutation_without_cleanup")
		violations = append(violations, v)
	}
	return violations
}

// collapseSQL squeezes a multi-line statement into one line for the report.
func collapseSQL(sql string) string {
	return strings.Join(strings.Fields(sql), " ")
}
