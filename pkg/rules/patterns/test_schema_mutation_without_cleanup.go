package patterns

import (
	"go/ast"
	"regexp"
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
// Правило требует, чтобы рядом с DDL стояла отмена: t.Cleanup или defer, которые сами
// отправляют SQL в базу. Какой именно запрос там написан, правило не проверяет — важно,
// что автор про возврат схемы подумал; а defer cancel() или t.Cleanup(cancel) схему не
// трогают и отменой не считаются.
type TestSchemaMutationWithoutCleanupRule struct {
	*rules.BaseRule

	// disposable are the functions (package.Name) that hand a test a database
	// of its own: they create it and drop it with t.Cleanup, or call one that
	// does.
	disposable map[string]bool

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

// undoRegistered reports whether the function registers a deferred undo that talks to the
// database: t.Cleanup(...) или defer, внутри которых есть вызов исполнителя SQL. Сам запрос
// не разбирается: его правильность проверяет прогон.
var createDatabase = regexp.MustCompile(`(?i)\bCREATE\s+DATABASE\b`)

// UseProjectFiles finds the helpers that give each test a database of its
// own: a function that runs CREATE DATABASE and registers t.Cleanup, and the
// functions that reach one through calls by name.
func (r *TestSchemaMutationWithoutCleanupRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	calls := make(map[string][]string)
	for _, ctx := range files {
		if !ctx.IsGoFile() || ctx.GoAST == nil {
			continue
		}
		pkg := ctx.GoAST.Name.Name
		for _, decl := range ctx.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			key := pkg + "." + fn.Name.Name
			if createsDatabase(fn.Body) && registersTestCleanup(fn.Body) {
				r.disposable[key] = true
			}
			calls[key] = calledFuncKeys(fn.Body, pkg)
		}
	}
	for changed := true; changed; {
		changed = false
		for key, callees := range calls {
			if r.disposable[key] {
				continue
			}
			for _, callee := range callees {
				if r.disposable[callee] {
					r.disposable[key], changed = true, true
					break
				}
			}
		}
	}
}

// ResetState forgets the helpers of the previous project.
func (r *TestSchemaMutationWithoutCleanupRule) ResetState() {
	r.disposable = make(map[string]bool)
}

// createsDatabase reports a string literal with CREATE DATABASE in the body.
func createsDatabase(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && !found {
			if text, ok := goStringLiteral(lit); ok {
				found = createDatabase.MatchString(text)
			}
		}
		return !found
	})
	return found
}

// registersTestCleanup reports t.Cleanup(...) on a testing handle.
func registersTestCleanup(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && !found {
			sel, ok := call.Fun.(*ast.SelectorExpr)
			found = ok && sel.Sel.Name == "Cleanup" && isTestingHandle(sel.X)
		}
		return !found
	})
	return found
}

// calledFuncKeys returns the package.Name of the plain function calls in the
// body: f() of the same package and pkg.F() of another.
func calledFuncKeys(body *ast.BlockStmt, pkg string) []string {
	var keys []string
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			keys = append(keys, pkg+"."+fun.Name)
		case *ast.SelectorExpr:
			if x, ok := fun.X.(*ast.Ident); ok {
				keys = append(keys, x.Name+"."+fun.Sel.Name)
			}
		}
		return true
	})
	return keys
}

// usesDisposableDatabase reports a test that gets its database from a helper
// that creates one for it.
func (r *TestSchemaMutationWithoutCleanupRule) usesDisposableDatabase(fn *ast.FuncDecl, pkg string) bool {
	for _, key := range calledFuncKeys(fn.Body, pkg) {
		if r.disposable[key] {
			return true
		}
	}
	return false
}

func undoRegistered(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.DeferStmt:
			found = executesSQL(node.Call)
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Cleanup" {
				found = executesSQL(node)
			}
		}
		return !found
	})
	return found
}

// executesSQL reports whether the subtree calls a SQL executor (Exec, ExecContext, …).
func executesSQL(root ast.Node) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && executors[sel.Sel.Name] {
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
			if !ok {
				continue
			}
			value, ok := goStringLiteral(lit)
			if !ok {
				continue
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
	testingPkgs := testingImportNames(ctx.GoAST)

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		switch goTestFuncKind(fn, testingPkgs) {
		case goTestCase, goBenchmark, goFuzz:
		default:
			continue
		}
		lit, sql := r.ddlLiteral(fn)
		if lit == nil || undoRegistered(fn) || r.usesDisposableDatabase(fn, ctx.GoAST.Name.Name) {
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
