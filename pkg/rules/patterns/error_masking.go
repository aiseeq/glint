package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewErrorMaskingRule())
}

// ErrorMaskingRule detects patterns that mask errors instead of handling them properly
// This implements CLAUDE.md principle: "Fail explicitly, never degrade silently"
type ErrorMaskingRule struct {
	*rules.BaseRule
	goPatterns map[string]*regexp.Regexp
	tsPatterns map[string]*regexp.Regexp
}

// NewErrorMaskingRule creates the rule
func NewErrorMaskingRule() *ErrorMaskingRule {
	r := &ErrorMaskingRule{
		BaseRule: rules.NewBaseRule(
			"error-masking",
			"patterns",
			"Detects patterns that mask errors instead of handling them properly (CLAUDE.md: Fail explicitly, never degrade silently)",
			core.SeverityCritical,
		),
	}
	r.goPatterns = r.initGoPatterns()
	r.tsPatterns = r.initTSPatterns()
	return r
}

// initGoPatterns initializes Go-specific regex patterns
func (r *ErrorMaskingRule) initGoPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		// Explicit masking comments
		"hardcoded_return": regexp.MustCompile(`return\s+(\d+|"[^"]*"|0x[0-9a-fA-F]+)\s*//.*(?i)(default|backup)`),
		"success_masked":   regexp.MustCompile(`return\s+true\s*//.*(?i)(assume)`),

		// NOTE: `if err != nil { ... return ... }` and recover-to-return are
		// handled by AST analysis only: matching per line, such regex would
		// require the whole statement on one line and is dead on gofmt code.

		// NOTE: Switch default is handled by AST analysis only (more precise)
		// Regex would cause false positives on display/suggestion functions

		// Fake/mock data in production
		// The word ends where the value does or at a separator: "testdata" is a
		// directory, "test_user" a made-up value.
		"fake_data_return": regexp.MustCompile(`return\s+"(?:fake|mock|dummy|stub|test)(?:[^a-z"][^"]*)?"`),

		// Zero balance on error
		"zero_on_error": regexp.MustCompile(`(?:buildZero|returnZero|getZero).*(?:error|fail|unavailable)`),
	}
}

// initTSPatterns initializes TypeScript-specific regex patterns
func (r *ErrorMaskingRule) initTSPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		// Environment variable with defaults
		"env_default": regexp.MustCompile(`process\.env\.[A-Z_]+\s*\|\|\s*['"][^'"]+['"]`),

		// Config with defaults
		"config_default": regexp.MustCompile(`config\??\.[a-zA-Z_]+\s*\|\|\s*['"][^'"]+['"]`),

		// Switch default masking
		"switch_default_value": regexp.MustCompile(`default:\s*(?:return\s+(?:['"][^'"]*['"]|true|false|\d+|\[\]|\{\}|null)|break;?\s*$)`),

		// Catch block masking
		"catch_hardcoded_return": regexp.MustCompile(`catch\s*\([^)]*\)\s*\{[^}]*return\s+(?:['"][^'"]*['"]|true|false|\d+|\[\]|\{\}|null)`),

		// Fake signatures
		"fake_signature": regexp.MustCompile(`return\s+['"]0x[0-9a-fA-F]*fake[0-9a-fA-F]*['"]`),

		// Error return empty
		"error_return_empty": regexp.MustCompile(`if\s*\([^)]*error[^)]*\)[^{]*\{[^}]*return\s+(?:null|\[\]|\{\}|"")`),
	}
}

// AnalyzeFile checks for error masking patterns
func (r *ErrorMaskingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if r.shouldSkipFile(ctx) {
		return nil
	}
	// A command package holds CLI tools, whose regex-shaped fallbacks are
	// left alone, and the main package of a server, whose handlers drop
	// errors the same way as any other code: the success-only guard is
	// checked there.
	if isCommandPath(ctx.RelPath) {
		if !ctx.HasGoAST() {
			return nil
		}
		return r.checkSuccessOnlyGuards(ctx)
	}

	return helpers.AnalyzeGoAndFrontend(ctx, r.analyzeGoFile, r.analyzeTSFile)
}

// isCommandPath reports a file of a command package or of an analyzer tool.
func isCommandPath(path string) bool {
	return strings.Contains(path, "/cmd/") || strings.HasPrefix(path, "cmd/") ||
		strings.Contains(path, "/tools/analyzers/") || strings.HasPrefix(path, "tools/analyzers/")
}

// shouldSkipFile checks if file should be excluded
func (r *ErrorMaskingRule) shouldSkipFile(ctx *core.FileContext) bool {
	path := ctx.RelPath

	// Skip test files
	if ctx.IsTestFile() {
		return true
	}

	// Skip vendor, node_modules
	if strings.Contains(path, "vendor/") || strings.Contains(path, "node_modules/") {
		return true
	}

	// Skip generated files
	if strings.Contains(path, "generated") || strings.Contains(path, ".gen.") {
		return true
	}

	// Skip templates
	if strings.Contains(path, "/templates/") {
		return true
	}

	// Skip test helper files (not _test.go but testing utilities)
	if strings.Contains(path, "/testing/") || strings.Contains(path, "test_helper") {
		return true
	}

	// Skip config module files - they contain documented development defaults
	if strings.Contains(path, "/config/") || strings.HasPrefix(path, "config/") {
		return true
	}

	return false
}

// analyzeGoFile analyzes Go file for error masking patterns
func (r *ErrorMaskingRule) analyzeGoFile(ctx *core.FileContext) []*core.Violation {
	violations := r.analyzeGoRegex(ctx)

	// AST-based analysis for more precise detection
	if ctx.HasGoAST() {
		violations = append(violations, r.analyzeGoAST(ctx)...)
	}

	return violations
}

// analyzeGoRegex uses regex patterns for Go files
func (r *ErrorMaskingRule) analyzeGoRegex(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		if r.isCommentOrEmpty(line) {
			continue
		}

		// Skip regex pattern definitions (they contain the patterns we're looking for)
		if r.isRegexPatternDefinition(line) {
			continue
		}

		for _, patternName := range slices.Sorted(maps.Keys(r.goPatterns)) {
			pattern := r.goPatterns[patternName]
			if pattern.MatchString(line) {
				if r.isGoException(ctx.RelPath, line) {
					continue
				}

				v := r.createGoViolation(ctx, lineNum+1, line, patternName)
				violations = append(violations, v)
			}
		}
	}

	return violations
}

// analyzeGoAST uses Go AST for precise detection. Every function is walked
// once with its own signature: the error slot of that signature decides
// whether a return in an error branch hands the error over.
func (r *ErrorMaskingRule) analyzeGoAST(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	forEachFunction(ctx.GoAST, func(name string, ftype *ast.FuncType, body *ast.BlockStmt) {
		// Semantic boolean functions (IsEmpty, HasPermission, CanAccess,
		// ShouldRetry) answer with true/false on error by contract. A closure
		// inherits the name of the declaration around it.
		if isPredicateName(name) {
			return
		}
		forEachOwnStatement(body, func(stmt ast.Stmt) {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				return
			}
			if v := r.checkErrorIfStmt(ctx, ftype.Results, ifStmt); v != nil {
				violations = append(violations, v)
			}
		})
	})

	violations = append(violations, r.checkSuccessOnlyGuards(ctx)...)
	violations = append(violations, analyzeGoFunctions(ctx, func(fn *ast.FuncDecl) []*core.Violation {
		return r.checkSwitchDefaultMember(ctx, fn)
	})...)
	violations = append(violations, r.checkParseHelperDefaults(ctx)...)

	return violations
}

// checkSuccessOnlyGuards finds the "assign on success, say nothing on failure" shape:
//
//	if items, err := repo.List(ctx); err == nil {
//	    out = build(items)
//	}
//
// The guard has no else and err is never looked at again — not returned, not logged —
// so a failed call is indistinguishable from an empty result. That
// is how a broken repository query surfaced as "no operations today" in the balance
// card while the headline kept showing yesterday's snapshot.
func (r *ErrorMaskingRule) checkSuccessOnlyGuards(ctx *core.FileContext) []*core.Violation {
	return analyzeGoFunctions(ctx, func(fn *ast.FuncDecl) []*core.Violation {
		var violations []*core.Violation
		var assigned map[*ast.Ident]bool
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			ifStmt, ok := inner.(*ast.IfStmt)
			if !ok {
				return true
			}
			if assigned == nil {
				assigned = assignedIdents(fn.Body)
			}
			if v := r.checkSuccessOnlyGuard(ctx, fn, ifStmt, assigned); v != nil {
				violations = append(violations, v)
			}
			return true
		})
		return violations
	})
}

func (r *ErrorMaskingRule) checkSuccessOnlyGuard(ctx *core.FileContext, fn *ast.FuncDecl, stmt *ast.IfStmt, assigned map[*ast.Ident]bool) *core.Violation {
	// An else that only logs below Warn is no handling: the line is not
	// seen in production and the target keeps its zero.
	if stmt.Else != nil && !onlyQuietLogs(stmt.Else) {
		return nil
	}
	errName, ok := successGuardErrName(stmt.Cond)
	if !ok {
		return nil
	}
	source, sourceOK := errSourceCall(fn, stmt, errName)
	if !sourceOK {
		return nil
	}
	if !guardBodyOnlyAssigns(stmt.Body) {
		return nil
	}
	// Уточнение готового значения прощается, пока разбирается не запрос
	// клиента: неразобранный параметр запроса — ошибка клиента, и ответ с
	// подставленным значением её прячет.
	sourceCall := errSourceExpr(fn.Body, stmt, errName)
	fromRequest := parsesRequestInput(fn.Body, sourceCall)
	if guardOnlyRefinesReadyValues(fn, stmt) && !fromRequest &&
		!setsFilterParam(fn, stmt) && !keepsDomainPresetOnRead(fn, stmt, sourceCall) {
		return nil
	}
	// err == nil && v > 0 on a parse is a test of the input's shape: a value
	// that does not parse simply is not the one looked for.
	if len(flattenAnd(stmt.Cond)) > 1 && isParseCall(sourceCall) && !fromRequest {
		return nil
	}
	if errUsedElsewhere(fn, stmt, errName, assigned) {
		return nil
	}

	pos := ctx.PositionFor(stmt)
	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"Result of "+source+" is used only on success: the error is dropped and the caller cannot tell failure from empty data")
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Return the error from this function, or handle the failure branch explicitly")
	v.WithContext("pattern", "success_only_guard")
	return v
}

// guardOnlyRefinesReadyValues отличает уточнение от потери. Если переменная уже
// получила осмысленное значение выше по функции, провал под guard'ом означает
// «оставить как было» — значение по умолчанию видно в коде рядом. Потеря данных
// начинается там, где цель пуста (var x T) или накапливается через append: тогда
// сбой неотличим от «данных не было».
func guardOnlyRefinesReadyValues(fn *ast.FuncDecl, stmt *ast.IfStmt) bool {
	targets := guardAssignTargets(stmt.Body)
	if len(targets) == 0 {
		return false
	}
	for name, accumulates := range targets {
		if accumulates {
			return false
		}
		if hasValueBefore(fn, stmt, name) || zeroStateHandledAfter(fn, stmt, name) {
			continue
		}
		return false
	}
	return true
}

// setsFilterParam reports a guard that writes a field of a filter parameter
// (*ListFilter, SearchCriteria): input that does not parse drops the bound,
// and the query widens to rows the caller did not ask for.
func setsFilterParam(fn *ast.FuncDecl, stmt *ast.IfStmt) bool {
	filters := make(map[string]bool)
	for _, field := range fn.Type.Params.List {
		typeName := ""
		switch t := ast.Unparen(stripStar(field.Type)).(type) {
		case *ast.Ident:
			typeName = t.Name
		case *ast.SelectorExpr:
			typeName = t.Sel.Name
		}
		if !strings.HasSuffix(typeName, "Filter") && !strings.HasSuffix(typeName, "Criteria") {
			continue
		}
		for _, name := range field.Names {
			filters[name.Name] = true
		}
	}
	for name := range guardAssignTargets(stmt.Body) {
		if filters[name] {
			return true
		}
	}
	return false
}

func stripStar(expr ast.Expr) ast.Expr {
	if star, ok := expr.(*ast.StarExpr); ok {
		return star.X
	}
	return expr
}

// keepsDomainPresetOnRead reports a guard over a read that takes a context
// (storage, network) whose target was preset to another package's constant:
//
//	fxSource := domain.FXSourceProvider
//	if project, err := repo.GetByID(ctx, id); err == nil { fxSource = project.FXSource }
//
// The preset is not a default of this code but a domain choice made up for
// the failure: a broken read takes the money path the record never chose.
func keepsDomainPresetOnRead(fn *ast.FuncDecl, stmt *ast.IfStmt, source *ast.CallExpr) bool {
	if source == nil || len(source.Args) == 0 || !isIdentNamed(source.Args[0], "ctx") {
		return false
	}
	for name := range guardAssignTargets(stmt.Body) {
		if presetToPackageConstant(fn.Body, stmt, name) {
			return true
		}
	}
	return false
}

// presetToPackageConstant reports a `name := pkg.Const` before the guard,
// where pkg is not a variable of the function.
func presetToPackageConstant(body *ast.BlockStmt, stmt *ast.IfStmt, name string) bool {
	preset := false
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Pos() >= stmt.Pos() || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		if !isIdentNamed(assign.Lhs[0], name) {
			return true
		}
		sel, ok := assign.Rhs[0].(*ast.SelectorExpr)
		if !ok || !sel.Sel.IsExported() {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		preset = ok && pkg.Obj == nil && !strings.Contains(strings.ToLower(sel.Sel.Name), "default")
		return true
	})
	return preset
}

// zeroStateHandledAfter ищет после guard'а явную проверку нулевого состояния:
// `if x.IsZero() { x = ... }`, `if x == "" { return ... }` и т.п. Такой код решает
// судьбу провала на месте — провал отличим от «данных не было», и это уже не
// потеря ошибки, а документированный в коде фолбек или отказ.
func zeroStateHandledAfter(fn *ast.FuncDecl, stmt *ast.IfStmt, name string) bool {
	handled := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if handled {
			return false
		}
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Pos() <= stmt.End() {
			return true
		}
		// A later test of the zero state tells the failure apart: the
		// branch gives the value a default or refuses to go on.
		if isZeroCheckOf(ifStmt.Cond, name) {
			handled = true
		}
		return true
	})
	return handled
}

// isZeroCheckOf распознаёт проверку нулевого состояния переменной:
// x.IsZero(), x == "", x == 0, x == nil.
func isZeroCheckOf(cond ast.Expr, name string) bool {
	switch e := cond.(type) {
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "IsZero" && rootIdentName(sel.X) == name
	case *ast.BinaryExpr:
		if e.Op != token.EQL {
			return false
		}
		return (rootIdentName(e.X) == name && isZeroValueExpr(e.Y)) ||
			(rootIdentName(e.Y) == name && isZeroValueExpr(e.X))
	}
	return false
}

// guardAssignTargets собирает имена, в которые пишет блок успеха. Значение флага —
// накопление (append к самому себе), при нём прежнее содержимое цель не спасает.
func guardAssignTargets(body *ast.BlockStmt) map[string]bool {
	targets := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN {
			return true
		}
		for i, lhs := range assign.Lhs {
			name := rootIdentName(lhs)
			if name == "" {
				continue
			}
			targets[name] = targets[name] || i < len(assign.Rhs) && isAppendExprTo(assign.Rhs[i], name)
		}
		return true
	})
	return targets
}

// rootIdentName возвращает имя переменной, в которую в итоге идёт запись:
// x, x.field, x[i] — всё это запись в x.
func rootIdentName(expr ast.Expr) string {
	switch node := expr.(type) {
	case *ast.Ident:
		if node.Name == "_" {
			return ""
		}
		return node.Name
	case *ast.SelectorExpr:
		return rootIdentName(node.X)
	case *ast.IndexExpr:
		return rootIdentName(node.X)
	case *ast.StarExpr:
		return rootIdentName(node.X)
	}
	return ""
}

func isAppendExprTo(expr ast.Expr, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "append" || len(call.Args) == 0 {
		return false
	}
	return rootIdentName(call.Args[0]) == name
}

// hasValueBefore проверяет, получила ли переменная значение до guard'а: параметр
// или receiver (значение приходит от вызывающего), присваивание или var с
// инициализатором. Голое `var x T` значением не считается.
func hasValueBefore(fn *ast.FuncDecl, stmt *ast.IfStmt, name string) bool {
	// Параметры и receiver лежат в fn.Type.Params и fn.Recv — ast.Inspect по
	// телу функции их не видит, проверяем явно.
	if fieldListsContainName(name, fn.Recv, fn.Type.Params) {
		return true
	}

	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil || n.Pos() >= stmt.Pos() {
			return true
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				// x := decimal.Zero is the zero the failure leaves, not a value.
				if rootIdentName(lhs) == name && (len(node.Rhs) != len(node.Lhs) || !isZeroInit(node.Rhs[i])) {
					found = true
				}
			}
		case *ast.ValueSpec:
			if len(node.Values) == 0 {
				return true
			}
			for _, ident := range node.Names {
				if ident.Name == name {
					found = true
				}
			}
		}
		return true
	})
	return found
}

// isZeroInit reports a zero value used as an initializer: "", 0, nil, T{},
// decimal.Zero.
func isZeroInit(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		return e.Sel.Name == "Zero"
	case *ast.CompositeLit:
		// An empty map or slice is a container the guard fills, not a zero
		// left in place of a value.
		switch e.Type.(type) {
		case *ast.ArrayType, *ast.MapType, nil:
			return false
		}
		return len(e.Elts) == 0
	}
	return isZeroValueExpr(expr)
}

// onlyQuietLogs reports an else block holding nothing but Debug, Info or
// Trace log calls.
func onlyQuietLogs(stmt ast.Stmt) bool {
	block, ok := stmt.(*ast.BlockStmt)
	if !ok || len(block.List) == 0 {
		return false
	}
	for _, own := range block.List {
		exprStmt, ok := own.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok || !helpers.IsLoggerCall(call) || isErrorReport(call) {
			return false
		}
	}
	return true
}

// fieldListsContainName ищет имя среди объявлений полей (параметры, receiver).
func fieldListsContainName(name string, lists ...*ast.FieldList) bool {
	for _, list := range lists {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			for _, ident := range field.Names {
				if ident.Name == name {
					return true
				}
			}
		}
	}
	return false
}

// successGuardErrName распознаёт условие «ошибки нет» и возвращает имя переменной.
// Условие может уточнять успех дальше: err == nil && parsed > 0 — провал
// и тогда молча оставляет всё как было.
func successGuardErrName(cond ast.Expr) (string, bool) {
	bin, ok := ast.Unparen(flattenAnd(cond)[0]).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return "", false
	}
	ident, ok := bin.X.(*ast.Ident)
	if !ok || !isErrorVarName(ident.Name) {
		return "", false
	}
	if !isNilIdent(bin.Y) {
		return "", false
	}
	return ident.Name, true
}

// errSourceCall находит вызов, из которого пришла ошибка: либо в Init самого if,
// либо в присваивании выше по тому же телу функции. Без вызова это не наш случай:
// переменная могла прийти аргументом и проверяться осмысленно.
func errSourceCall(fn *ast.FuncDecl, stmt *ast.IfStmt, errName string) (string, bool) {
	if assign, ok := stmt.Init.(*ast.AssignStmt); ok {
		if name, found := callAssignedToErr(assign, errName); found {
			return name, true
		}
		return "", false
	}
	if stmt.Init != nil {
		return "", false
	}

	var source string
	var found bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Pos() >= stmt.Pos() {
			return true
		}
		if name, ok := callAssignedToErr(assign, errName); ok {
			source = name // берём ближайшее присваивание перед проверкой
			found = true
		}
		return true
	})
	return source, found
}

func callAssignedToErr(assign *ast.AssignStmt, errName string) (string, bool) {
	if len(assign.Rhs) != 1 {
		return "", false
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return "", false
	}
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name == errName {
			return core.ExtractFullFunctionName(call), true
		}
	}
	return "", false
}

// guardBodyOnlyAssigns требует, чтобы тело успеха писало наружу и не выходило из
// функции: return, panic, continue и break — это уже явная развилка, а не тишина.
func guardBodyOnlyAssigns(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) == 0 {
		return false
	}

	hasOuterAssign := false
	terminates := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ReturnStmt:
			terminates = true
		case *ast.BranchStmt:
			terminates = true
		case *ast.AssignStmt:
			if node.Tok == token.ASSIGN {
				hasOuterAssign = true
			}
		case *ast.FuncLit:
			return false // тело замыкания живёт своей жизнью
		}
		return true
	})

	return hasOuterAssign && !terminates
}

// errUsedElsewhere проверяет, смотрит ли на ошибку кто-то ещё в этой функции:
// лог, второй if, возврат. Собственное присваивание и условие не считаются.
// assigned — идентификаторы, стоящие слева в присваиваниях тела функции.
// Ошибка, объявленная в Init самого if, за его пределами не видна; объявленная
// через := в блоке — видна только в этом блоке: одноимённая err в другом
// месте функции — другая переменная.
func errUsedElsewhere(fn *ast.FuncDecl, stmt *ast.IfStmt, errName string, assigned map[*ast.Ident]bool) bool {
	if assign, ok := stmt.Init.(*ast.AssignStmt); ok && assign.Tok == token.DEFINE && assignsName(assign, errName) {
		return false
	}
	var scope ast.Node = fn.Body
	if block := definingBlock(fn.Body, stmt, errName); block != nil {
		scope = block
	}
	used := false
	ast.Inspect(scope, func(n ast.Node) bool {
		if used {
			return false
		}
		ident, ok := n.(*ast.Ident)
		if !ok || ident.Name != errName {
			return true
		}
		if ident.Pos() >= stmt.Pos() && ident.End() <= stmt.End() {
			return true // внутри самого if: Init и условие
		}
		if assigned[ident] {
			return true // строка, где ошибка получена
		}
		used = true
		return false
	})
	return used
}

// definingBlock returns the block whose own statement declares name with :=
// last before stmt — the scope of the variable stmt checks — or nil when the
// nearest assignment before stmt is a plain = (the variable is shared).
func definingBlock(body *ast.BlockStmt, stmt *ast.IfStmt, name string) *ast.BlockStmt {
	var block *ast.BlockStmt
	var nearest token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		list, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for _, own := range list.List {
			assign, ok := own.(*ast.AssignStmt)
			if !ok || assign.Pos() >= stmt.Pos() || assign.Pos() < nearest || !assignsName(assign, name) {
				continue
			}
			nearest = assign.Pos()
			block = nil
			if assign.Tok == token.DEFINE && list.Pos() <= stmt.Pos() && stmt.End() <= list.End() {
				block = list
			}
		}
		return true
	})
	return block
}

// errSourceExpr returns the call the checked error comes from: in the Init of
// the if or in the nearest assignment before it.
func errSourceExpr(body *ast.BlockStmt, stmt *ast.IfStmt, errName string) *ast.CallExpr {
	var source *ast.CallExpr
	consider := func(assign *ast.AssignStmt) {
		if len(assign.Rhs) != 1 || !assignsName(assign, errName) {
			return
		}
		if call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); ok {
			source = call
		}
	}
	if assign, ok := stmt.Init.(*ast.AssignStmt); ok {
		consider(assign)
		return source
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok && assign.Pos() < stmt.Pos() {
			consider(assign)
		}
		return true
	})
	return source
}

// isParseCall reports a call that checks the shape of its input: strconv,
// a function or method named Parse..., Unquote. Its error says the input is
// not of that shape, not that something broke.
func isParseCall(call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	name := ""
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		name = fun.Name
	case *ast.SelectorExpr:
		if isIdentNamed(fun.X, "strconv") {
			return true
		}
		name = fun.Sel.Name
	}
	return strings.HasPrefix(name, "Parse") || strings.HasPrefix(name, "parse") || name == "Unquote" || name == "Atoi"
}

// requestValueMethods read a value the client sent.
var requestValueMethods = map[string]bool{"FormValue": true, "PostFormValue": true, "PathValue": true}

// parsesRequestInput reports a call that parses a value of the request: an
// argument read by r.URL.Query().Get, a query copy's Get, FormValue,
// PostFormValue, PathValue or mux.Vars(r)[...], directly or through a local.
func parsesRequestInput(body *ast.BlockStmt, call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	for _, arg := range call.Args {
		if isRequestValue(body, arg, 2) {
			return true
		}
	}
	return false
}

func isRequestValue(body *ast.BlockStmt, expr ast.Expr, depth int) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		value := localValue(body, e.Name)
		return depth > 0 && value != nil && isRequestValue(body, value, depth-1)
	case *ast.IndexExpr:
		inner, ok := ast.Unparen(e.X).(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := inner.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Vars"
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if requestValueMethods[sel.Sel.Name] {
			return true
		}
		return sel.Sel.Name == "Get" && isQueryValues(body, sel.X)
	}
	return false
}

// isQueryValues reports r.URL.Query() or a local holding it.
func isQueryValues(body *ast.BlockStmt, expr ast.Expr) bool {
	if ident, ok := ast.Unparen(expr).(*ast.Ident); ok {
		value := localValue(body, ident.Name)
		return value != nil && strings.HasSuffix(types.ExprString(value), ".URL.Query()")
	}
	return strings.HasSuffix(types.ExprString(expr), ".URL.Query()")
}

// localValue returns the value a := (an if-init too) gives name in the
// function; nil when there is none or more than one.
func localValue(body *ast.BlockStmt, name string) ast.Expr {
	var value ast.Expr
	count := 0
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			if isIdentNamed(lhs, name) {
				value = assign.Rhs[i]
				count++
			}
		}
		return true
	})
	if count != 1 {
		return nil
	}
	return value
}

// assignedIdents собирает идентификаторы, стоящие непосредственно слева в
// присваиваниях тела: один проход на функцию вместо поиска объемлющего
// присваивания для каждого упоминания.
func assignedIdents(body *ast.BlockStmt) map[*ast.Ident]bool {
	assigned := make(map[*ast.Ident]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok {
				assigned[ident] = true
			}
		}
		return true
	})
	return assigned
}

// checkErrorIfStmt checks an `if err != nil` of a function with the given
// results for a return that hands out a success value instead of the error.
func (r *ErrorMaskingRule) checkErrorIfStmt(ctx *core.FileContext, results *ast.FieldList, stmt *ast.IfStmt) *core.Violation {
	errName := errNilCheckName(stmt.Cond)
	if errName == "" {
		return nil
	}

	// Check if error is logged before return (acceptable pattern)
	info := r.analyzeErrorBlock(stmt.Body.List, errName)
	if r.isAcceptableDenialPattern(info) {
		return nil
	}

	// Find first problematic return
	return r.findProblematicReturn(ctx, results, stmt)
}

// blockAnalysis holds analysis results of an error handling block
type blockAnalysis struct {
	hasLogging bool
	// causeLogged: the branch logs the error value itself at Error, Warn or
	// Fatal level — the failure is on record whatever the function answers.
	causeLogged bool
	returnStmt  *ast.ReturnStmt
}

// analyzeErrorBlock analyzes statements in error handling block for logging and return
func (r *ErrorMaskingRule) analyzeErrorBlock(stmts []ast.Stmt, errName string) blockAnalysis {
	var info blockAnalysis
	for _, bodyStmt := range stmts {
		if exprStmt, ok := bodyStmt.(*ast.ExprStmt); ok {
			if call, ok := exprStmt.X.(*ast.CallExpr); ok && helpers.IsLoggerCall(call) {
				info.hasLogging = true
				if isErrorLevelLogCall(call) && nodeReadsIdent(call, errName) {
					info.causeLogged = true
				}
			}
		}
		if ret, ok := bodyStmt.(*ast.ReturnStmt); ok {
			info.returnStmt = ret
		}
	}
	return info
}

// isAcceptableDenialPattern checks if block is an acceptable logged denial pattern
func (r *ErrorMaskingRule) isAcceptableDenialPattern(info blockAnalysis) bool {
	if !info.hasLogging || info.returnStmt == nil {
		return false
	}
	// A bool cannot carry the error. Once the cause is logged at error level,
	// the bool answers what to do next (skip the event and keep streaming), not
	// whether the operation succeeded; a number or a string in the same place
	// would still stand in for data the caller never got.
	if info.causeLogged && returnsOnlyBoolLiterals(info.returnStmt) {
		return true
	}
	for _, result := range info.returnStmt.Results {
		if ident, ok := result.(*ast.Ident); ok && ident.Name == "false" {
			return true // Logged error + return false is acceptable
		}
		if lit, ok := result.(*ast.BasicLit); ok && lit.Value == `""` {
			return true // Logged error + return "" is acceptable
		}
	}
	return false
}

// findProblematicReturn finds problematic returns in error handling block
func (r *ErrorMaskingRule) findProblematicReturn(ctx *core.FileContext, results *ast.FieldList, stmt *ast.IfStmt) *core.Violation {
	for _, bodyStmt := range stmt.Body.List {
		retStmt, ok := bodyStmt.(*ast.ReturnStmt)
		if !ok {
			continue
		}
		if returnHandsOverError(results, retStmt) || r.isCommaOkReturnWithFalse(retStmt) {
			continue
		}
		for _, result := range retStmt.Results {
			// A zero struct next to a non-nil value in the last slot (a
			// custom error type) is the usual "no value, here is why"; after
			// other statements (fail(...) collecting the problem) the branch
			// has reported it.
			if _, zeroStruct := result.(*ast.CompositeLit); zeroStruct && (len(stmt.Body.List) > 1 ||
				len(retStmt.Results) > 1 && !isNilIdent(retStmt.Results[len(retStmt.Results)-1])) {
				continue
			}
			if r.isProblematicReturn(result) {
				pos := ctx.PositionFor(stmt)
				v := r.CreateViolation(ctx.RelPath, pos.Line, "Error condition returns success value, masking the error")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Return the error or handle it explicitly")
				v.WithContext("pattern", "error_return_value")
				return v
			}
		}
	}
	return nil
}

// isCommaOkReturnWithFalse checks if return is a comma-ok pattern ending with false
// Pattern: return value, false - indicates failure in Go idiom
func (r *ErrorMaskingRule) isCommaOkReturnWithFalse(stmt *ast.ReturnStmt) bool {
	if len(stmt.Results) < 2 {
		return false
	}

	// Check if last return value is false (comma-ok failure indicator)
	lastResult := stmt.Results[len(stmt.Results)-1]
	if ident, ok := lastResult.(*ast.Ident); ok {
		return ident.Name == "false"
	}

	return false
}

// returnHandsOverError reports whether the return passes an error to the
// caller: the function's last result is error and the value in that slot is
// not nil. A sentinel, a wrap helper or any other expression there is the
// error, whatever it is called.
//
// A function may declare its own error type in that slot (*RequestError):
// there the value hands the failure over when it carries an error — built by
// an error constructor or wrapping the cause.
func returnHandsOverError(results *ast.FieldList, ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false
	}
	last := ret.Results[len(ret.Results)-1]
	if lastResultIsErrorType(results) {
		return !isNilIdent(last)
	}
	return exprCarriesError(last)
}

// returnsOnlyBoolLiterals reports whether every value of the return is true or
// false.
func returnsOnlyBoolLiterals(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false
	}
	for _, result := range ret.Results {
		ident, ok := result.(*ast.Ident)
		if !ok || (ident.Name != "true" && ident.Name != "false") {
			return false
		}
	}
	return true
}

// isProblematicReturn checks if return value masks the error
func (r *ErrorMaskingRule) isProblematicReturn(expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.Ident:
		// Only "true" is problematic - it masks error as success
		// "false" is acceptable as it indicates failure (comma-ok pattern, deny-by-default)
		return v.Name == "true"
	case *ast.BasicLit:
		// Empty string, zero values
		return v.Value == `""` || v.Value == "0"
	case *ast.CompositeLit:
		// A zero struct (time.Time{}) passes for a real value; an empty
		// slice or map stays with nil, an answer of "nothing".
		switch v.Type.(type) {
		case *ast.ArrayType, *ast.MapType, nil:
			return false
		}
		return len(v.Elts) == 0
	}
	return false
}

// analyzeTSFile analyzes TypeScript/JavaScript file for masking patterns
func (r *ErrorMaskingRule) analyzeTSFile(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		if r.isCommentOrEmpty(line) {
			continue
		}

		for _, patternName := range slices.Sorted(maps.Keys(r.tsPatterns)) {
			pattern := r.tsPatterns[patternName]
			if pattern.MatchString(line) {
				if r.isTSException(ctx.RelPath) {
					continue
				}

				v := r.createTSViolation(ctx, lineNum+1, line, patternName)
				violations = append(violations, v)
			}
		}
	}

	return violations
}

// isCommentOrEmpty checks if line is a comment or empty
func (r *ErrorMaskingRule) isCommentOrEmpty(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*")
}

// isRegexPatternDefinition checks if line is defining a regex pattern
func (r *ErrorMaskingRule) isRegexPatternDefinition(line string) bool {
	return strings.Contains(line, "regexp.MustCompile") ||
		strings.Contains(line, "regexp.Compile")
}

// isGoException checks if pattern match is a valid exception
func (r *ErrorMaskingRule) isGoException(path, line string) bool {
	// Config files with documented defaults (case-insensitive)
	if strings.Contains(path, "config") {
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "// default") ||
			strings.Contains(lineLower, "//default") ||
			strings.Contains(lineLower, "default value") ||
			strings.Contains(lineLower, "default if") {
			return true
		}
	}

	// Validation returning false for invalid input
	if strings.Contains(path, "valid") && strings.Contains(line, "return false") {
		return true
	}

	// Pagination defaults
	if strings.Contains(line, "defaultLimit") || strings.Contains(line, "defaultPage") {
		return true
	}

	// Config getter functions returning documented defaults
	if strings.Contains(path, "config") && strings.Contains(line, "return") {
		// Allow returns with documented fallback comments
		if strings.Contains(line, "// ") && (strings.Contains(strings.ToLower(line), "limit") ||
			strings.Contains(strings.ToLower(line), "gas") ||
			strings.Contains(strings.ToLower(line), "rate") ||
			strings.Contains(strings.ToLower(line), "timeout")) {
			return true
		}
	}

	// E2E test support - "test-" prefix returns are intentional for test mode
	if strings.Contains(line, `"test-`) && strings.Contains(line, "return") {
		return true
	}

	return false
}

// isTSException checks if pattern match is a valid exception for TS
func (r *ErrorMaskingRule) isTSException(path string) bool {
	// next.config.js defaults
	if strings.Contains(path, "next.config") {
		return true
	}

	// Test utilities
	if strings.Contains(path, "test") || strings.Contains(path, "spec") {
		return true
	}

	// E2E test utilities
	if strings.Contains(path, "e2e") {
		return true
	}

	// Scripts and setup files
	if strings.Contains(path, "scripts/") || strings.Contains(path, "setup") {
		return true
	}

	return false
}

// createGoViolation creates a violation for Go pattern
func (r *ErrorMaskingRule) createGoViolation(ctx *core.FileContext, lineNum int, line, patternName string) *core.Violation {
	msg, suggestion, severity := r.getGoViolationDetails(patternName)

	v := core.NewViolation(r.Name(), r.Category(), ctx.RelPath, lineNum, severity, msg)
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion(suggestion)
	v.WithContext("pattern", patternName)
	v.WithContext("language", "go")

	return v
}

// violationInfo holds message, suggestion and severity for a pattern
type violationInfo struct {
	msg        string
	suggestion string
	severity   core.Severity
}

// goViolationDetails maps pattern names to violation details
var goViolationDetails = map[string]violationInfo{
	"hardcoded_return": {"Function returns hardcoded value instead of handling error", "Move value to configuration or return error", core.SeverityHigh},
	"success_masked":   {"Function returns success, masking real problems", "Return error or add proper error handling", core.SeverityCritical},
	"fake_data_return": {"Returns fake/mock data in production code", "Remove fake data or move to test configuration", core.SeverityHigh},
	"zero_on_error":    {"Zero value returned on system error - critical UX problem", "Show user the real error instead of fake zero", core.SeverityCritical},
}

// getGoViolationDetails returns message, suggestion, and severity for Go pattern
func (r *ErrorMaskingRule) getGoViolationDetails(patternName string) (string, string, core.Severity) {
	if info, ok := goViolationDetails[patternName]; ok {
		return info.msg, info.suggestion, info.severity
	}
	return "Suspicious error masking pattern detected", "Check if this pattern is necessary", core.SeverityMedium
}

// createTSViolation creates a violation for TypeScript pattern
func (r *ErrorMaskingRule) createTSViolation(ctx *core.FileContext, lineNum int, line, patternName string) *core.Violation {
	msg, suggestion, severity := r.getTSViolationDetails(patternName)

	v := core.NewViolation(r.Name(), r.Category(), ctx.RelPath, lineNum, severity, msg)
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion(suggestion)
	v.WithContext("pattern", patternName)
	v.WithContext("language", "typescript")

	return v
}

// tsViolationDetails maps TS pattern names to violation details
var tsViolationDetails = map[string]violationInfo{
	"env_default":            {"Environment variable with hardcoded default may mask configuration problems", "Use fail-fast validation: if (!process.env.VAR) throw new Error()", core.SeverityHigh},
	"config_default":         {"Config property with hardcoded default may become stale", "Move defaults to centralized configuration", core.SeverityHigh},
	"switch_default_value":   {"Switch default with value masks unknown cases", "Replace with explicit error: default: throw new Error('Unknown case')", core.SeverityCritical},
	"catch_hardcoded_return": {"Try-catch with hardcoded value masks real errors", "Rethrow error or return explicit error object", core.SeverityCritical},
	"fake_signature":         {"Fake signature in code", "Use real signature from test configuration", core.SeverityHigh},
	"error_return_empty":     {"Returns empty value after error check", "Add proper error handling or show user the error", core.SeverityMedium},
}

// getTSViolationDetails returns message, suggestion, and severity for TS pattern
func (r *ErrorMaskingRule) getTSViolationDetails(patternName string) (string, string, core.Severity) {
	if info, ok := tsViolationDetails[patternName]; ok {
		return info.msg, info.suggestion, info.severity
	}
	return "Suspicious error masking pattern detected", "Check if this pattern is necessary", core.SeverityMedium
}
