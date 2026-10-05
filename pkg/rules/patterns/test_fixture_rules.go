package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewTestTemplateDBSharedAcrossSourcesRule())
	rules.Register(NewTestFixtureWriteOverriddenByDBTriggerRule())
	rules.Register(NewTestWaitsOnProxySignalRule())
	rules.Register(NewTestAuthSchemeDriftRule())
}

// TestTemplateDBSharedAcrossSourcesRule detects a test database template with
// a fixed name copied from a source database chosen at run time:
//
//	const templateName = "app_test_template"
//	fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", templateName, cfg.DBName)
//
// A run against another source (a copy with an older schema) finds the
// template already there, or replaces it: the other run's tests then work on
// the wrong schema.
type TestTemplateDBSharedAcrossSourcesRule struct {
	*rules.BaseRule
}

// NewTestTemplateDBSharedAcrossSourcesRule creates the rule.
func NewTestTemplateDBSharedAcrossSourcesRule() *TestTemplateDBSharedAcrossSourcesRule {
	return &TestTemplateDBSharedAcrossSourcesRule{BaseRule: rules.NewBaseRule(
		"test-template-db-shared-across-sources",
		"patterns",
		"Detects CREATE DATABASE <fixed name> TEMPLATE <source chosen at run time> — runs against different source databases share one template, and one run's tests get the other's schema",
		core.SeverityMedium,
	)}
}

var createFromTemplate = regexp.MustCompile(`(?i)\bCREATE\s+DATABASE\s+"?%[sqv]"?\s+(?:WITH\s+)?TEMPLATE\s*=?\s*"?%[sqv]"?`)

// AnalyzeFile reports the template copies with a fixed name.
func (r *TestTemplateDBSharedAcrossSourcesRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}
	consts := goFileConstants(ctx.GoAST)
	var out []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isSelectorCall(call, "fmt", "Sprintf") || len(call.Args) != 3 {
			return true
		}
		format, ok := call.Args[0].(*ast.BasicLit)
		if !ok || format.Kind != token.STRING || !createFromTemplate.MatchString(format.Value) {
			return true
		}
		if !isConstantExpr(call.Args[1], consts) || isConstantExpr(call.Args[2], consts) {
			return true
		}
		line := ctx.LineFor(call)
		if ctx.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(ctx.RelPath, line, "The template has a fixed name while its source database is chosen at run time — a run against another source reuses or replaces it, and its tests get the other schema")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Derive the template name from the source database (its name or a hash of its schema)")
		out = append(out, v)
		return true
	})
	return out
}

// isConstantExpr reports a literal or a constant declared in the file.
func isConstantExpr(expr ast.Expr, consts map[string]bool) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return consts[e.Name]
	}
	return false
}

// goFileConstants returns the names of the constants declared in the file.
func goFileConstants(file *ast.File) map[string]bool {
	consts := make(map[string]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.CONST {
			return true
		}
		for _, spec := range decl.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range value.Names {
				consts[name.Name] = true
			}
		}
		return true
	})
	return consts
}

// TestFixtureWriteOverriddenByDBTriggerRule detects a test that sets a
// column which a BEFORE UPDATE trigger stamps with the current time:
//
//	db.Exec(`UPDATE orders SET updated_at = NOW() - INTERVAL '30 days' WHERE id = $1`, id)
//
// The trigger writes NOW() over the value, and the test checks a fixture it
// never got: an "older than" case passes or fails for the wrong reason.
type TestFixtureWriteOverriddenByDBTriggerRule struct {
	*rules.BaseRule
}

// NewTestFixtureWriteOverriddenByDBTriggerRule creates the rule.
func NewTestFixtureWriteOverriddenByDBTriggerRule() *TestFixtureWriteOverriddenByDBTriggerRule {
	return &TestFixtureWriteOverriddenByDBTriggerRule{BaseRule: rules.NewBaseRule(
		"test-fixture-write-overridden-by-db-trigger",
		"patterns",
		"Detects a test UPDATE that sets the column a BEFORE UPDATE trigger stamps with NOW() — the trigger replaces the value, and the test runs on a fixture it never got",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the stamped-column writes of a Go test file.
func (r *TestFixtureWriteOverriddenByDBTriggerRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	literals := sqlLiterals(ctx.GoAST)
	if len(literals) == 0 {
		return nil
	}
	schema, err := sqlschema.LoadCached(ctx.ProjectRoot, migrationDirs(r.BaseRule))
	var migrationErr *sqlschema.MigrationError
	if errors.As(err, &migrationErr) {
		return nil // the schema rules report the migration; nothing to check against
	}
	if err != nil {
		v := r.CreateViolation(ctx.RelPath, 1, "The migrations cannot be listed, so the test SQL was not checked against the triggers: "+err.Error())
		v.Severity = core.SeverityCritical
		v.WithSuggestion("Point the migrations setting at the directories that hold the schema")
		return []*core.Violation{v}
	}
	if !schema.AnyStampedOnUpdate() {
		return nil
	}
	var out []*core.Violation
	for _, literal := range literals {
		off := triggersOffBefore(ctx.GoAST, literal.expr.Pos())
		for _, overwrite := range schema.StampOverwrites(literal.text) {
			if off.all || off.tables[overwrite.Table] {
				continue
			}
			line := ctx.LineFor(literal.expr)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line, fmt.Sprintf("A trigger stamps %s.%s with NOW() on every UPDATE — the value the test writes there is replaced", overwrite.Table, overwrite.Column))
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Disable the trigger for the fixture (ALTER TABLE ... DISABLE TRIGGER) or set the time with the INSERT, which the trigger does not touch")
			out = append(out, v)
		}
	}
	return out
}

var (
	disableTrigger     = regexp.MustCompile(`(?i)\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:\w+\.)?"?(\w+)"?\s+DISABLE\s+TRIGGER\b`)
	replicationReplica = regexp.MustCompile(`(?i)\bsession_replication_role\s*(?:=|\bTO\b)\s*'?replica\b`)
)

// triggersOff are the triggers a function switched off before a statement:
// on some tables, or all of them for the session.
type triggersOff struct {
	all    bool
	tables map[string]bool
}

// triggersOffBefore reads the string literals of the function holding pos
// that come before it: ALTER TABLE t DISABLE TRIGGER switches off the
// triggers of t, SET session_replication_role = 'replica' the ordinary
// triggers of every table.
func triggersOffBefore(file *ast.File, pos token.Pos) triggersOff {
	off := triggersOff{tables: make(map[string]bool)}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || pos < fn.Body.Pos() || pos >= fn.Body.End() {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Pos() >= pos {
				return true
			}
			text, ok := goStringLiteral(lit)
			if !ok {
				return true
			}
			off.all = off.all || replicationReplica.MatchString(text)
			for _, m := range disableTrigger.FindAllStringSubmatch(text, -1) {
				off.tables[strings.ToLower(m[1])] = true
			}
			return true
		})
	}
	return off
}

// TestWaitsOnProxySignalRule detects a test that waits for a counter its fake
// server bumps at the start of a handler, and then uses the result of the
// request:
//
//	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		hits.Add(1)
//		json.NewEncoder(w).Encode(rows)
//	}))
//	waitForCondition(func() bool { return hits.Load() > 0 }, 5*time.Second)
//	records, err := client.Search(ctx) // the warmed cache may not be there yet
//
// The counter says the request arrived, not that the client got and stored
// the answer: the test races with the rest of the handler and the client.
type TestWaitsOnProxySignalRule struct {
	*rules.BaseRule
}

// NewTestWaitsOnProxySignalRule creates the rule.
func NewTestWaitsOnProxySignalRule() *TestWaitsOnProxySignalRule {
	return &TestWaitsOnProxySignalRule{BaseRule: rules.NewBaseRule(
		"test-waits-on-proxy-signal-not-completion",
		"patterns",
		"Detects a test that waits until a fake server's handler counter moves and then relies on the request's result — the counter rises when the request arrives, before the answer is processed, so the test races",
		core.SeverityMedium,
	)}
}

var waitCallName = regexp.MustCompile(`(?i)^(?:waitFor\w*|wait(?:Until)?|eventually\w*|poll\w*)$`)

// AnalyzeFile reports the waits on handler counters followed by use of the
// request's result.
func (r *TestWaitsOnProxySignalRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	helpers := handlerCounterParams(ctx.GoAST)
	var out []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		counters := handlerCounters(fn.Body, helpers)
		if len(counters) == 0 {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, stmt := range block.List {
				counter, ok := counterWait(stmt, counters)
				if !ok || !usesResultAfter(block.List[i+1:], counter) {
					continue
				}
				line := ctx.LineFor(stmt)
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(ctx.RelPath, line, counter+" rises when the request reaches the fake server, before the answer is processed — the steps after the wait race with the handler and the client")
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("Wait for the effect the test needs (the stored result, a done channel closed after the work), not for the request's arrival")
				out = append(out, v)
			}
			return true
		})
	}
	return out
}

// handlerCounterParams returns, per function of the file, the parameters it
// bumps inside an HTTP handler literal.
func handlerCounterParams(file *ast.File) map[string]map[int]bool {
	helpers := make(map[string]map[int]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Recv != nil {
			continue
		}
		bumped := bumpedInHandlers(fn.Body)
		index := 0
		for _, field := range fn.Type.Params.List {
			for _, name := range field.Names {
				if bumped[name.Name] {
					if helpers[fn.Name.Name] == nil {
						helpers[fn.Name.Name] = make(map[int]bool)
					}
					helpers[fn.Name.Name][index] = true
				}
				index++
			}
			if len(field.Names) == 0 {
				index++
			}
		}
	}
	return helpers
}

// handlerCounters returns the counters of a function body that an HTTP
// handler bumps: in a handler literal of the body or in a helper of the file
// that gets the counter's address.
func handlerCounters(body *ast.BlockStmt, helpers map[string]map[int]bool) map[string]bool {
	counters := bumpedInHandlers(body)
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		for i, arg := range call.Args {
			unary, ok := arg.(*ast.UnaryExpr)
			if !ok || unary.Op != token.AND || !helpers[ident.Name][i] {
				continue
			}
			if name, ok := unary.X.(*ast.Ident); ok {
				counters[name.Name] = true
			}
		}
		return true
	})
	return counters
}

// bumpedInHandlers returns the variables incremented inside the HTTP handler
// literals under node: x.Add(1), x++, atomic.AddInt64(&x, 1).
func bumpedInHandlers(node ast.Node) map[string]bool {
	bumped := make(map[string]bool)
	ast.Inspect(node, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok || !isHTTPHandlerType(lit.Type) {
			return true
		}
		ast.Inspect(lit.Body, func(m ast.Node) bool {
			switch s := m.(type) {
			case *ast.IncDecStmt:
				if ident, ok := s.X.(*ast.Ident); ok && s.Tok == token.INC {
					bumped[ident.Name] = true
				}
			case *ast.CallExpr:
				if sel, ok := s.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Add" {
					if ident, ok := sel.X.(*ast.Ident); ok {
						bumped[ident.Name] = true
					}
				}
				if isSelectorCall(s, "atomic", "AddInt64") || isSelectorCall(s, "atomic", "AddInt32") {
					if unary, ok := s.Args[0].(*ast.UnaryExpr); ok {
						if ident, ok := unary.X.(*ast.Ident); ok {
							bumped[ident.Name] = true
						}
					}
				}
			}
			return true
		})
		return false
	})
	return bumped
}

// isHTTPHandlerType reports func(w http.ResponseWriter, r *http.Request).
func isHTTPHandlerType(ft *ast.FuncType) bool {
	if ft.Params == nil || len(ft.Params.List) == 0 {
		return false
	}
	sel, ok := ft.Params.List[0].Type.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "ResponseWriter"
}

// counterWait reports a statement that polls until a counter moves: a wait
// call whose condition literal only compares counter.Load() with a number.
func counterWait(stmt ast.Stmt, counters map[string]bool) (string, bool) {
	var found string
	ast.Inspect(stmt, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found != "" {
			return found == ""
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		if !waitCallName.MatchString(name) {
			return true
		}
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.FuncLit)
			if !ok || len(lit.Body.List) != 1 {
				continue
			}
			ret, ok := lit.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				continue
			}
			if counter, ok := countComparison(ret.Results[0]); ok && counters[counter] {
				found = counter
			}
		}
		return true
	})
	return found, found != ""
}

// countComparison reports x.Load() compared with an integer literal.
func countComparison(expr ast.Expr) (string, bool) {
	bin, ok := ast.Unparen(expr).(*ast.BinaryExpr)
	if !ok || !isComparisonOp(bin.Op) {
		return "", false
	}
	for _, pair := range [][2]ast.Expr{{bin.X, bin.Y}, {bin.Y, bin.X}} {
		lit, ok := ast.Unparen(pair[1]).(*ast.BasicLit)
		if !ok || lit.Kind != token.INT {
			continue
		}
		call, ok := ast.Unparen(pair[0]).(*ast.CallExpr)
		if !ok {
			continue
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Load" {
			if ident, ok := sel.X.(*ast.Ident); ok {
				return ident.Name, true
			}
		}
	}
	return "", false
}

// usesResultAfter reports a statement after the wait that calls something
// other than the test's own reporting and the counter: the test goes on to
// use what the request produced.
func usesResultAfter(rest []ast.Stmt, counter string) bool {
	for _, stmt := range rest {
		used := false
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || used {
				return !used
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok && (ident.Name == "t" || ident.Name == "require" || ident.Name == "assert" || ident.Name == counter) {
					return true
				}
				used = true
			}
			return !used
		})
		if used {
			return true
		}
	}
	return false
}

// TestAuthSchemeDriftRule detects tests that authenticate with an
// Authorization header against a server that never reads one:
//
//	headers = { 'Authorization': `Bearer ${token}` } // e2e spec
//	cookie, err := r.Cookie("session")              // the only auth the server reads
//
// The request goes in unauthenticated, and the test checks a 401 path or is
// rewritten around mocks instead of the real API.
type TestAuthSchemeDriftRule struct {
	*rules.BaseRule
	cookieAuth, headerAuth bool
}

// NewTestAuthSchemeDriftRule creates the rule.
func NewTestAuthSchemeDriftRule() *TestAuthSchemeDriftRule {
	return &TestAuthSchemeDriftRule{BaseRule: rules.NewBaseRule(
		"test-auth-scheme-drift",
		"patterns",
		"Detects tests that send an Authorization header to a Go server that reads authentication only from a cookie — the requests go in unauthenticated",
		core.SeverityMedium,
	)}
}

var (
	requestCookieRead    = regexp.MustCompile(`\.Cookie\(\s*[\w."]`)
	authHeaderConstant   = regexp.MustCompile(`\b(\w+)\s*=\s*"Authorization"`)
	authHeaderMiddleware = regexp.MustCompile(`(?i)\b(?:echojwt|jwtauth|ginjwt|jwtmiddleware|BearerAuth|HeaderAuthorization)\b|(?:TrimPrefix|HasPrefix|CutPrefix)\([^)]*"Bearer `)
	corsHeaderList       = regexp.MustCompile(`(?i)allow-?headers|allowedheaders|expose-?headers`)
	testAuthHeaderTS     = regexp.MustCompile(`['"]?\bAuthorization['"]?\s*:\s*[` + "`" + `'"]Bearer\b`)
	testAuthHeaderGo     = regexp.MustCompile(`\.Header\.(?:Set|Add)\(\s*"Authorization"`)
)

// UseProjectFiles learns how the project's Go server reads authentication.
func (r *TestAuthSchemeDriftRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	for _, ctx := range files {
		if !ctx.IsGoFile() || ctx.IsTestFile() {
			continue
		}
		var headerNames []string
		for _, line := range ctx.Lines {
			if m := authHeaderConstant.FindStringSubmatch(line); m != nil {
				headerNames = append(headerNames, m[1])
			}
		}
		for _, line := range ctx.Lines {
			r.cookieAuth = r.cookieAuth || requestCookieRead.MatchString(line)
			if corsHeaderList.MatchString(line) {
				continue
			}
			r.headerAuth = r.headerAuth || readsAuthHeader(line, headerNames)
		}
	}
}

// readsAuthHeader reports a line that reads the Authorization header of a
// request, by name or through a constant holding it.
func readsAuthHeader(line string, headerNames []string) bool {
	if authHeaderMiddleware.MatchString(line) {
		return true
	}
	if !strings.Contains(line, "Get") && !strings.Contains(line, "Values") {
		return false
	}
	if strings.Contains(line, `"Authorization"`) {
		return true
	}
	compact := strings.Join(strings.Fields(line), "")
	for _, name := range headerNames {
		if strings.Contains(compact, "("+name+")") {
			return true
		}
	}
	return false
}

// ResetState forgets the server's authentication.
func (r *TestAuthSchemeDriftRule) ResetState() { r.cookieAuth, r.headerAuth = false, false }

// AnalyzeFile reports the Authorization headers a test sends.
func (r *TestAuthSchemeDriftRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !r.cookieAuth || r.headerAuth || !testSourceFile(ctx) {
		return nil
	}
	pattern := testAuthHeaderTS
	if ctx.IsGoFile() {
		pattern = testAuthHeaderGo
	}
	var out []*core.Violation
	for i, line := range ctx.Lines {
		if !pattern.MatchString(line) || ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, "The test authenticates with an Authorization header, while the server reads authentication only from a cookie — the request goes in unauthenticated")
		v.WithCode(strings.TrimSpace(line))
		v.WithSuggestion("Authenticate the test the way the server reads it: set the session cookie")
		out = append(out, v)
	}
	return out
}

// testSourceFile reports a Go test file or a TS/JS test or e2e file.
func testSourceFile(ctx *core.FileContext) bool {
	path := "/" + strings.ToLower(ctx.RelPath)
	if strings.Contains(path, "/node_modules/") {
		return false
	}
	if ctx.IsGoFile() {
		return ctx.IsTestFile()
	}
	return (ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile()) && (ctx.IsTestFile() || strings.Contains(path, "/e2e/"))
}
