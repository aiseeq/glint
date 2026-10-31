package frontendrules

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewNextConfigIgnoresBuildErrorsRule())
	rules.Register(NewFrontendWarnedFallbackRule())
	rules.Register(NewAllSettledRejectionsIgnoredRule())
	rules.Register(NewISODateAsLocalDateRule())
	rules.Register(NewDocumentDateFromNowRule())
	rules.Register(NewAsyncIIFEResultUnawaitedRule())
	rules.Register(NewEnvSecretLiteralFallbackRule())
	rules.Register(NewDefaultInventsDomainValueRule())
	rules.Register(NewMissingAmountCoercedToZeroRule())
	rules.Register(NewCSVCellDisplayFormatterRule())
}

// NextConfigIgnoresBuildErrorsRule detects a Next.js config that builds past
// type errors:
//
//	typescript: { ignoreBuildErrors: true },
//
// The build then ships code the compiler rejected: a page that calls a method
// its context type lacks fails on the first click in production instead of in
// the build. Lint skipped in the build (eslint.ignoreDuringBuilds) is left
// out: projects run it as a separate step.
type NextConfigIgnoresBuildErrorsRule struct {
	*rules.BaseRule
}

// NewNextConfigIgnoresBuildErrorsRule creates the rule
func NewNextConfigIgnoresBuildErrorsRule() *NextConfigIgnoresBuildErrorsRule {
	return &NextConfigIgnoresBuildErrorsRule{BaseRule: rules.NewBaseRule(
		"next-config-ignores-build-errors",
		"patterns",
		"Detects a Next.js config that builds past type errors — code the compiler rejected reaches production",
		core.SeverityHigh,
	)}
}

var (
	nextConfigFile  = regexp.MustCompile(`^next\.config\.(?:js|mjs|cjs|ts|mts)$`)
	nextIgnoreError = regexp.MustCompile(`\bignoreBuildErrors\s*:\s*true\b`)
)

// AnalyzeFile reports the switches that skip the checks of the build.
func (r *NextConfigIgnoresBuildErrorsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !nextConfigFile.MatchString(filepath.Base(ctx.RelPath)) || patternkit.SkipFrontendPath(ctx) {
		return nil
	}
	var violations []*core.Violation
	for i, line := range helpers.FileJSText(ctx) {
		if nextIgnoreError.MatchString(line) {
			violations = patternkit.JsReport(violations, r.BaseRule, ctx, i+1,
				"Next.js build ignores type errors — code the compiler rejected reaches production",
				"Remove the switch and fix the type errors the build reports")
		}
	}
	return violations
}

// FrontendWarnedFallbackRule detects a missing setting or a failed load in
// production frontend code answered with a warning and a substitute:
//
//	if (!currency?.code) {
//		logger.warn('Default currency not configured, using USDC fallback')
//		return api.address('USDC')
//	}
//
// The page goes on with a value nobody chose, and the warning lands in a
// console nobody reads. A branch that warns and then throws is left out.
type FrontendWarnedFallbackRule struct {
	*rules.BaseRule
}

// NewFrontendWarnedFallbackRule creates the rule
func NewFrontendWarnedFallbackRule() *FrontendWarnedFallbackRule {
	return &FrontendWarnedFallbackRule{BaseRule: rules.NewBaseRule(
		"frontend-warned-fallback",
		"patterns",
		"Detects a frontend branch that warns about a missing setting or failed load and goes on with a substitute",
		core.SeverityMedium,
	)}
}

var (
	jsWarnCall        = regexp.MustCompile(`\b(?:console|logger|log)\s*\.\s*warn\s*\(`)
	jsFallbackMessage = regexp.MustCompile(`(?i)fallback|using defaults?\b|not configured|не настроен|по умолчанию`)
	jsBranchHeader    = regexp.MustCompile(`^(?:else\b|(?:else\s+)?if\s*\(|catch\b)`)
	jsThrow           = regexp.MustCompile(`\bthrow\b`)
)

// AnalyzeFile reports the warnings that announce a substitute.
func (r *FrontendWarnedFallbackRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := patternkit.NewJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsWarnCall.FindAllStringIndex(f.Code, -1) {
		end, ok := f.Closing(m[1] - 1)
		if !ok || !jsFallbackMessage.MatchString(f.Text[m[1]:end]) {
			continue
		}
		brace := f.EnclosingBrace(m[0])
		if brace < 0 {
			continue
		}
		head, _ := f.Header(brace)
		blockEnd, ok := f.Closing(brace)
		if !ok || !jsBranchHeader.MatchString(head) || jsThrow.MatchString(f.Code[brace:blockEnd]) {
			continue
		}
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, f.Line(m[0]),
			"Branch warns and goes on with a substitute — the page runs on a value nobody chose",
			"Fail the operation and show the error, or require the setting at startup")
	}
	return violations
}

// AllSettledRejectionsIgnoredRule detects Promise.allSettled whose results are
// read for the fulfilled ones only:
//
//	const settled = await Promise.allSettled(types.map(load))
//	for (const r of settled) if (r.status === 'fulfilled') all.push(...r.value)
//
// A failed load disappears without a trace: the list is shorter and nothing
// says why. The function that reads 'fulfilled' must also read the rejected
// results or their reason.
type AllSettledRejectionsIgnoredRule struct {
	*rules.BaseRule
}

// NewAllSettledRejectionsIgnoredRule creates the rule
func NewAllSettledRejectionsIgnoredRule() *AllSettledRejectionsIgnoredRule {
	return &AllSettledRejectionsIgnoredRule{BaseRule: rules.NewBaseRule(
		"allsettled-rejections-ignored",
		"patterns",
		"Detects Promise.allSettled whose results are read for the fulfilled ones only — failures disappear without a trace",
		core.SeverityMedium,
	)}
}

var (
	jsAllSettled      = regexp.MustCompile(`\bPromise\s*\.\s*allSettled\s*\(`)
	jsFulfilledStatus = regexp.MustCompile(`['"` + "`" + `]fulfilled['"` + "`" + `]`)
	jsRejectedRead    = regexp.MustCompile(`\brejected\b|\.\s*reason\b`)
)

// AnalyzeFile reports the allSettled calls whose failures nobody reads.
func (r *AllSettledRejectionsIgnoredRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := patternkit.NewJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsAllSettled.FindAllStringIndex(f.Code, -1) {
		fn, ok := f.EnclosingFunction(m[0])
		if !ok {
			continue
		}
		end, ok := f.Closing(fn.Brace)
		if !ok {
			continue
		}
		body := f.Text[fn.Brace:end]
		if !jsFulfilledStatus.MatchString(body) || jsRejectedRead.MatchString(body) {
			continue
		}
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, f.Line(m[0]),
			"Promise.allSettled results are read for the fulfilled ones only — a failed call disappears without a trace",
			"Handle the rejected results: report their reason or fail the whole operation")
	}
	return violations
}

// ISODateAsLocalDateRule detects a calendar date cut from toISOString in code
// that counts local calendar days:
//
//	yesterday.setDate(yesterday.getDate() - 1)
//	const to = yesterday.toISOString().split('T')[0]
//
// toISOString is the UTC date: east of UTC a local midnight or morning is the
// previous UTC day, so the range starts and ends a day early.
type ISODateAsLocalDateRule struct {
	*rules.BaseRule
}

// NewISODateAsLocalDateRule creates the rule
func NewISODateAsLocalDateRule() *ISODateAsLocalDateRule {
	return &ISODateAsLocalDateRule{BaseRule: rules.NewBaseRule(
		"iso-date-as-local-date",
		"patterns",
		"Detects a date cut from toISOString next to local calendar arithmetic — the UTC date is a day off east of UTC",
		core.SeverityMedium,
	)}
}

var (
	jsISODateCut  = regexp.MustCompile(`\.\s*toISOString\s*\(\s*\)\s*\.\s*(?:split\s*\(\s*['"]T['"]\s*\)|slice\s*\(\s*0\s*,\s*10\s*\)|substring\s*\(\s*0\s*,\s*10\s*\))`)
	jsLocalDateOp = regexp.MustCompile(`\.\s*(?:set|get)(?:Date|Month|FullYear|Hours|Day)\s*\(|\bnew\s+Date\s*\(\s*[^(),\s]+\s*,`)
)

// AnalyzeFile reports the UTC dates taken in local calendar code.
func (r *ISODateAsLocalDateRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := patternkit.NewJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsISODateCut.FindAllStringIndex(f.Text, -1) {
		fn, ok := f.EnclosingFunction(m[0])
		if !ok {
			continue
		}
		end, ok := f.Closing(fn.Brace)
		if !ok || !jsLocalDateOp.MatchString(f.Code[fn.Brace:end]) {
			continue
		}
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, f.Line(m[0]),
			"Date cut from toISOString in code that counts local days — the UTC date is a day off east of UTC",
			"Format the local date from getFullYear/getMonth/getDate, or count the days in UTC throughout")
	}
	return violations
}

// DocumentDateFromNowRule detects the date of a document taken from the
// current time:
//
//	<p>Last updated: {new Date().toLocaleDateString()}</p>
//
// Every visitor sees today's date: the terms look changed every day, and the
// real date of the last change is lost.
type DocumentDateFromNowRule struct {
	*rules.BaseRule
}

// NewDocumentDateFromNowRule creates the rule
func NewDocumentDateFromNowRule() *DocumentDateFromNowRule {
	return &DocumentDateFromNowRule{BaseRule: rules.NewBaseRule(
		"document-date-from-now",
		"patterns",
		"Detects the update date of a document rendered from the current time — every visitor sees today",
		core.SeverityMedium,
	)}
}

var (
	jsDocumentDateLabel = regexp.MustCompile(`(?i)последнее обновление|последние изменения|дата вступления|редакция от|last updated|last modified|effective date|updated on`)
	jsCurrentTime       = regexp.MustCompile(`\bnew\s+Date\s*\(\s*\)`)
)

// AnalyzeFile reports the document dates that are the time of the view.
func (r *DocumentDateFromNowRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for i, line := range helpers.FileJSText(ctx) {
		if jsDocumentDateLabel.MatchString(line) && jsCurrentTime.MatchString(line) {
			violations = patternkit.JsReport(violations, r.BaseRule, ctx, i+1,
				"Document date is the current time — every visitor sees today's date",
				"Write the date of the document's last change as a constant next to its text")
		}
	}
	return violations
}

// AsyncIIFEResultUnawaitedRule detects the result of an async IIFE kept as a
// value and never awaited:
//
//	const fallback = (async () => { ... })()
//	set({ eth: fallback })
//
// The variable holds a Promise: the state gets "[object Promise]" instead of
// the value, and a rejection is unhandled.
type AsyncIIFEResultUnawaitedRule struct {
	*rules.BaseRule
}

// NewAsyncIIFEResultUnawaitedRule creates the rule
func NewAsyncIIFEResultUnawaitedRule() *AsyncIIFEResultUnawaitedRule {
	return &AsyncIIFEResultUnawaitedRule{BaseRule: rules.NewBaseRule(
		"async-iife-result-unawaited",
		"patterns",
		"Detects the result of an async IIFE stored and never awaited — the variable holds a Promise, not the value",
		core.SeverityHigh,
	)}
}

var jsAsyncIIFEBinding = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*\(\s*async\b`)

// AnalyzeFile reports the async IIFE results that stay promises.
func (r *AsyncIIFEResultUnawaitedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := patternkit.NewJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsAsyncIIFEBinding.FindAllStringSubmatchIndex(f.Code, -1) {
		open := strings.LastIndexByte(f.Code[:m[1]], '(')
		end, ok := f.Closing(open)
		if !ok || !strings.HasPrefix(strings.TrimSpace(f.Code[end+1:]), "(") {
			continue
		}
		scopeEnd := len(f.Code)
		if brace := f.EnclosingBrace(m[0]); brace >= 0 {
			if e, ok := f.Closing(brace); ok {
				scopeEnd = e
			}
		}
		name := f.Code[m[2]:m[3]]
		if promiseHandled(f.Code[end:scopeEnd], name) {
			continue
		}
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, f.Line(m[0]),
			"Async IIFE result "+name+" is never awaited — the variable holds a Promise, not the value",
			"Await the IIFE where it is defined, or await "+name+" before its value is used")
	}
	return violations
}

// promiseHandled reports a promise variable that the code awaits, chains,
// returns or hands to a Promise combinator.
func promiseHandled(code, name string) bool {
	id := regexp.QuoteMeta(name)
	handled := regexp.MustCompile(`\bawait\s+` + id + `\b|(?:^|[^.\w$])` + id + `\s*\.\s*(?:then|catch|finally)\b|\breturn\s+` + id + `\b`)
	if handled.MatchString(code) {
		return true
	}
	combinator := regexp.MustCompile(`\bPromise\s*\.\s*(?:all|allSettled|race|any)\s*\(`)
	use := regexp.MustCompile(`(?:^|[^.\w$])` + id + `\b`)
	for _, m := range combinator.FindAllStringIndex(code, -1) {
		if end, ok := closingIn(code, m[1]-1); ok && use.MatchString(code[m[1]:end]) {
			return true
		}
	}
	return false
}

// EnvSecretLiteralFallbackRule detects a credential read from the environment
// with a literal fallback:
//
//	password: process.env.TEST_DB_PASSWORD || 'devpass',
//
// Wherever the variable is missing the code runs on the password from the
// source, and the source carries the secret. Tests are checked too: a test
// config with a real DSN is the usual place for it.
type EnvSecretLiteralFallbackRule struct {
	*rules.BaseRule
}

// NewEnvSecretLiteralFallbackRule creates the rule
func NewEnvSecretLiteralFallbackRule() *EnvSecretLiteralFallbackRule {
	return &EnvSecretLiteralFallbackRule{BaseRule: rules.NewBaseRule(
		"env-secret-literal-fallback",
		"patterns",
		"Detects a credential from process.env with a literal fallback — the secret lives in the source and works where the variable is missing",
		core.SeverityHigh,
	)}
}

var (
	jsEnvLiteralFallback = regexp.MustCompile(`process\.env(?:\.([A-Za-z0-9_]+)|\[\s*['"]([A-Za-z0-9_]+)['"]\s*\])\s*(?:\|\||\?\?)\s*(?:'[^']|"[^"]|` + "`[^`]" + `)`)
	envSecretName        = regexp.MustCompile(`(?i)PASSWORD|PASSWD|SECRET|TOKEN|DSN|API_?KEY|PRIVATE_?KEY|DATABASE_URL|CREDENTIAL`)
)

// AnalyzeFile reports the credentials with a fallback in the source.
func (r *EnvSecretLiteralFallbackRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || patternkit.IsVendoredOrGeneratedPath(filepath.ToSlash(ctx.RelPath)) {
		return nil
	}
	var violations []*core.Violation
	for i, line := range helpers.FileJSText(ctx) {
		for _, m := range jsEnvLiteralFallback.FindAllStringSubmatch(line, -1) {
			if envSecretName.MatchString(m[1] + m[2]) {
				violations = patternkit.JsReport(violations, r.BaseRule, ctx, i+1,
					"Credential from the environment falls back to a literal — the secret is in the source and used wherever the variable is missing",
					"Require the variable and fail when it is missing; keep the value in an env file outside the repository")
				break
			}
		}
	}
	return violations
}

// DefaultInventsDomainValueRule detects a missing domain value replaced with
// a made-up one in production frontend code:
//
//	network: w.network ?? 'polygon',
//	serviceFee: w.serviceFee?.toString() ?? '0',
//	const total = parseFloat(balance.total || '0')
//	async depositAddress(currency: string = 'USDC') { ... }
//
// The record says nothing about the network or the fee, and the screen shows
// a polygon payout without a fee; a caller that forgets the currency gets the
// USDC address. A missing value is shown as missing or rejected.
type DefaultInventsDomainValueRule struct {
	*rules.BaseRule
}

// NewDefaultInventsDomainValueRule creates the rule
func NewDefaultInventsDomainValueRule() *DefaultInventsDomainValueRule {
	return &DefaultInventsDomainValueRule{BaseRule: rules.NewBaseRule(
		"default-invents-domain-value",
		"patterns",
		"Detects a missing network, currency or money field replaced with a made-up value in frontend code, and in Go an unknown variant kept with a made-up domain value in a switch default, a failed rate or amount lookup answered with a made-up number, and a first-non-empty helper that fills an identity field with a literal or a company's field",
		core.SeverityMedium,
	)}
}

// inventsDomainCode reports a default of the pattern that is a network or
// currency code, not a placeholder for a missing value.
func inventsDomainCode(re *regexp.Regexp, line string) bool {
	for _, m := range re.FindAllStringSubmatch(line, -1) {
		if patternkit.JsDomainCode.MatchString(m[1]) && !patternkit.JsMissingWord.MatchString(m[1]) {
			return true
		}
	}
	return false
}

// moneyFieldZeroed reports a money field of a record defaulted to 0. A field
// of an optional lookup (byStatus('x')?.amount: no group, no sum) and a
// default inside a comparison are left out.
func moneyFieldZeroed(line string) bool {
	for _, m := range patternkit.JsMoneyFieldZero.FindAllStringSubmatch(line, -1) {
		if m[1] == "" {
			return true
		}
	}
	return false
}

// AnalyzeFile reports the invented domain values.
func (r *DefaultInventsDomainValueRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.HasGoAST() {
		return patternkit.AnalyzeGoFunctions(ctx, func(fn *ast.FuncDecl) []*core.Violation {
			violations := r.checkGoSwitchDefaults(ctx, fn)
			violations = append(violations, r.checkGoLookupMissLiterals(ctx, fn)...)
			return append(violations, r.checkGoCoalesceDefaults(ctx, fn)...)
		})
	}
	if !productionFrontendFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for i, line := range helpers.FileJSText(ctx) {
		switch {
		case inventsDomainCode(patternkit.JsDomainFieldDefault, line), inventsDomainCode(patternkit.JsDomainParamDefault, line):
			violations = patternkit.JsReport(violations, r.BaseRule, ctx, i+1,
				"Missing network or currency replaced with a fixed one — the screen or the call works on a value the data does not have",
				"Show the value as missing, or require it from the caller")
		case moneyFieldZeroed(line):
			violations = patternkit.JsReport(violations, r.BaseRule, ctx, i+1,
				"Missing money field shown as 0 — a record without the amount looks like a zero amount",
				"Show the field as missing, or reject the record without it")
		}
	}
	return violations
}

// checkGoSwitchDefaults reports a switch over a field of external data
// whose cases are string literals (the source's vocabulary) and whose default
// keeps the record with a domain constant made up for it:
//
//	switch action.Type {
//	case "ChainTransfer": ...
//	default:
//	    tx.Direction = model.DirectionOut // an unknown event becomes an outgoing transfer
//	}
//
// A constant naming the unknown (DirectionUnknown, KindOther) is a visible
// label and is left alone; so is a default that leaves the flow.
func (r *DefaultInventsDomainValueRule) checkGoSwitchDefaults(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		if _, ok := sw.Tag.(*ast.SelectorExpr); !ok {
			return true
		}
		def := literalSwitchDefault(sw)
		if def == nil {
			return true
		}
		for _, stmt := range def.Body {
			if _, ok := stmt.(*ast.ReturnStmt); ok {
				return true
			}
			if _, ok := stmt.(*ast.BranchStmt); ok {
				return true
			}
		}
		for _, stmt := range def.Body {
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				continue
			}
			if _, ok := assign.Lhs[0].(*ast.SelectorExpr); !ok {
				continue
			}
			value, ok := assign.Rhs[0].(*ast.SelectorExpr)
			if !ok || namesMissingValue(value.Sel.Name) {
				continue
			}
			if _, ok := value.X.(*ast.Ident); !ok {
				continue
			}
			line := ctx.LineFor(assign)
			v := r.CreateViolation(ctx.RelPath, line,
				"Unknown variant kept with a made-up "+types.ExprString(assign.Lhs[0])+" - a value the source did not send passes for a known one")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Skip or reject the unknown variant, or store it with a value that says unknown")
			violations = append(violations, v)
		}
		return true
	})
	return violations
}

// literalSwitchDefault returns the default clause of a switch whose other
// cases are all string literals.
func literalSwitchDefault(sw *ast.SwitchStmt) *ast.CaseClause {
	var def *ast.CaseClause
	cases := 0
	for _, stmt := range sw.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			return nil
		}
		if clause.List == nil {
			def = clause
			continue
		}
		for _, expr := range clause.List {
			lit, ok := expr.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return nil
			}
		}
		cases++
	}
	if cases == 0 {
		return nil
	}
	return def
}

// namesMissingValue reports a constant whose name says the value is not
// known: DirectionUnknown, KindOther.
func namesMissingValue(name string) bool {
	for _, word := range helpers.IdentifierWords(name) {
		switch strings.ToLower(word) {
		case "unknown", "other", "unclassified", "unsupported", "none", "unspecified":
			return true
		}
	}
	return false
}

// MissingAmountCoercedToZeroRule detects a parser of untyped input that
// answers what it cannot read with 0, applied to money fields:
//
//	function parseSafe(value: unknown): number {
//		return typeof value === 'number' ? value : 0
//	}
//	amount: parseSafe(txn.amount)
//
// A payload without the amount shows as a zero-amount operation, and the sum
// over the list is wrong without a sign of it. Metric properties defaulted to
// zero are also reported: stats?.requestCount ?? 0 presents missing data as a
// measured count. A local value and a comparison against zero are left out.
type MissingAmountCoercedToZeroRule struct {
	*rules.BaseRule
}

const defaultMetricWords = "Count|Total|Sum|Avg|Average|Rate|Ratio|Pct|Percent|Usd"

// NewMissingAmountCoercedToZeroRule creates the rule
func NewMissingAmountCoercedToZeroRule() *MissingAmountCoercedToZeroRule {
	return &MissingAmountCoercedToZeroRule{BaseRule: rules.NewBaseRule(
		"missing-amount-coerced-to-zero",
		"patterns",
		"Detects a parser that turns unreadable input into 0, applied to money fields, and in Go a nil amount replaced with decimal.Zero — a missing amount becomes a zero amount",
		core.SeverityHigh,
	).DeclareSettings(rules.NewSettingSpec("metric_words", "string", defaultMetricWords, "Pipe-separated metric words that identify amount fields.", "Count|Total|Usd"))}
}

var (
	jsUntypedNumberParser    = regexp.MustCompile(`(?:\bfunction\s+([A-Za-z_$][\w$]*)|\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*)\s*\(\s*[A-Za-z_$][\w$]*\s*\??\s*:\s*(?:unknown|any)\s*\)\s*:\s*number\s*(?:=>\s*)?`)
	jsZeroResult             = regexp.MustCompile(`(?:[?:]|\breturn|\|\||\?\?)\s*0\s*(?:[;})\n]|$)|,\s*0\s*\)`)
	jsMetricPath             = `(?:[A-Za-z_$][\w$]*\s*(?:\?\.|\.)\s*)*[A-Za-z_$][\w$]*`
	jsMetricFallback         = regexp.MustCompile(`((?:[A-Za-z_$][\w$]*\s*(?:\?\.|\.)\s*)+[A-Za-z_$][\w$]*)\s*(?:\?\?|\|\|)\s*(?:0\b|'0'|"0")`)
	jsMetricTernary          = regexp.MustCompile(`(` + jsMetricPath + `)\s*\?\s*(` + jsMetricPath + `)\s*:\s*(?:0\b|'0'|"0")`)
	jsMetricParserFallback   = regexp.MustCompile(`[A-Za-z_$][\w$]*\s*\(\s*(` + jsMetricPath + `)\s*\)\s*(?:\?\?|\|\|)\s*(?:0\b|'0'|"0")`)
	jsMetricWords            = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)
	jsConditionComparePrefix = regexp.MustCompile(`^(?:===?|!==?|<=|>=|<|>)`)
	jsConditionCompareSuffix = regexp.MustCompile(`(?:===?|!==?|<=|>=|<|>)$`)
)

// Configure reads the optional metric_words setting (pipe-separated).
func (r *MissingAmountCoercedToZeroRule) Configure(settings map[string]any) error {
	return r.BaseRule.Configure(settings)
}

func (r *MissingAmountCoercedToZeroRule) metricWords() map[string]bool {
	words := make(map[string]bool)
	for word := range strings.SplitSeq(r.GetStringSetting("metric_words", defaultMetricWords), "|") {
		word = strings.ToLower(strings.TrimSpace(word))
		if word != "" {
			words[word] = true
		}
	}
	return words
}

func isMetricProperty(name string, words map[string]bool) bool {
	if !jsMetricWords.MatchString(name) {
		return false
	}
	parts := helpers.IdentifierWords(name)
	if len(parts) == 0 {
		return false
	}
	if words[strings.ToLower(parts[len(parts)-1])] {
		return true
	}
	return words["total"] && strings.EqualFold(parts[0], "total")
}

func metricFallbackIsCompared(f patternkit.JsFlat, start, end int) bool {
	code := f.Code
	cursor := end
	for {
		for cursor < len(code) && (code[cursor] == ' ' || code[cursor] == '\t' || code[cursor] == '\r' || code[cursor] == '\n') {
			cursor++
		}
		if cursor >= len(code) || code[cursor] != ')' {
			break
		}
		open := matchingParenOpen(code, cursor)
		if open < 0 || !isGroupingParen(code, open) {
			break
		}
		cursor++
	}
	if jsConditionComparePrefix.MatchString(strings.TrimLeft(code[cursor:], " \t\r\n")) {
		return true
	}

	cursor = start
	for {
		for cursor > 0 && (code[cursor-1] == ' ' || code[cursor-1] == '\t' || code[cursor-1] == '\r' || code[cursor-1] == '\n') {
			cursor--
		}
		if cursor == 0 || code[cursor-1] != '(' || !isGroupingParen(code, cursor-1) {
			break
		}
		cursor--
	}
	return jsConditionCompareSuffix.MatchString(strings.TrimRight(code[:cursor], " \t\r\n"))
}

func matchingParenOpen(code string, close int) int {
	depth := 0
	for i := close; i >= 0; i-- {
		switch code[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isGroupingParen(code string, open int) bool {
	before := strings.TrimRight(code[:open], " \t\r\n")
	if before == "" {
		return true
	}
	last := before[len(before)-1]
	return (last < 'a' || last > 'z') && (last < 'A' || last > 'Z') && (last < '0' || last > '9') && last != '_' && last != '$' && last != ')' && last != ']'
}

func (r *MissingAmountCoercedToZeroRule) metricFallbackViolations(ctx *core.FileContext, f patternkit.JsFlat) []*core.Violation {
	var violations []*core.Violation
	words := r.metricWords()
	addMetric := func(start, end int, property string) {
		last := property[strings.LastIndexAny(property, ".")+1:]
		last = strings.TrimPrefix(last, "?")
		if !isMetricProperty(last, words) || metricFallbackIsCompared(f, start, end) {
			return
		}
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, f.Line(start),
			"Missing metric "+last+" shown as 0 — the result presents an unknown value as a measured zero",
			"Keep the metric missing, or show an explicit unavailable value")
	}
	for _, match := range jsMetricFallback.FindAllStringSubmatchIndex(f.Text, -1) {
		addMetric(match[0], match[1], f.Code[match[2]:match[3]])
	}
	for _, match := range jsMetricTernary.FindAllStringSubmatchIndex(f.Text, -1) {
		condition := strings.ReplaceAll(strings.TrimSpace(f.Code[match[2]:match[3]]), "?.", ".")
		value := strings.ReplaceAll(strings.TrimSpace(f.Code[match[4]:match[5]]), "?.", ".")
		if value != condition && !strings.HasPrefix(value, condition+".") {
			continue
		}
		addMetric(match[0], match[1], f.Code[match[4]:match[5]])
	}
	for _, match := range jsMetricParserFallback.FindAllStringSubmatchIndex(f.Text, -1) {
		addMetric(match[0], match[1], f.Code[match[2]:match[3]])
	}
	return violations
}

// jsMoneyArgument is a call argument that reads a money field.
const jsMoneyArgument = `\s*\(\s*[\w$.?\[\]]*\.\s*\w*(?:[Aa]mount|[Ff]ee|[Bb]alance|[Pp]rice|[Tt]otal|[Yy]ield)\b`

// AnalyzeFile reports the zero-answering parsers used on money.
func (r *MissingAmountCoercedToZeroRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.HasGoAST() {
		return r.analyzeGoMissingAmounts(ctx)
	}
	if !productionFrontendFile(ctx) || ctx.IsGenerated() || patternkit.IsVendoredOrGeneratedPath(filepath.ToSlash(ctx.RelPath)) {
		return nil
	}
	f := patternkit.NewJSFlat(ctx)
	var violations []*core.Violation
	violations = append(violations, r.metricFallbackViolations(ctx, f)...)
	for _, m := range jsUntypedNumberParser.FindAllStringSubmatchIndex(f.Code, -1) {
		name := ""
		for _, g := range []int{2, 4} {
			if m[g] >= 0 {
				name = f.Code[m[g]:m[g+1]]
			}
		}
		if !jsZeroResult.MatchString(arrowOrBlockBody(f, m[1])) {
			continue
		}
		if !regexp.MustCompile(`(?:^|[^.\w$])` + regexp.QuoteMeta(name) + jsMoneyArgument).MatchString(f.Code) {
			continue
		}
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, f.Line(m[0]),
			name+" answers unreadable input with 0 and is applied to money fields — a missing amount shows as zero",
			"Return an error or undefined for unreadable input and show the field as missing")
	}
	for _, head := range zeroCoercingFormatters(f) {
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, f.Line(head.pos),
			head.name+" renders a missing or unreadable value as 0 — the screen shows a real-looking $0.00 or 0.00% for data that is not there",
			"Answer a value that is not a finite number with a dash (or an empty cell), not with 0")
	}
	return violations
}

// jsFormatterHead is the start of a function whose first parameter carries
// a type: function formatUsd(value: ... or const formatPct = (value: ...
var jsFormatterHead = regexp.MustCompile(`(?:\bfunction\s+([A-Za-z_$][\w$]*)\s*|\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*)\(\s*([A-Za-z_$][\w$]*)\s*(\??)\s*:`)

var (
	jsFormatterName   = regexp.MustCompile(`^(?:format|fmt|display|render)[A-Z0-9_]`)
	jsMissingType     = regexp.MustCompile(`\b(?:unknown|any|undefined|null)\b`)
	jsStringResult    = regexp.MustCompile(`^\s*:\s*string\s*(=>\s*)?`)
	jsCurrencyStyle   = regexp.MustCompile(`style\s*:\s*['"]currency['"]`)
	jsZeroAsMissingOf = func(v string) *regexp.Regexp {
		return regexp.MustCompile(`!\s*` + regexp.QuoteMeta(v) + `\b|\b` + regexp.QuoteMeta(v) + `\s*===?\s*0\b`)
	}
)

type jsFormatterAt struct {
	name string
	pos  int
}

// zeroCoercingFormatters returns the display formatters that turn a missing
// value into 0: the first parameter admits a missing value (unknown, any,
// undefined, null or optional), the result is a string, and the body
// coerces the parameter with Number(value) || 0, parseFloat(...) || 0 or
// value ?? 0. A body that afterwards treats the zero as missing (if (!n)
// return '-') renders it as missing after all.
func zeroCoercingFormatters(f patternkit.JsFlat) []jsFormatterAt {
	var found []jsFormatterAt
	for _, m := range jsFormatterHead.FindAllStringSubmatchIndex(f.Code, -1) {
		name := ""
		for _, g := range []int{2, 4} {
			if m[g] >= 0 {
				name = f.Code[m[g]:m[g+1]]
			}
		}
		param := f.Code[m[6]:m[7]]
		open := strings.LastIndexByte(f.Code[m[0]:m[6]], '(') + m[0]
		closeParen, ok := f.Closing(open)
		if !ok {
			continue
		}
		paramType := f.Code[m[1]:closeParen]
		if comma := strings.IndexByte(paramType, ','); comma >= 0 {
			paramType = paramType[:comma]
		}
		if m[9] == m[8] && !jsMissingType.MatchString(paramType) {
			continue
		}
		result := jsStringResult.FindStringIndex(f.Code[closeParen+1:])
		if result == nil {
			continue
		}
		body := arrowOrBlockBody(f, closeParen+1+result[1])
		if !jsFormatterName.MatchString(name) && !jsCurrencyStyle.MatchString(body) {
			continue
		}
		p := regexp.QuoteMeta(param)
		coercion := regexp.MustCompile(`(?:\b(?:Number|parseFloat|parseInt)\(\s*(?:String\(\s*)?` + p + `\s*\)?\s*\)\s*\|\|\s*0\b|\b` + p + `\s*\?\?\s*0\b)`)
		loc := coercion.FindStringIndex(body)
		if loc == nil {
			continue
		}
		lineStart := strings.LastIndexAny(body[:loc[0]], "\n;{") + 1
		if v := regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=`).FindStringSubmatch(body[lineStart:loc[0]]); v != nil && jsZeroAsMissingOf(v[1]).MatchString(body[loc[1]:]) {
			continue
		}
		found = append(found, jsFormatterAt{name: name, pos: m[0]})
	}
	return found
}

// arrowOrBlockBody returns the body that starts at pos: a '{' block, or an
// expression up to the end of its line.
func arrowOrBlockBody(f patternkit.JsFlat, pos int) string {
	rest := f.Code[pos:]
	if trimmed := strings.TrimLeft(rest, " \t\n"); strings.HasPrefix(trimmed, "{") {
		open := pos + len(rest) - len(trimmed)
		if end, ok := f.Closing(open); ok {
			return f.Code[open : end+1]
		}
	}
	if before, _, ok := strings.Cut(rest, "\n"); ok {
		return before
	}
	return rest
}

// CSVCellDisplayFormatterRule detects a display formatter writing a CSV cell:
//
//	const rows = months.map(m => [m.start, formatters.formatAmount(m.yield)])
//	downloadCsv('all.csv', buildCsv(header, rows))
//
// A display formatter adds thousands separators, a currency sign and a
// locale's decimal comma: the spreadsheet reads the cell as text, and sums
// over the column are empty. Reported in a file named for CSV, and in an
// array literal of a block that builds a CSV.
type CSVCellDisplayFormatterRule struct {
	*rules.BaseRule
}

// NewCSVCellDisplayFormatterRule creates the rule
func NewCSVCellDisplayFormatterRule() *CSVCellDisplayFormatterRule {
	return &CSVCellDisplayFormatterRule{BaseRule: rules.NewBaseRule(
		"csv-cell-display-formatter",
		"patterns",
		"Detects a display number formatter writing a CSV cell — separators and currency signs turn the number into text",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the display formatters in CSV cells.
func (r *CSVCellDisplayFormatterRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	csvFile := patternkit.JsCSVMention.MatchString(filepath.Base(ctx.RelPath))
	f := patternkit.NewJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range patternkit.JsDisplayFormatterCall.FindAllStringSubmatchIndex(f.Code, -1) {
		if patternkit.JsPlainFormatter.MatchString(f.Code[m[2]:m[3]]) {
			continue
		}
		if !csvFile && !f.InCSVRow(m[0]) {
			continue
		}
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, f.Line(m[0]),
			"Display formatter writes a CSV cell — separators and currency signs make the spreadsheet read the number as text",
			"Write the plain number with a dot as the decimal separator; format it in the spreadsheet")
	}
	return violations
}
