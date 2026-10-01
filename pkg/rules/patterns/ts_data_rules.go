package patterns

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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

// jsReport appends the finding of a frontend rule at a line unless the line
// suppresses it.
func jsReport(violations []*core.Violation, rule *rules.BaseRule, ctx *core.FileContext, line int, message, suggestion string) []*core.Violation {
	if ctx.IsSuppressed(line, rule.Name()) {
		return violations
	}
	return append(violations, sqlViolation(rule, ctx, line, message, suggestion))
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
	if !nextConfigFile.MatchString(filepath.Base(ctx.RelPath)) || skipFrontendPath(ctx) {
		return nil
	}
	var violations []*core.Violation
	for i, line := range helpers.FileJSText(ctx) {
		if nextIgnoreError.MatchString(line) {
			violations = jsReport(violations, r.BaseRule, ctx, i+1,
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
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsWarnCall.FindAllStringIndex(f.code, -1) {
		end, ok := f.closing(m[1] - 1)
		if !ok || !jsFallbackMessage.MatchString(f.text[m[1]:end]) {
			continue
		}
		brace := f.enclosingBrace(m[0])
		if brace < 0 {
			continue
		}
		head, _ := f.header(brace)
		blockEnd, ok := f.closing(brace)
		if !ok || !jsBranchHeader.MatchString(head) || jsThrow.MatchString(f.code[brace:blockEnd]) {
			continue
		}
		violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
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
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsAllSettled.FindAllStringIndex(f.code, -1) {
		fn, ok := f.enclosingFunction(m[0])
		if !ok {
			continue
		}
		end, ok := f.closing(fn.brace)
		if !ok {
			continue
		}
		body := f.text[fn.brace:end]
		if !jsFulfilledStatus.MatchString(body) || jsRejectedRead.MatchString(body) {
			continue
		}
		violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
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
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsISODateCut.FindAllStringIndex(f.text, -1) {
		fn, ok := f.enclosingFunction(m[0])
		if !ok {
			continue
		}
		end, ok := f.closing(fn.brace)
		if !ok || !jsLocalDateOp.MatchString(f.code[fn.brace:end]) {
			continue
		}
		violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
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
			violations = jsReport(violations, r.BaseRule, ctx, i+1,
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
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsAsyncIIFEBinding.FindAllStringSubmatchIndex(f.code, -1) {
		open := strings.LastIndexByte(f.code[:m[1]], '(')
		end, ok := f.closing(open)
		if !ok || !strings.HasPrefix(strings.TrimSpace(f.code[end+1:]), "(") {
			continue
		}
		scopeEnd := len(f.code)
		if brace := f.enclosingBrace(m[0]); brace >= 0 {
			if e, ok := f.closing(brace); ok {
				scopeEnd = e
			}
		}
		name := f.code[m[2]:m[3]]
		if promiseHandled(f.code[end:scopeEnd], name) {
			continue
		}
		violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
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
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || isVendoredOrGeneratedPath(filepath.ToSlash(ctx.RelPath)) {
		return nil
	}
	var violations []*core.Violation
	for i, line := range helpers.FileJSText(ctx) {
		for _, m := range jsEnvLiteralFallback.FindAllStringSubmatch(line, -1) {
			if envSecretName.MatchString(m[1] + m[2]) {
				violations = jsReport(violations, r.BaseRule, ctx, i+1,
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
		"Detects a missing network, currency or money field replaced with a made-up value in frontend code",
		core.SeverityMedium,
	)}
}

const jsDomainNames = `network|chain|currency|token|asset|symbol|coin`

var (
	jsDomainFieldDefault = regexp.MustCompile(`\.\s*(?:` + jsDomainNames + `)\s*(?:\?\?|\|\|)\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]`)
	jsDomainParamDefault = regexp.MustCompile(`[(,{]\s*(?:` + jsDomainNames + `)\s*(?::\s*string\s*)?=\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]`)
	// jsDomainCode is a value that names a network or a currency: USDC,
	// polygon, eth-mainnet. Words for a missing value are not codes.
	jsDomainCode     = regexp.MustCompile(`^[A-Za-z][\w.-]*$`)
	jsMissingWord    = regexp.MustCompile(`(?i)^(?:unknown|none|n/?a|null|undefined|tbd|empty|missing)$`)
	jsMoneyFieldZero = regexp.MustCompile(`(?:^|[^?])\.\s*\w*(?:[Aa]mount|[Ff]ee|[Bb]alance|[Pp]rice)\s*(?:\?\.\s*toString\s*\(\s*\))?\s*\?\?\s*(?:'0'|"0"|0\b)\s*\)?\s*([<>!=]?)`)
)

// inventsDomainCode reports a default of the pattern that is a network or
// currency code, not a placeholder for a missing value.
func inventsDomainCode(re *regexp.Regexp, line string) bool {
	for _, m := range re.FindAllStringSubmatch(line, -1) {
		if jsDomainCode.MatchString(m[1]) && !jsMissingWord.MatchString(m[1]) {
			return true
		}
	}
	return false
}

// moneyFieldZeroed reports a money field of a record defaulted to 0. A field
// of an optional lookup (byStatus('x')?.amount: no group, no sum) and a
// default inside a comparison are left out.
func moneyFieldZeroed(line string) bool {
	for _, m := range jsMoneyFieldZero.FindAllStringSubmatch(line, -1) {
		if m[1] == "" {
			return true
		}
	}
	return false
}

// AnalyzeFile reports the invented domain values.
func (r *DefaultInventsDomainValueRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for i, line := range helpers.FileJSText(ctx) {
		switch {
		case inventsDomainCode(jsDomainFieldDefault, line), inventsDomainCode(jsDomainParamDefault, line):
			violations = jsReport(violations, r.BaseRule, ctx, i+1,
				"Missing network or currency replaced with a fixed one — the screen or the call works on a value the data does not have",
				"Show the value as missing, or require it from the caller")
		case moneyFieldZeroed(line):
			violations = jsReport(violations, r.BaseRule, ctx, i+1,
				"Missing money field shown as 0 — a record without the amount looks like a zero amount",
				"Show the field as missing, or reject the record without it")
		}
	}
	return violations
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
// over the list is wrong without a sign of it.
type MissingAmountCoercedToZeroRule struct {
	*rules.BaseRule
}

// NewMissingAmountCoercedToZeroRule creates the rule
func NewMissingAmountCoercedToZeroRule() *MissingAmountCoercedToZeroRule {
	return &MissingAmountCoercedToZeroRule{BaseRule: rules.NewBaseRule(
		"missing-amount-coerced-to-zero",
		"patterns",
		"Detects a parser that turns unreadable input into 0, applied to money fields — a missing amount becomes a zero amount",
		core.SeverityHigh,
	)}
}

var (
	jsUntypedNumberParser = regexp.MustCompile(`(?:\bfunction\s+([A-Za-z_$][\w$]*)|\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*)\s*\(\s*[A-Za-z_$][\w$]*\s*\??\s*:\s*(?:unknown|any)\s*\)\s*:\s*number\s*(?:=>\s*)?`)
	jsZeroResult          = regexp.MustCompile(`(?:[?:]|\breturn|\|\||\?\?)\s*0\s*(?:[;})\n]|$)|,\s*0\s*\)`)
)

// jsMoneyArgument is a call argument that reads a money field.
const jsMoneyArgument = `\s*\(\s*[\w$.?\[\]]*\.\s*\w*(?:[Aa]mount|[Ff]ee|[Bb]alance|[Pp]rice|[Tt]otal|[Yy]ield)\b`

// AnalyzeFile reports the zero-answering parsers used on money.
func (r *MissingAmountCoercedToZeroRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsUntypedNumberParser.FindAllStringSubmatchIndex(f.code, -1) {
		name := ""
		for _, g := range []int{2, 4} {
			if m[g] >= 0 {
				name = f.code[m[g]:m[g+1]]
			}
		}
		if !jsZeroResult.MatchString(arrowOrBlockBody(f, m[1])) {
			continue
		}
		if !regexp.MustCompile(`(?:^|[^.\w$])` + regexp.QuoteMeta(name) + jsMoneyArgument).MatchString(f.code) {
			continue
		}
		violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
			name+" answers unreadable input with 0 and is applied to money fields — a missing amount shows as zero",
			"Return an error or undefined for unreadable input and show the field as missing")
	}
	return violations
}

// arrowOrBlockBody returns the body that starts at pos: a '{' block, or an
// expression up to the end of its line.
func arrowOrBlockBody(f jsFlat, pos int) string {
	rest := f.code[pos:]
	if trimmed := strings.TrimLeft(rest, " \t\n"); strings.HasPrefix(trimmed, "{") {
		open := pos + len(rest) - len(trimmed)
		if end, ok := f.closing(open); ok {
			return f.code[open : end+1]
		}
	}
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		return rest[:nl]
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

var (
	jsDisplayFormatterCall = regexp.MustCompile(`\b(format(?:Amount|Money|Currency|Usd|USD|Number|Price|Balance)\w*)\s*\(`)
	jsPlainFormatter       = regexp.MustCompile(`Plain|Raw|Input|Csv|CSV`)
	jsCSVMention           = regexp.MustCompile(`(?i)csv`)
)

// AnalyzeFile reports the display formatters in CSV cells.
func (r *CSVCellDisplayFormatterRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	csvFile := jsCSVMention.MatchString(filepath.Base(ctx.RelPath))
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsDisplayFormatterCall.FindAllStringSubmatchIndex(f.code, -1) {
		if jsPlainFormatter.MatchString(f.code[m[2]:m[3]]) {
			continue
		}
		if !csvFile && !f.inCSVRow(m[0]) {
			continue
		}
		violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
			"Display formatter writes a CSV cell — separators and currency signs make the spreadsheet read the number as text",
			"Write the plain number with a dot as the decimal separator; format it in the spreadsheet")
	}
	return violations
}

// inCSVRow reports a position inside an array literal of a block that builds
// a CSV.
func (f jsFlat) inCSVRow(pos int) bool {
	if f.innermostOpen(pos) != '[' {
		return false
	}
	brace := f.enclosingBrace(pos)
	if brace < 0 {
		return false
	}
	end, ok := f.closing(brace)
	return ok && jsCSVMention.MatchString(f.text[brace:end])
}

// innermostOpen returns the innermost bracket left open before pos, 0 at the
// top level.
func (f jsFlat) innermostOpen(pos int) byte {
	depth := 0
	for i := pos - 1; i >= 0; i-- {
		switch c := f.code[i]; c {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth == 0 {
				return c
			}
			depth--
		}
	}
	return 0
}
