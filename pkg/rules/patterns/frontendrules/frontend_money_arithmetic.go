package frontendrules

import (
	"go/ast"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewFrontendMoneyArithmeticRule())
}

// defaultMoneyFields are field-name fragments treated as money values.
const defaultMoneyFields = "amount|balance|fee|fees|price|profit|yield|deposit|withdrawal|invested|debit|credit"

// FrontendMoneyArithmeticRule detects client-side arithmetic over money
// values in TS/JS:
//
//	investedAmount += parseFloat(inv.amount)
//	pending.reduce((sum, w) => sum + parseFloat(w.amount || '0'), 0)
//
// Financial aggregates must be computed on the backend (single canonical
// calculation logic); parseFloat over decimal strings silently loses
// precision, and duplicated client math diverges from the server.
//
// Not flagged: pure formatting (formatAmount(parseFloat(x))), comparisons,
// non-money numerics, tests.
type FrontendMoneyArithmeticRule struct {
	*rules.BaseRule
	parseCall     *regexp.Regexp
	moneyField    *regexp.Regexp
	reduceRawSum  *regexp.Regexp
	accumulate    *regexp.Regexp
	reduceMarker  string
	numberParsers string
	decimalFields map[string]bool
}

// NewFrontendMoneyArithmeticRule creates the rule
func NewFrontendMoneyArithmeticRule() *FrontendMoneyArithmeticRule {
	r := &FrontendMoneyArithmeticRule{
		BaseRule: rules.NewBaseRule(
			"frontend-money-arithmetic",
			"patterns",
			"Detects client-side arithmetic over money values (must come from backend)",
			core.SeverityHigh,
		),
		parseCall:    regexp.MustCompile(`\b(?:parseFloat|Number)\s*\(`),
		accumulate:   regexp.MustCompile(`\b([\w$]+)\s*[+\-]=\s*(.+)$`),
		reduceMarker: ".reduce(",
	}
	r.numberParsers = `parseFloat|Number|toNumber\w*`
	r.setMoneyFields(defaultMoneyFields)
	r.setNumberParsers(r.numberParsers)
	r.ResetState()
	return r
}

// Configure reads the optional money_fields setting ("a|b|c" fragments).
func (r *FrontendMoneyArithmeticRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.setMoneyFields(r.GetStringSetting("money_fields", defaultMoneyFields))
	r.setNumberParsers(r.GetStringSetting("number_parsers", `parseFloat|Number|toNumber\w*`))
	return nil
}

// ResetState clears project-specific decimal field names.
func (r *FrontendMoneyArithmeticRule) ResetState() { r.decimalFields = make(map[string]bool) }

// UseProjectFiles collects decimal fields declared by the analyzed project.
func (r *FrontendMoneyArithmeticRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	conflicts := make(map[string]bool)
	for _, fields := range decimalJSONStructFields(files) {
		for name := range fields {
			r.decimalFields[name] = true
		}
	}
	for _, ctx := range files {
		if !patternkit.ProductionGoFile(ctx) {
			continue
		}
		ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
			field, ok := n.(*ast.Field)
			if !ok || len(field.Names) != 1 || decimalTypeName.MatchString(typeIdentName(field.Type)) {
				return true
			}
			name, ok := patternkit.JsonFieldName(field, false)
			if ok && name != "" && name != "-" {
				conflicts[name] = true
			}
			return true
		})
	}
	for _, ctx := range files {
		if !ctx.IsTypeScriptFile() {
			continue
		}
		f := patternkit.NewJSFlat(ctx)
		for _, m := range tsDecimalProperty.FindAllStringSubmatch(f.Code, -1) {
			r.decimalFields[m[1]] = true
		}
	}
	for name := range conflicts {
		delete(r.decimalFields, name)
	}
}

var (
	tsDecimalProperty   = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\??\s*:\s*[\w$]*Decimal\b`)
	moneyVariableDecl   = regexp.MustCompile(`\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=`)
	moneyMathCall       = regexp.MustCompile(`\bMath\s*\.\s*(?:round|floor|ceil|trunc)\s*\(`)
	stringWrapperPrefix = regexp.MustCompile(`(?s)^\s*(?:String\s*\(\s*)*`)
	identifierWords     = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	formattingCall      = regexp.MustCompile(`\b(?:formatAmount|money\d*)\s*\(`)
)

func (r *FrontendMoneyArithmeticRule) setNumberParsers(parsers string) {
	r.parseCall = regexp.MustCompile(`\b(?:` + parsers + `)\s*\(`)
}

func (r *FrontendMoneyArithmeticRule) setMoneyFields(fields string) {
	r.moneyField = regexp.MustCompile(`(?i)\b\w*(?:` + fields + `)\w*\b`)
	r.reduceRawSum = regexp.MustCompile(`[+]\s*[\w$]+\.\w*(?i:` + fields + `)\w*\b`)
}

// AnalyzeFile checks TS/JS code for arithmetic over parsed money values.
func (r *FrontendMoneyArithmeticRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || ctx.IsTestFile() || strings.Contains(ctx.RelPath, "generated") {
		return nil
	}
	return r.analyzeFlat(ctx, patternkit.NewJSFlat(ctx))
}

func (r *FrontendMoneyArithmeticRule) isMoneyFieldName(name string) bool {
	return r.moneyField.MatchString(name) || r.decimalFields[name]
}

func (r *FrontendMoneyArithmeticRule) analyzeFlat(ctx *core.FileContext, f patternkit.JsFlat) []*core.Violation {
	parsed := r.moneyParseSpans(f)
	vars := r.moneyVariables(f, parsed)
	found := r.arithmeticFindings(ctx, f, parsed, vars)
	roundingFindings(ctx, f, parsed, vars, found)
	existingPatternFindings(r, ctx, found)
	lines := make([]int, 0, len(found))
	for line := range found {
		lines = append(lines, line)
	}
	sort.Ints(lines)
	out := make([]*core.Violation, 0, len(lines))
	for _, line := range lines {
		raw := stripTrailingComment(ctx.Lines[line-1])
		v := r.CreateViolation(ctx.RelPath, line, "Client-side arithmetic over a money value — financial aggregates must be computed on the backend")
		v.WithCode(strings.TrimSpace(raw))
		v.WithSuggestion("Return the computed value from the backend API (canonical calculation) and only format it here")
		out = append(out, v)
	}
	return out
}

type moneySpan struct{ start, end int }

func (r *FrontendMoneyArithmeticRule) moneyParseSpans(f patternkit.JsFlat) []moneySpan {
	var parsed []moneySpan
	for _, loc := range r.parseCall.FindAllStringIndex(f.Code, -1) {
		if loc[0] > 0 && f.Code[loc[0]-1] == '.' {
			continue
		}
		close, ok := f.Closing(loc[1] - 1)
		if !ok {
			continue
		}
		args := f.CallArgs(loc[1] - 1)
		if len(args) == 0 || !r.moneyArgument(f.Code[args[0].Start:args[0].End]) {
			continue
		}
		parsed = append(parsed, moneySpan{loc[0], close + 1})
	}
	return parsed
}

func (r *FrontendMoneyArithmeticRule) moneyVariables(f patternkit.JsFlat, parsed []moneySpan) map[string][]int {
	vars := make(map[string][]int)
	for _, m := range moneyVariableDecl.FindAllStringSubmatchIndex(f.Code, -1) {
		start, end := m[1], moneyExpressionEnd(f.Code, m[1])
		hasMoneyParse := false
		for _, p := range parsed {
			if p.start >= start && p.end <= end {
				hasMoneyParse = true
				break
			}
		}
		if !hasMoneyParse {
			continue
		}
		fn, ok := f.EnclosingFunction(m[0])
		scope := -1
		if ok {
			scope = fn.Brace
		}
		name := f.Code[m[2]:m[3]]
		vars[name] = append(vars[name], scope)
	}
	return vars
}

func (r *FrontendMoneyArithmeticRule) arithmeticFindings(ctx *core.FileContext, f patternkit.JsFlat, parsed []moneySpan, vars map[string][]int) map[int]bool {
	found := make(map[int]bool)
	for _, op := range arithmeticOperators(f.Code) {
		leftMoney := r.isMoneyVariable(f, vars, identifierBefore(f.Code, op.pos), op.pos)
		rightMoney := r.isMoneyVariable(f, vars, identifierAfter(f.Code, op.pos+len(op.op)), op.pos)
		if comparisonFollows(f.Code, op.pos) || stringConcatAt(f.Code, op.pos) ||
			op.op == "/" && leftMoney && rightMoney ||
			op.op == "/" && percentageRatio(f.Code, op.pos) ||
			op.op == "*" && ratioScale(f.Code, op.pos) {
			continue
		}
		for _, p := range parsed {
			if operandTouches(f.Code, op.pos, p.start, p.end) {
				addMoneyFinding(r, ctx, f, found, op.pos)
				break
			}
		}
		if leftMoney || rightMoney {
			addMoneyFinding(r, ctx, f, found, op.pos)
		}
	}
	return found
}

func roundingFindings(ctx *core.FileContext, f patternkit.JsFlat, parsed []moneySpan, vars map[string][]int, found map[int]bool) {
	for _, m := range moneyMathCall.FindAllStringIndex(f.Code, -1) {
		if comparisonFollows(f.Code, m[0]) || insideFormattingCall(f, m[0]) {
			continue
		}
		open := strings.LastIndex(f.Code[m[0]:m[1]], "(")
		if open < 0 {
			continue
		}
		args := f.CallArgs(m[0] + open)
		if len(args) == 0 {
			continue
		}
		arg := strings.TrimSpace(f.Code[args[0].Start:args[0].End])
		for _, p := range parsed {
			if p.start >= args[0].Start && p.end <= args[0].End {
				addMoneyFinding(nil, ctx, f, found, m[0])
				break
			}
		}
		id := strings.Trim(arg, "() \t\n")
		if patternkit.JsIdentifier.MatchString(id) && moneyVariableAt(f, vars, id, m[0]) {
			addMoneyFinding(nil, ctx, f, found, m[0])
		}
	}
}

func ratioScale(code string, pos int) bool {
	start, end := pos, pos
	for start > 0 && code[start-1] != '\n' && code[start-1] != ';' {
		start--
	}
	for end < len(code) && code[end] != '\n' && code[end] != ';' {
		end++
	}
	return strings.Contains(code[start:end], "/") && strings.HasPrefix(strings.TrimSpace(code[pos+1:end]), "100")
}

func percentageRatio(code string, pos int) bool {
	end := pos
	for end < len(code) && code[end] != '\n' && code[end] != ';' {
		end++
	}
	line := code[pos:end]
	return strings.Contains(line, "* 100")
}

func comparisonFollows(code string, pos int) bool {
	end := pos
	for end < len(code) && code[end] != '\n' && code[end] != ';' {
		end++
	}
	for i := pos; i < end; i++ {
		if i+2 < end && (code[i:i+3] == "===" || code[i:i+3] == "!==") {
			return true
		}
		if i+1 < end && (code[i:i+2] == ">=" || code[i:i+2] == "<=") {
			return true
		}
		if code[i] != '<' && code[i] != '>' {
			continue
		}
		if i > pos && code[i-1] == '=' || i+1 < end && (code[i+1] == '=' || code[i+1] == '/' || code[i+1] == '{') {
			continue
		}
		if (i > pos && (code[i-1] == ' ' || code[i-1] == '\t')) ||
			(i+1 < end && (code[i+1] == ' ' || code[i+1] == '\t')) {
			return true
		}
	}
	return false
}

func insideFormattingCall(f patternkit.JsFlat, pos int) bool {
	for _, loc := range formattingCall.FindAllStringIndex(f.Code, -1) {
		if loc[1] == 0 {
			continue
		}
		close, ok := f.Closing(loc[1] - 1)
		if ok && loc[1] <= pos && pos < close {
			return true
		}
	}
	return false
}

func existingPatternFindings(r *FrontendMoneyArithmeticRule, ctx *core.FileContext, found map[int]bool) {
	for i, raw := range ctx.Lines {
		line := stripTrailingComment(raw)
		if (strings.Contains(line, r.reduceMarker) && r.reduceRawSum.MatchString(line)) || strings.Contains(line, "+=") || strings.Contains(line, "-=") {
			if r.isMoneyAccumulation(line) || strings.Contains(line, r.reduceMarker) && r.reduceRawSum.MatchString(line) {
				found[i+1] = true
			}
		}
	}
}

func addMoneyFinding(r *FrontendMoneyArithmeticRule, ctx *core.FileContext, f patternkit.JsFlat, found map[int]bool, pos int) {
	line := f.Line(pos)
	if line < 1 || line > len(ctx.Lines) || found[line] {
		return
	}
	if r != nil && r.isSameFieldComparator(stripTrailingComment(ctx.Lines[line-1])) {
		return
	}
	found[line] = true
}

func (r *FrontendMoneyArithmeticRule) isMoneyVariable(f patternkit.JsFlat, vars map[string][]int, name string, pos int) bool {
	return name != "" && moneyVariableAt(f, vars, name, pos)
}

func moneyVariableAt(f patternkit.JsFlat, vars map[string][]int, name string, pos int) bool {
	fn, ok := f.EnclosingFunction(pos)
	scope := -1
	if ok {
		scope = fn.Brace
	}
	return slices.Contains(vars[name], scope)
}

func (r *FrontendMoneyArithmeticRule) moneyArgument(arg string) bool {
	arg = stringWrapperPrefix.ReplaceAllString(arg, "")
	words := identifierWords.FindAllString(arg, -1)
	if len(words) == 0 {
		return false
	}
	return r.isMoneyFieldName(words[len(words)-1])
}

type arithmeticOperator struct {
	pos int
	op  string
}

func arithmeticOperators(code string) []arithmeticOperator {
	var out []arithmeticOperator
	for i := 0; i < len(code); i++ {
		if !strings.ContainsRune("+-*/", rune(code[i])) {
			continue
		}
		op := string(code[i])
		if i+1 < len(code) && code[i+1] == '=' {
			op += "="
		}
		if i > 0 && code[i-1] == '=' || i+1 < len(code) && (code[i+1] == '>' || code[i+1] == '=') {
			continue
		}
		if (op == "+" || op == "-") && i+1 < len(code) && code[i+1] == code[i] {
			continue
		}
		if op == "+" || op == "-" {
			prev := i - 1
			for prev >= 0 && (code[prev] == ' ' || code[prev] == '\t' || code[prev] == '\n') {
				prev--
			}
			if prev < 0 || strings.ContainsRune("([{,:?;=+-*/!<>", rune(code[prev])) {
				continue
			}
		}
		out = append(out, arithmeticOperator{i, op})
	}
	return out
}

func operandTouches(code string, op, start, end int) bool {
	return end <= op && strings.TrimSpace(code[end:op]) == "" || start > op && strings.TrimSpace(code[op+1:start]) == ""
}

func identifierBefore(code string, pos int) string {
	i := pos - 1
	for i >= 0 && (code[i] == ' ' || code[i] == '\t' || code[i] == ')') {
		i--
	}
	end := i + 1
	for i >= 0 && (code[i] == '_' || code[i] == '$' || code[i] >= 'a' && code[i] <= 'z' || code[i] >= 'A' && code[i] <= 'Z' || code[i] >= '0' && code[i] <= '9') {
		i--
	}
	return code[i+1 : end]
}

func identifierAfter(code string, pos int) string {
	for pos < len(code) && (code[pos] == ' ' || code[pos] == '\t' || code[pos] == '(') {
		pos++
	}
	start := pos
	for pos < len(code) && (code[pos] == '_' || code[pos] == '$' || code[pos] >= 'a' && code[pos] <= 'z' || code[pos] >= 'A' && code[pos] <= 'Z' || code[pos] >= '0' && code[pos] <= '9') {
		pos++
	}
	return code[start:pos]
}

func stringConcatAt(code string, pos int) bool {
	left, right := pos-1, pos+1
	for left >= 0 && (code[left] == ' ' || code[left] == '\t') {
		left--
	}
	for right < len(code) && (code[right] == ' ' || code[right] == '\t') {
		right++
	}
	return left >= 0 && (code[left] == '\'' || code[left] == '"' || code[left] == '`') || right < len(code) && (code[right] == '\'' || code[right] == '"' || code[right] == '`')
}

func moneyExpressionEnd(code string, start int) int {
	depth := 0
	for i := start; i < len(code); i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return i
			}
			depth--
		case ';':
			if depth == 0 {
				return i
			}
		case '\n':
			if depth == 0 {
				prev := strings.TrimSpace(code[start:i])
				next := strings.TrimSpace(code[i+1:])
				if strings.HasSuffix(prev, "?") || strings.HasSuffix(prev, ":") || strings.HasSuffix(prev, "??") || strings.HasSuffix(prev, "||") || strings.HasSuffix(prev, "+") || strings.HasSuffix(prev, "-") || strings.HasPrefix(next, ":") {
					continue
				}
				return i
			}
		}
	}
	return len(code)
}

// isMoneyAccumulation matches "moneyVar += <expr with money ident>" —
// aggregation through intermediate variables (investedAmount += invAmount).
func (r *FrontendMoneyArithmeticRule) isMoneyAccumulation(line string) bool {
	m := r.accumulate.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	return r.moneyField.MatchString(m[1]) && r.moneyField.MatchString(m[2])
}

// isSameFieldComparator reports whether the line subtracts the SAME money
// field of two different receivers — the sort-comparator / trend-delta idiom
// (presentational, not aggregation):
//
//	(parseFloat(String(a.amount)) - parseFloat(String(b.amount))) * dir
func (r *FrontendMoneyArithmeticRule) isSameFieldComparator(line string) bool {
	locs := r.parseCall.FindAllStringIndex(line, -1)
	if len(locs) != 2 {
		return false
	}
	var fields []string
	for _, loc := range locs {
		end := patternkit.MatchingParenEnd(line, loc[1])
		if end < 0 {
			return false
		}
		words := r.moneyField.FindAllString(line[loc[1]:end], -1)
		if len(words) == 0 {
			return false
		}
		fields = append(fields, strings.ToLower(words[len(words)-1]))
	}
	between := line[locs[0][1]:locs[1][0]]
	return fields[0] == fields[1] && strings.Contains(between, "-")
}

// stripTrailingComment removes a trailing // or /* comment, ignoring comment
// markers inside string literals.
func stripTrailingComment(line string) string {
	quote := byte(0)
	for i := 0; i < len(line)-1; i++ {
		c := line[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '/':
			if line[i+1] == '/' || line[i+1] == '*' {
				return line[:i]
			}
		}
	}
	return line
}
