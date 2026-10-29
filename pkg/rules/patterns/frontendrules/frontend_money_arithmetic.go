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
const defaultMoneyFields = "amount|balance|fee|fees|price|profit|yield|income|investment|deposit|withdrawal|invested|debit|credit"

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
// non-money numerics, tests, and percentage-change helpers with generic
// parameters that have no money names.
type FrontendMoneyArithmeticRule struct {
	*rules.BaseRule
	parseCall       *regexp.Regexp
	moneyField      *regexp.Regexp
	moneyFieldToken *regexp.Regexp
	reduceRawSum    *regexp.Regexp
	accumulate      *regexp.Regexp
	reduceMarker    string
	numberParsers   string
	decimalFields   map[string]bool
	moneyFormatter  string
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
	r.moneyFormatter = r.GetStringSetting("money_formatter", "")
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
	moneyMathCallName   = regexp.MustCompile(`\bMath\s*\.\s*(round|floor|ceil|trunc)\s*\(`)
	centScaledArgument  = regexp.MustCompile(`(?is)^\s*(.+?)\s*\*\s*100\s*(?:[+\-]\s*(?:\d+(?:\.\d*)?|\.\d+)(?:e[+\-]?\d+)?)?\s*$`)
	divideByCents       = regexp.MustCompile(`(?is)^\s*/\s*100\b`)
	centEpsilon         = regexp.MustCompile(`(?i)(?:\+\s*1e-?\d+|\+\s*0\.0{4,}\d+|EPSILON)`)
	simpleMemberName    = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*$`)
	stringWrapperPrefix = regexp.MustCompile(`(?s)^\s*(?:String\s*\(\s*)*`)
	identifierWords     = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	formattingCall      = regexp.MustCompile(`\b(?:formatAmount|money\d*)\s*\(`)
	parameterName       = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)\b`)
)

func (r *FrontendMoneyArithmeticRule) setNumberParsers(parsers string) {
	r.parseCall = regexp.MustCompile(`\b(?:` + parsers + `)\s*\(`)
}

func (r *FrontendMoneyArithmeticRule) setMoneyFields(fields string) {
	r.moneyField = regexp.MustCompile(`(?i)\b\w*(?:` + fields + `)\w*\b`)
	r.moneyFieldToken = regexp.MustCompile(`(?i)^(?:` + fields + `)s?$`)
	r.reduceRawSum = regexp.MustCompile(`[+]\s*[\w$]+\.\w*(?i:` + fields + `)\w*\b`)
}

// AnalyzeFile checks TS/JS code for arithmetic over parsed money values.
func (r *FrontendMoneyArithmeticRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || ctx.IsTestFile() || strings.Contains(ctx.RelPath, "generated") || strings.Contains("/"+ctx.RelPath, "/e2e/") {
		return nil
	}
	return r.analyzeFlat(ctx, patternkit.NewJSFlat(ctx))
}

func (r *FrontendMoneyArithmeticRule) isMoneyFieldName(name string) bool {
	if r.decimalFields[name] {
		return true
	}
	if name == "" || strings.HasSuffix(strings.ToLower(name), "applied") {
		return false
	}
	field := name
	if dot := strings.LastIndex(field, "."); dot >= 0 {
		field = strings.TrimPrefix(field[dot+1:], "?")
	}
	parts := splitMoneyName(field)
	if len(parts) == 0 || slices.Contains([]string{"can", "has", "is", "should", "allow", "show", "enable"}, strings.ToLower(parts[0])) {
		return false
	}
	return r.moneyFieldToken.MatchString(parts[len(parts)-1])
}

func splitMoneyName(name string) []string {
	var parts []string
	start := 0
	for i := 1; i < len(name); i++ {
		current, previous := name[i], name[i-1]
		if current >= 'A' && current <= 'Z' && (previous >= 'a' && previous <= 'z' || previous >= '0' && previous <= '9' || previous >= 'A' && previous <= 'Z' && i+1 < len(name) && name[i+1] >= 'a' && name[i+1] <= 'z') {
			parts = append(parts, name[start:i])
			start = i
		} else if !(current >= 'A' && current <= 'Z' || current >= 'a' && current <= 'z' || current >= '0' && current <= '9') {
			if start < i {
				parts = append(parts, name[start:i])
			}
			start = i + 1
		}
	}
	if start < len(name) {
		parts = append(parts, name[start:])
	}
	return parts
}

func (r *FrontendMoneyArithmeticRule) analyzeFlat(ctx *core.FileContext, f patternkit.JsFlat) []*core.Violation {
	parsed := r.moneyParseSpans(f)
	vars := r.moneyVariables(f, parsed)
	found := r.arithmeticFindings(ctx, f, parsed, vars)
	roundingFindings(r, ctx, f, parsed, vars, found)
	centRoundingFindings(r, ctx, f, found)
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
		if jsxTagOperator(f.Code, op.pos) || insideFormattingFunction(f, op.pos) {
			continue
		}
		if financialFPRoundingDuplicateAt(f, op.pos) {
			continue
		}
		leftName := moneyNameBefore(f.Code, op.pos)
		rightName := moneyNameAfter(f.Code, op.pos+len(op.op))
		leftMoney := r.isMoneyVariable(f, vars, identifierBefore(f.Code, op.pos), op.pos) || r.isMoneyFieldName(leftName) && !counterParameterAt(f, leftName, op.pos)
		rightMoney := r.isMoneyVariable(f, vars, identifierAfter(f.Code, op.pos+len(op.op)), op.pos) || r.isMoneyFieldName(rightName) && !counterParameterAt(f, rightName, op.pos)
		if strings.HasSuffix(op.op, "=") {
			if leftMoney {
				addMoneyFinding(r, ctx, f, found, op.pos)
				continue
			}
			rhs := op.pos + len(op.op)
			for _, p := range parsed {
				if p.start >= rhs && strings.TrimSpace(f.Code[rhs:p.start]) == "" {
					addMoneyFinding(r, ctx, f, found, op.pos)
					break
				}
			}
			continue
		}
		if stringConcatAt(f.Code, op.pos) {
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

func roundingFindings(r *FrontendMoneyArithmeticRule, ctx *core.FileContext, f patternkit.JsFlat, parsed []moneySpan, vars map[string][]int, found map[int]bool) {
	for _, m := range moneyMathCall.FindAllStringIndex(f.Code, -1) {
		if insideFormattingFunction(f, m[0]) || financialFPRoundingDuplicateAt(f, m[0]) {
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
		id := strings.Trim(arg, "() \t\n")
		moneyName := r.moneyNameExpression(id) && !counterParameterAt(f, id, m[0])
		if insideFormattingCall(f, m[0]) && !moneyName {
			continue
		}
		if moneyName {
			addMoneyFinding(r, ctx, f, found, m[0])
		}
		for _, p := range parsed {
			if p.start >= args[0].Start && p.end <= args[0].End {
				addMoneyFinding(nil, ctx, f, found, m[0])
				break
			}
		}
		if patternkit.JsIdentifier.MatchString(id) && moneyVariableAt(f, vars, id, m[0]) {
			addMoneyFinding(nil, ctx, f, found, m[0])
		}
	}
}

func centRoundingFindings(r *FrontendMoneyArithmeticRule, ctx *core.FileContext, f patternkit.JsFlat, found map[int]bool) {
	for _, m := range moneyMathCallName.FindAllStringSubmatchIndex(f.Code, -1) {
		open := strings.LastIndex(f.Code[m[0]:m[1]], "(") + m[0]
		close, ok := f.Closing(open)
		if !ok {
			continue
		}
		args := f.CallArgs(open)
		if len(args) == 0 {
			continue
		}
		arg := strings.TrimSpace(f.Code[args[0].Start:args[0].End])
		scaled := centScaledArgument.FindStringSubmatch(arg)
		if scaled == nil || !divideByCents.MatchString(f.Code[close+1:]) || insideMoneyFormatter(r, f, m[0]) {
			continue
		}
		if financialFPRoundingDuplicate(f.Code[m[2]:m[3]], arg) {
			continue
		}
		addMoneyFinding(r, ctx, f, found, m[0])
	}
}

func financialFPRoundingDuplicate(method, arg string) bool {
	if method == "round" || centEpsilon.MatchString(arg) {
		return false
	}
	for _, token := range patternkit.IdentifierTokens(arg) {
		switch token {
		case "amount", "balance", "cost", "fee", "price", "profit", "usd", "total", "subtotal", "sum", "payout", "payment", "deposit", "withdraw", "withdrawal", "principal", "usdc", "usdt":
			return true
		}
	}
	return false
}

func financialFPRoundingDuplicateAt(f patternkit.JsFlat, pos int) bool {
	for _, m := range moneyMathCallName.FindAllStringSubmatchIndex(f.Code, -1) {
		if pos < m[0] {
			continue
		}
		open := strings.LastIndex(f.Code[m[0]:m[1]], "(") + m[0]
		close, ok := f.Closing(open)
		if !ok {
			continue
		}
		div := divideByCents.FindStringIndex(f.Code[close+1:])
		if div == nil || pos > close+1+div[1] {
			continue
		}
		args := f.CallArgs(open)
		if len(args) == 0 {
			continue
		}
		arg := strings.TrimSpace(f.Code[args[0].Start:args[0].End])
		if centScaledArgument.MatchString(arg) && financialFPRoundingDuplicate(f.Code[m[2]:m[3]], arg) {
			return true
		}
	}
	return false
}

func insideMoneyFormatter(r *FrontendMoneyArithmeticRule, f patternkit.JsFlat, pos int) bool {
	return r.moneyFormatter != "" && f.InsideNamedFunction(pos, r.moneyFormatter)
}

func (r *FrontendMoneyArithmeticRule) moneyNameExpression(expr string) bool {
	if !simpleMemberName.MatchString(expr) {
		return false
	}
	words := identifierWords.FindAllString(expr, -1)
	return len(words) > 0 && r.isMoneyFieldName(words[len(words)-1])
}

func moneyNameBefore(code string, pos int) string {
	end := pos
	for end > 0 && (code[end-1] == ' ' || code[end-1] == '\t' || code[end-1] == ')' || code[end-1] == ']') {
		end--
	}
	start := end
	for start > 0 && (code[start-1] == '_' || code[start-1] == '$' || code[start-1] >= 'a' && code[start-1] <= 'z' || code[start-1] >= 'A' && code[start-1] <= 'Z' || code[start-1] >= '0' && code[start-1] <= '9' || code[start-1] == '.') {
		start--
	}
	return code[start:end]
}

func moneyNameAfter(code string, pos int) string {
	for pos < len(code) && (code[pos] == ' ' || code[pos] == '\t' || code[pos] == '(') {
		pos++
	}
	start := pos
	for pos < len(code) && (code[pos] == '_' || code[pos] == '$' || code[pos] >= 'a' && code[pos] <= 'z' || code[pos] >= 'A' && code[pos] <= 'Z' || code[pos] >= '0' && code[pos] <= '9' || code[pos] == '.') {
		pos++
	}
	return code[start:pos]
}

func insideFormattingFunction(f patternkit.JsFlat, pos int) bool {
	for pos >= 0 {
		fn, ok := f.EnclosingFunction(pos)
		if !ok {
			return false
		}
		name := strings.ToLower(fn.Name)
		if strings.HasPrefix(name, "format") || strings.HasPrefix(name, "money") {
			return true
		}
		if fn.Start >= pos {
			return false
		}
		pos = fn.Start
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

func counterParameterAt(f patternkit.JsFlat, name string, pos int) bool {
	fn, ok := f.EnclosingFunction(pos)
	if !ok {
		return false
	}
	header := f.Code[fn.Start:fn.Brace]
	openOffset := strings.Index(header, "(")
	if openOffset < 0 {
		return false
	}
	args := f.CallArgs(fn.Start + openOffset)
	for _, arg := range args {
		text := strings.TrimSpace(f.Code[arg.Start:arg.End])
		before, after, ok := strings.Cut(text, "=")
		if !ok {
			continue
		}
		parameter := parameterName.FindStringSubmatch(before)
		if len(parameter) != 2 || parameter[1] != name {
			continue
		}
		defaultValue := strings.TrimSpace(after)
		if defaultValue == "" {
			continue
		}
		allDigits := true
		for _, char := range defaultValue {
			if char < '0' || char > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && strings.TrimLeft(defaultValue, "0") != "" {
			return true
		}
	}
	return false
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
	return slices.ContainsFunc(words, r.isMoneyFieldName)
}

type arithmeticOperator struct {
	pos int
	op  string
}

func jsxTagOperator(code string, pos int) bool {
	start := strings.LastIndex(code[:pos], "<")
	if start < 0 || strings.Contains(code[start:pos], ">") {
		return false
	}
	i := start + 1
	if i < pos && code[i] == '/' {
		i++
	}
	if i >= pos || !(code[i] >= 'A' && code[i] <= 'Z' || code[i] >= 'a' && code[i] <= 'z') {
		return false
	}
	depth := 0
	var quote byte
	for i = start + 1; i < pos; i++ {
		c := code[i]
		if quote != 0 {
			if c == quote && (i == 0 || code[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return quote != 0 || depth == 0
}

func arithmeticOperators(code string) []arithmeticOperator {
	var out []arithmeticOperator
	for i := 0; i < len(code); i++ {
		if !strings.ContainsRune("+-*/", rune(code[i])) || code[i] == '/' && i > 0 && code[i-1] == '<' {
			continue
		}
		op := string(code[i])
		if i+1 < len(code) && code[i+1] == '=' {
			op += "="
		}
		if len(op) == 2 {
			out = append(out, arithmeticOperator{i, op})
			i++
			continue
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
