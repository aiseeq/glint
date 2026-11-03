package frontendrules

import (
	"go/ast"
	"maps"
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
		).DeclareSettings(
			rules.NewSettingSpec("money_fields", "string", defaultMoneyFields, "Regular expression matching money field names.", "amount|balance|price"),
			rules.NewSettingSpec("number_parsers", "string", `parseFloat|Number|toNumber\w*`, "Regular expression matching number parser functions.", `parseFloat|Number|parseAmount`),
			rules.NewSettingSpec("money_formatter", "string", "", "Name of the money formatting function.", "renderAmount"),
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
	tsDecimalProperty = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\??\s*:\s*[\w$]*Decimal\b`)

	memberChain         = regexp.MustCompile(`[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*`)
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

// decimalMember tells whether a member access reads a decimal field of the
// project. The field names a field of a value the code receives, so a bare
// local of that name, such as the min of a chart axis, is not that field.
func (r *FrontendMoneyArithmeticRule) decimalMember(name string) bool {
	dot := strings.LastIndex(name, ".")
	return dot >= 0 && r.decimalFields[strings.TrimPrefix(name[dot+1:], "?")]
}

func (r *FrontendMoneyArithmeticRule) isMoneyFieldName(name string) bool {
	if name == "" || strings.HasSuffix(strings.ToLower(name), "applied") {
		return false
	}
	field := name
	if dot := strings.LastIndex(field, "."); dot >= 0 {
		field = strings.TrimPrefix(field[dot+1:], "?")
	}
	parts := patternkit.IdentifierWords(field)
	if len(parts) == 0 || slices.Contains([]string{"can", "has", "is", "should", "allow", "show", "enable"}, strings.ToLower(parts[0])) {
		return false
	}
	return r.moneyFieldToken.MatchString(parts[len(parts)-1])
}

func (r *FrontendMoneyArithmeticRule) analyzeFlat(ctx *core.FileContext, f patternkit.JsFlat) []*core.Violation {
	parsed := r.moneyParseSpans(f)
	vars := r.moneyVariables(f, parsed)
	functions := f.Functions()
	formatting := newFormattingIndex(f, functions)
	duplicateRounding := newFinancialFPRoundingDuplicateIndex(f)
	found := r.arithmeticFindings(ctx, f, functions, parsed, vars, duplicateRounding, formatting)
	roundingFindings(r, ctx, f, parsed, vars, found, duplicateRounding, formatting)
	centRoundingFindings(r, ctx, f, found)
	existingPatternFindings(r, ctx, found)
	lines := slices.Sorted(maps.Keys(found))
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

func (r *FrontendMoneyArithmeticRule) arithmeticFindings(ctx *core.FileContext, f patternkit.JsFlat, index *patternkit.JsFunctions, parsed []moneySpan, vars map[string][]int, duplicateRounding financialFPRoundingDuplicateIndex, formatting formattingIndex) map[int]bool {
	found := make(map[int]bool)
	ops := arithmeticOperators(f.Code)
	positions := make([]int, len(ops))
	for i, op := range ops {
		positions[i] = op.pos
	}
	functions := enclosingFunctionsAt(f, index, positions)
	inJSXTag := jsxTagOperators(f.Code, positions)
	texts := stringAccumulators(f, index, ops)
	parameters := make(map[int]map[string]bool)
	for k, op := range ops {
		if inJSXTag[k] || formatting.inFunction(op.pos) {
			continue
		}
		if duplicateRounding.contains(op.pos) {
			continue
		}
		leftName := moneyNameBefore(f.Code, op.pos)
		fn, inFunction := functions[op.pos]
		moneyAt := func(pos int) bool {
			name := moneyNameAfter(f.Code, pos)
			return moneyVariableInScope(vars, identifierAfter(f.Code, pos), fn, inFunction) || r.isMoneyFieldName(name) && !counterParameterCached(f, name, fn, inFunction, parameters)
		}
		leftMoney := moneyVariableInScope(vars, identifierBefore(f.Code, op.pos), fn, inFunction) || r.isMoneyFieldName(leftName) && !counterParameterCached(f, leftName, fn, inFunction, parameters)
		rightMoney := addendMoney(f.Code, op.pos+len(op.op), strings.HasSuffix(op.op, "="), moneyAt)
		hit := leftMoney || rightMoney
		if strings.HasSuffix(op.op, "=") {
			// total += it.price sums money as much as amount += 1 changes it.
			rhs := op.pos + len(op.op)
			for _, p := range parsed {
				if hit {
					break
				}
				hit = p.start >= rhs && strings.TrimSpace(f.Code[rhs:p.start]) == ""
			}
		} else {
			if stringConcatAt(f.Code, op.pos) {
				continue
			}
			for _, p := range parsed {
				if hit {
					break
				}
				hit = operandTouches(f.Code, op.pos, p.start, p.end)
			}
		}
		if !hit {
			continue
		}
		if appends := op.op == "+" || op.op == "+="; !appends || !texts.appendsText(f.Code, op) {
			addMoneyFinding(r, ctx, f, found, op.pos)
		}
	}
	return found
}

// addendMoney tells whether the value added at pos, right after an operator,
// is money. A money name there is that value unless it only decides it:
// count += it.price ? 1 : 0 adds one, total += it.fee ? it.amount : 0 adds
// the amount, and shown += it.price > 0 adds a boolean. The right side of a
// compound assignment is the whole expression; the right operand of a binary
// operator is the whole condition only inside parentheses, since + binds
// tighter than ?: and the comparisons.
func addendMoney(code string, pos int, whole bool, moneyAt func(int) bool) bool {
	if !moneyAt(pos) {
		return false
	}
	start, opened := pos, false
	for start < len(code) && (code[start] == ' ' || code[start] == '\t' || code[start] == '(') {
		opened = opened || code[start] == '('
		start++
	}
	if !whole && !opened {
		return true
	}
	next := start
	for next < len(code) && (patternkit.IsWordChar(code[next]) || code[next] == '.') {
		next++
	}
	for next < len(code) && (code[next] == ' ' || code[next] == '\t') {
		next++
	}
	if !decidesValue(code, next) {
		return true
	}
	end := moneyExpressionEnd(code, start)
	question := ternaryQuestion(code, next, end)
	if question < 0 {
		return false
	}
	colon := ternaryColon(code, question+1, end)
	return moneyAt(question+1) || colon >= 0 && moneyAt(colon+1)
}

// decidesValue tells whether the operator at i makes the operand before it a
// condition or a comparison rather than a value.
func decidesValue(code string, i int) bool {
	if i >= len(code) {
		return false
	}
	nextIs := func(c byte) bool { return i+1 < len(code) && code[i+1] == c }
	switch code[i] {
	case '?':
		return !nextIs('.') && !nextIs('?')
	case '<', '>':
		return true
	case '=', '!':
		return nextIs('=')
	}
	return false
}

func ternaryQuestion(code string, from, end int) int {
	depth := 0
	for i := from; i < end; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '?':
			if i+1 < end && (code[i+1] == '.' || code[i+1] == '?') {
				i++
				continue
			}
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func ternaryColon(code string, from, end int) int {
	depth, nested := 0, 0
	for i := from; i < end; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '?':
			if i+1 < end && (code[i+1] == '.' || code[i+1] == '?') {
				i++
				continue
			}
			if depth == 0 {
				nested++
			}
		case ':':
			if depth != 0 {
				continue
			}
			if nested == 0 {
				return i
			}
			nested--
		}
	}
	return -1
}

var stringAssignment = regexp.MustCompile(`(?:^|[^\w$.])([A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?(\+=|-=|\*=|/=|=)`)
var stringIdentifier = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
var stringArrow = regexp.MustCompile(`=>`)

type textAccumulators struct {
	at map[int]bool
}

// stringAccumulators marks a name when a literal assignment exists, no
// non-string assignment exists, and no function parameter binds it. It
// deliberately ignores scope and order, conservatively preserving findings.
func stringAccumulators(f patternkit.JsFlat, functions *patternkit.JsFunctions, ops []arithmeticOperator) textAccumulators {
	stringNames, nonStringNames := stringAssignmentNames(f)
	brackets := patternkit.NewJsBrackets(f.Code)
	parameters := functionParameterNames(f.Code, functions, brackets)
	addArrowParameterNames(f.Code, brackets, parameters)
	closureText := arrowTextAppends(f.Code, ops, stringNames, parameters, brackets)
	return stringAccumulatorOps(f.Code, ops, stringNames, nonStringNames, parameters, closureText)
}

func stringAssignmentNames(f patternkit.JsFlat) (map[string]bool, map[string]bool) {
	code := f.Code
	stringNames := make(map[string]bool)
	nonStringNames := make(map[string]bool)
	matches := stringAssignment.FindAllStringSubmatchIndex(code, -1)
	for _, match := range matches {
		if followsJSXTextBoundary(code, match[2]) {
			continue
		}
		name := code[match[2]:match[3]]
		opEnd := match[5]
		if opEnd < len(code) && (code[opEnd] == '=' || code[opEnd] == '>') {
			continue
		}
		rhs := opEnd
		for rhs < len(f.Text) && isExpressionSpace(f.Text[rhs]) {
			rhs++
		}
		if rhs < len(f.Text) && isStringSelfReference(f.Text, rhs, name) {
			continue
		}
		if rhs < len(f.Text) && strings.ContainsRune("\"'`", rune(f.Text[rhs])) {
			stringNames[name] = true
		} else {
			nonStringNames[name] = true
		}
	}

	return stringNames, nonStringNames
}

func stringAccumulatorOps(code string, ops []arithmeticOperator, stringsFound, nonStrings, parameters map[string]bool, closureText map[int]bool) textAccumulators {
	out := textAccumulators{at: make(map[int]bool)}
	for _, op := range ops {
		name := identifierBefore(code, op.pos)
		if closureText[op.pos] || stringsFound[name] && !nonStrings[name] && !parameters[name] && moneyNameBefore(code, op.pos) == name {
			out.at[op.pos] = true
		}
	}
	return out
}

func arrowTextAppends(code string, ops []arithmeticOperator, stringsFound, parameters map[string]bool, brackets *patternkit.JsBrackets) map[int]bool {
	var ranges []arrowBodyRange
	for _, arrow := range stringArrow.FindAllStringIndex(code, -1) {
		start := arrow[1]
		for start < len(code) && isExpressionSpace(code[start]) {
			start++
		}
		if start >= len(code) || code[start] != '{' {
			continue
		}
		if end, ok := brackets.Closing(start); ok {
			ranges = append(ranges, arrowBodyRange{start, end})
		}
	}
	out := make(map[int]bool)
	var active []int
	next := 0
	for _, op := range ops {
		for next < len(ranges) && ranges[next].start < op.pos {
			active = append(active, ranges[next].end)
			next++
		}
		for len(active) > 0 && active[len(active)-1] < op.pos {
			active = active[:len(active)-1]
		}
		if op.op != "+=" {
			continue
		}
		name := identifierBefore(code, op.pos)
		if len(active) > 0 && stringsFound[name] && !parameters[name] {
			out[op.pos] = true
		}
	}
	return out
}

type arrowBodyRange struct{ start, end int }

func functionParameterNames(code string, functions *patternkit.JsFunctions, brackets *patternkit.JsBrackets) map[string]bool {
	names := make(map[string]bool)
	for _, brace := range brackets.Braces() {
		fn, ok := functions.AtBrace(brace.Open)
		if !ok {
			continue
		}
		open, ok := brackets.OpeningBefore(fn.Brace)
		if !ok || open < fn.Start {
			continue
		}
		close, ok := brackets.Closing(open)
		if ok && close < fn.Brace {
			addParameterIdentifiers(code, open+1, close, names)
		}
	}
	return names
}

func addArrowParameterNames(code string, brackets *patternkit.JsBrackets, names map[string]bool) {
	for _, arrow := range stringArrow.FindAllStringIndex(code, -1) {
		end := arrow[0]
		for end > 0 && isExpressionSpace(code[end-1]) {
			end--
		}
		if end > 0 && code[end-1] == ')' {
			if open, ok := brackets.Opening(end - 1); ok {
				addParameterIdentifiers(code, open+1, end-1, names)
			}
			continue
		}
		start := end
		for start > 0 && identifierByte(code[start-1]) {
			start--
		}
		if start < end {
			names[code[start:end]] = true
		}
	}
}

func addParameterIdentifiers(code string, start, end int, names map[string]bool) {
	for _, match := range stringIdentifier.FindAllStringIndex(code[start:end], -1) {
		names[code[start+match[0]:start+match[1]]] = true
	}
}

func followsJSXTextBoundary(code string, nameStart int) bool {
	for nameStart > 0 && (code[nameStart-1] == ' ' || code[nameStart-1] == '\t') {
		nameStart--
	}
	return nameStart > 0 && code[nameStart-1] == '>' && (nameStart < 2 || code[nameStart-2] != '=')
}

func isStringSelfReference(code string, start int, name string) bool {
	for start < len(code) && (code[start] == '(' || isExpressionSpace(code[start])) {
		start++
	}
	if !strings.HasPrefix(code[start:], name) {
		return false
	}
	end := start + len(name)
	return end == len(code) || !identifierByte(code[end])
}

// appendsText tells whether the + or += at op builds text based on the
// file-wide string classification or a string literal on the right.
func (t textAccumulators) appendsText(code string, op arithmeticOperator) bool {
	if t.at[op.pos] {
		return true
	}
	if op.op != "+=" {
		return false
	}
	rhs := op.pos + len(op.op)
	end := moneyExpressionEnd(code, rhs)
	depth := 0
	for i := rhs; i < end; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '"', '\'', '`':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

func roundingFindings(r *FrontendMoneyArithmeticRule, ctx *core.FileContext, f patternkit.JsFlat, parsed []moneySpan, vars map[string][]int, found map[int]bool, duplicateRounding financialFPRoundingDuplicateIndex, formatting formattingIndex) {
	for _, m := range moneyMathCall.FindAllStringIndex(f.Code, -1) {
		if formatting.inFunction(m[0]) || duplicateRounding.contains(m[0]) {
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
		if formatting.inCall(m[0]) && !moneyName {
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

type financialFPRoundingDuplicateRange struct {
	start int
	end   int
}

type financialFPRoundingDuplicateIndex struct {
	ranges  []financialFPRoundingDuplicateRange
	maxEnds []int
}

func newFinancialFPRoundingDuplicateIndex(f patternkit.JsFlat) financialFPRoundingDuplicateIndex {
	var index financialFPRoundingDuplicateIndex
	for _, m := range moneyMathCallName.FindAllStringSubmatchIndex(f.Code, -1) {
		open := strings.LastIndex(f.Code[m[0]:m[1]], "(") + m[0]
		close, ok := f.Closing(open)
		if !ok {
			continue
		}
		div := divideByCents.FindStringIndex(f.Code[close+1:])
		if div == nil {
			continue
		}
		args := f.CallArgs(open)
		if len(args) == 0 {
			continue
		}
		arg := strings.TrimSpace(f.Code[args[0].Start:args[0].End])
		if !centScaledArgument.MatchString(arg) || !financialFPRoundingDuplicate(f.Code[m[2]:m[3]], arg) {
			continue
		}
		index.ranges = append(index.ranges, financialFPRoundingDuplicateRange{start: m[0], end: close + 1 + div[1]})
	}
	index.maxEnds = make([]int, len(index.ranges))
	for i, item := range index.ranges {
		if i > 0 && index.maxEnds[i-1] > item.end {
			index.maxEnds[i] = index.maxEnds[i-1]
		} else {
			index.maxEnds[i] = item.end
		}
	}
	return index
}

func (index financialFPRoundingDuplicateIndex) contains(pos int) bool {
	i := sort.Search(len(index.ranges), func(i int) bool { return index.ranges[i].start > pos }) - 1
	return i >= 0 && index.maxEnds[i] >= pos
}

func insideMoneyFormatter(r *FrontendMoneyArithmeticRule, f patternkit.JsFlat, pos int) bool {
	return r.moneyFormatter != "" && f.InsideNamedFunction(pos, r.moneyFormatter)
}

func (r *FrontendMoneyArithmeticRule) moneyNameExpression(expr string) bool {
	if !simpleMemberName.MatchString(expr) {
		return false
	}
	return r.decimalMember(expr) || r.isMoneyFieldName(expr)
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

type formattingRange struct{ start, end int }

type formattingIndex struct {
	functions       []formattingRange
	functionMaxEnds []int
	calls           []formattingRange
	callMaxEnds     []int
}

var formattingFunctionName = regexp.MustCompile(`(?i)\b(?:format|money)[A-Za-z0-9_$]*`)

func newFormattingIndex(f patternkit.JsFlat, functions *patternkit.JsFunctions) formattingIndex {
	var index formattingIndex
	closing := make(map[int]int)
	stack := make([]int, 0)
	parenStack := make([]int, 0)
	braceClosing := make(map[int]int)
	braceStack := make([]int, 0)
	functionNames := formattingFunctionName.FindAllStringIndex(f.Code, -1)
	functionBraces := make([]int, 0)
	lastHeaderBoundary := -1
	functionNameIndex := 0
	for pos := 0; pos < len(f.Code); pos++ {
		switch f.Code[pos] {
		case '{':
			headerStart := lastHeaderBoundary + 1
			if len(parenStack) > 0 {
				headerStart = parenStack[len(parenStack)-1] + 1
			}
			for functionNameIndex < len(functionNames) && functionNames[functionNameIndex][0] < headerStart {
				functionNameIndex++
			}
			if functionNameIndex < len(functionNames) && functionNames[functionNameIndex][0] < pos {
				if fn, ok := functions.AtBrace(pos); ok {
					name := strings.ToLower(fn.Name)
					if strings.HasPrefix(name, "format") || strings.HasPrefix(name, "money") {
						functionBraces = append(functionBraces, pos)
					}
				}
			}
			if len(parenStack) == 0 {
				lastHeaderBoundary = pos
			}
			stack = append(stack, pos)
			braceStack = append(braceStack, pos)
		case '}':
			if len(stack) > 0 {
				open := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				closing[open] = pos
				if len(parenStack) > 0 && parenStack[len(parenStack)-1] == open {
					parenStack = parenStack[:len(parenStack)-1]
				}
			}
			if len(braceStack) > 0 {
				open := braceStack[len(braceStack)-1]
				braceStack = braceStack[:len(braceStack)-1]
				braceClosing[open] = pos
			}
			if len(parenStack) == 0 {
				lastHeaderBoundary = pos
			}
		case '(', '[':
			stack = append(stack, pos)
			parenStack = append(parenStack, pos)
		case ')', ']':
			if len(stack) > 0 {
				open := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				closing[open] = pos
				if len(parenStack) > 0 && parenStack[len(parenStack)-1] == open {
					parenStack = parenStack[:len(parenStack)-1]
				}
			}
		case ';', '\n':
			if len(parenStack) == 0 {
				lastHeaderBoundary = pos
			}
		}
	}
	for _, pos := range functionBraces {
		close, hasClose := braceClosing[pos]
		if !hasClose {
			close = len(f.Code)
		}
		index.functions = append(index.functions, formattingRange{start: pos, end: close})
	}
	for _, loc := range formattingCall.FindAllStringIndex(f.Code, -1) {
		if loc[1] == 0 {
			continue
		}
		if close, ok := closing[loc[1]-1]; ok {
			index.calls = append(index.calls, formattingRange{start: loc[1], end: close})
		}
	}
	index.functionMaxEnds = rangePrefixMaxEnds(index.functions)
	index.callMaxEnds = rangePrefixMaxEnds(index.calls)
	return index
}

func rangePrefixMaxEnds(ranges []formattingRange) []int {
	maxEnds := make([]int, len(ranges))
	for i, current := range ranges {
		maxEnds[i] = current.end
		if i > 0 && maxEnds[i-1] > maxEnds[i] {
			maxEnds[i] = maxEnds[i-1]
		}
	}
	return maxEnds
}

func (index formattingIndex) inFunction(pos int) bool {
	return index.contains(index.functions, index.functionMaxEnds, pos, false)
}
func (index formattingIndex) inCall(pos int) bool {
	return index.contains(index.calls, index.callMaxEnds, pos, true)
}

func (index formattingIndex) contains(ranges []formattingRange, maxEnds []int, pos int, includeStart bool) bool {
	bound := sort.Search(len(ranges), func(i int) bool {
		if includeStart {
			return ranges[i].start > pos
		}
		return ranges[i].start >= pos
	}) - 1
	return bound >= 0 && maxEnds[bound] > pos
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

func counterParameterAt(f patternkit.JsFlat, name string, pos int) bool {
	fn, ok := f.EnclosingFunction(pos)
	if !ok {
		return false
	}
	return counterParameterInFunction(f, name, fn)
}

func counterParameterCached(f patternkit.JsFlat, name string, fn patternkit.JsFunc, inFunction bool, cache map[int]map[string]bool) bool {
	if !inFunction {
		return false
	}
	parameters, ok := cache[fn.Brace]
	if !ok {
		parameters = make(map[string]bool)
		header := f.Code[fn.Start:fn.Brace]
		if openOffset := strings.Index(header, "("); openOffset >= 0 {
			for _, arg := range f.CallArgs(fn.Start + openOffset) {
				text := strings.TrimSpace(f.Code[arg.Start:arg.End])
				before, after, ok := strings.Cut(text, "=")
				if !ok || strings.TrimSpace(after) == "" {
					continue
				}
				parameter := parameterName.FindStringSubmatch(before)
				if len(parameter) != 2 {
					continue
				}
				allDigits := true
				for _, char := range strings.TrimSpace(after) {
					if char < '0' || char > '9' {
						allDigits = false
						break
					}
				}
				defaultValue := strings.TrimSpace(after)
				if allDigits && strings.TrimLeft(defaultValue, "0") != "" {
					parameters[parameter[1]] = true
				}
			}
		}
		cache[fn.Brace] = parameters
	}
	return parameters[name]
}

func moneyVariableInScope(vars map[string][]int, name string, fn patternkit.JsFunc, inFunction bool) bool {
	if name == "" {
		return false
	}
	scope := -1
	if inFunction {
		scope = fn.Brace
	}
	return slices.Contains(vars[name], scope)
}

func counterParameterInFunction(f patternkit.JsFlat, name string, fn patternkit.JsFunc) bool {
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

// enclosingFunctionsAt resolves function scopes for sorted source positions in
// one forward pass. Calling EnclosingFunction separately for each arithmetic
// operator rescans the preceding source each time on minified files.
func enclosingFunctionsAt(f patternkit.JsFlat, index *patternkit.JsFunctions, positions []int) map[int]patternkit.JsFunc {
	// arithmeticOperators returns source-ordered offsets, so keep this scan linear.
	functions := make(map[int]patternkit.JsFunc, len(positions))
	type functionScope struct {
		function patternkit.JsFunc
		ok       bool
	}
	active := functionScope{}
	stack := make([]functionScope, 0)
	positionIndex := 0
	for i := 0; i < len(f.Code) && positionIndex < len(positions); i++ {
		for positionIndex < len(positions) && positions[positionIndex] == i {
			if active.ok {
				functions[i] = active.function
			}
			positionIndex++
		}
		switch f.Code[i] {
		case '{':
			stack = append(stack, active)
			if fn, ok := index.AtBrace(i); ok {
				active = functionScope{function: fn, ok: true}
			}
		case '}':
			if len(stack) > 0 {
				active = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
		}
	}
	return functions
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
	return slices.ContainsFunc(words, r.isMoneyFieldName) || slices.ContainsFunc(memberChain.FindAllString(arg, -1), r.decimalMember)
}

type arithmeticOperator struct {
	pos int
	op  string
}

// jsxTagOperators reports, for each of the sorted offsets, whether it sits
// inside a JSX tag: after the last '<' before it, with no '>' since, the '<'
// opening a tag name (<div, </div), and not inside a {...} expression of the
// tag unless a quote is still open. One pass carries the scan state from one
// offset to the next and starts it again at every '<'.
func jsxTagOperators(code string, positions []int) []bool {
	out := make([]bool, len(positions))
	start, depth := -1, 0
	var quote byte
	closed := false
	i := 0
	for k, pos := range positions {
		for ; i < pos; i++ {
			c := code[i]
			if c == '<' {
				start, depth, quote, closed = i, 0, 0, false
				continue
			}
			if c == '>' {
				closed = true
			}
			if quote != 0 {
				if c == quote && code[i-1] != '\\' {
					quote = 0
				}
				continue
			}
			switch c {
			case '\'', '"', '`':
				quote = c
			case '{':
				depth++
			case '}':
				if depth > 0 {
					depth--
				}
			}
		}
		if start < 0 || closed {
			continue
		}
		name := start + 1
		if name < pos && code[name] == '/' {
			name++
		}
		if name >= pos || (code[name] < 'A' || code[name] > 'Z') && (code[name] < 'a' || code[name] > 'z') {
			continue
		}
		out[k] = quote != 0 || depth == 0
	}
	return out
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

func isExpressionSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == '\v' || value == '\f'
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
				prev := i - 1
				for prev >= start && isExpressionSpace(code[prev]) {
					prev--
				}
				continues := prev >= start && (code[prev] == '?' || code[prev] == ':' || code[prev] == '+' || code[prev] == '-')
				continues = continues || prev-1 >= start && code[prev-1] == '|' && code[prev] == '|'
				next := i + 1
				for next < len(code) && isExpressionSpace(code[next]) {
					next++
				}
				if continues || next < len(code) && code[next] == ':' {
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

// ReportsOn reports whether this rule can report on this file.
func (r *FrontendMoneyArithmeticRule) ReportsOn(ctx *core.FileContext) bool {
	return frontendProjectReportsOn(ctx)
}
