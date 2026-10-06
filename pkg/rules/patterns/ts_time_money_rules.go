package patterns

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDatetimeLocalFilledWithUTCRule())
	rules.Register(NewClientFloorsServerRoundedAmountRule())
}

// DatetimeLocalFilledWithUTCRule detects a datetime-local input filled with
// the digits of a UTC timestamp:
//
//	<input type="datetime-local" value={transfer.executedAt.slice(0, 16)} />
//
// The browser shows and returns the value of a datetime-local field as local
// time, without a zone. The field shows UTC digits, and saving it through
// new Date(value).toISOString() shifts the moment by the zone's offset; an
// operator who enters the UTC time he sees stores another one.
type DatetimeLocalFilledWithUTCRule struct {
	*rules.BaseRule
}

// NewDatetimeLocalFilledWithUTCRule creates the rule
func NewDatetimeLocalFilledWithUTCRule() *DatetimeLocalFilledWithUTCRule {
	return &DatetimeLocalFilledWithUTCRule{BaseRule: rules.NewBaseRule(
		"datetime-local-filled-with-utc",
		"patterns",
		"Detects an input type=\"datetime-local\" whose value is cut from an ISO/UTC string — the browser reads the digits as local time, and saving shifts the moment by the zone offset",
		core.SeverityMedium,
	)}
}

var (
	jsDatetimeLocalType = regexp.MustCompile(`\btype\s*=\s*\{?\s*["'` + "`" + `]datetime-local["'` + "`" + `]`)
	jsValueAttribute    = regexp.MustCompile(`\b(?:value|defaultValue)\s*=\s*\{`)
	jsUTCDigits         = regexp.MustCompile(`\.\s*(?:slice|substring|substr)\s*\(\s*0\s*,\s*16\s*\)|\.\s*toISOString\s*\(\s*\)`)
)

// AnalyzeFile reports the datetime-local inputs filled with UTC digits.
func (r *DatetimeLocalFilledWithUTCRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsDatetimeLocalType.FindAllStringIndex(f.text, -1) {
		start, end, ok := f.jsxElement(m[0])
		if !ok {
			continue
		}
		element := f.text[start:end]
		for _, v := range jsValueAttribute.FindAllStringIndex(element, -1) {
			open := start + v[1] - 1
			closeAt, ok := f.closing(open)
			if !ok || closeAt > end {
				continue
			}
			if jsUTCDigits.MatchString(f.text[open:closeAt]) {
				violations = jsReport(violations, r.BaseRule, ctx, f.line(open),
					"The datetime-local field is filled with the digits of a UTC timestamp — the browser reads them as local time, and saving shifts the moment by the zone offset",
					"Fill the field with the local time of the moment (getFullYear/getMonth/getDate/getHours/getMinutes) and show the UTC value next to it")
			}
		}
	}
	return violations
}

// jsxElement returns the span of the JSX opening tag that holds pos: from
// its '<' to the '>' that ends it, outside the braces of its attributes.
func (f jsFlat) jsxElement(pos int) (int, int, bool) {
	start := -1
	for i := pos; i > 0; i-- {
		if f.code[i] == '<' && i+1 < len(f.code) && isASCIILetter(f.code[i+1]) {
			start = i
			break
		}
		if f.code[i] == '>' || f.code[i] == ';' {
			return 0, 0, false
		}
	}
	if start < 0 {
		return 0, 0, false
	}
	depth := 0
	for i := start + 1; i < len(f.code); i++ {
		switch f.code[i] {
		case '{':
			depth++
		case '}':
			depth--
		case '>':
			if depth == 0 {
				return start, i + 1, true
			}
		}
	}
	return 0, 0, false
}

// ClientFloorsServerRoundedAmountRule detects the frontend flooring to cents
// an amount the backend already rounded half up:
//
//	DailyGain: dailyGain.StringFixed(2),          // Go: 0.41515 -> "0.42"
//	const delta = parseDecimal(entry.dailyGain)    // TS
//	amount: floorToCent(delta)                      // 0.42, not 0.41
//
// The floor of a value rounded half up is that value: the screen that floors
// the raw figure shows 0.41 and this one 0.42 for the same day. A Go field is
// matched by its json name.
type ClientFloorsServerRoundedAmountRule struct {
	*rules.BaseRule
	// halfUp holds the json names of the fields the Go code fills with a
	// value rounded half up.
	halfUp map[string]bool
}

// NewClientFloorsServerRoundedAmountRule creates the rule
func NewClientFloorsServerRoundedAmountRule() *ClientFloorsServerRoundedAmountRule {
	r := &ClientFloorsServerRoundedAmountRule{BaseRule: rules.NewBaseRule(
		"client-floors-server-rounded-amount",
		"patterns",
		"Detects the frontend flooring to cents an amount whose Go field the backend fills rounded half up (StringFixed/Round) — the floor of a rounded value keeps the rounding, and the screen disagrees by a cent with those that floor the raw figure",
		core.SeverityMedium,
	)}
	r.ResetState()
	return r
}

// ResetState drops the root's fields.
func (r *ClientFloorsServerRoundedAmountRule) ResetState() {
	r.halfUp = make(map[string]bool)
}

// UseProjectFiles collects the json names of the Go fields set from a value
// rounded half up.
func (r *ClientFloorsServerRoundedAmountRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	jsonNames := make(map[string]map[string]string)
	var literals []*ast.CompositeLit
	for _, ctx := range files {
		if !productionGoFile(ctx) {
			continue
		}
		ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.TypeSpec:
				st, ok := node.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range st.Fields.List {
					name, ok := jsonFieldName(field, false)
					if !ok || len(field.Names) != 1 || name == "" || name == "-" {
						continue
					}
					if jsonNames[node.Name.Name] == nil {
						jsonNames[node.Name.Name] = make(map[string]string)
					}
					jsonNames[node.Name.Name][field.Names[0].Name] = name
				}
			case *ast.CompositeLit:
				literals = append(literals, node)
			}
			return true
		})
	}
	for _, lit := range literals {
		fields := jsonNames[typeIdentName(lit.Type)]
		if fields == nil {
			continue
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || fields[key.Name] == "" || !roundedHalfUpSyntax(kv.Value) {
				continue
			}
			r.halfUp[fields[key.Name]] = true
		}
	}
}

// roundedHalfUpSyntax reports a chain of calls ending in StringFixed(n) or
// Round(n) with no rounding toward the floor on the way.
func roundedHalfUpSyntax(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || !halfUpMethods[sel.Sel.Name] || len(call.Args) != 1 {
		return false
	}
	switch arg := ast.Unparen(call.Args[0]).(type) {
	case *ast.BasicLit:
	case *ast.Ident:
		if arg.Name == "nil" {
			return false
		}
	default:
		return false
	}
	for x := sel.X; ; {
		inner, ok := ast.Unparen(x).(*ast.CallExpr)
		if !ok {
			return true
		}
		innerSel, ok := ast.Unparen(inner.Fun).(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if downMethods[innerSel.Sel.Name] {
			return false
		}
		x = innerSel.X
	}
}

var (
	jsFloorCentsCall = regexp.MustCompile(`(?i)\bfloor\w*cents?\s*\(`)
	jsMathFloorCents = regexp.MustCompile(`\bMath\.floor\s*\(`)
	jsCentScale      = regexp.MustCompile(`\*\s*100\b`)
	jsMemberName     = regexp.MustCompile(`\.\s*([A-Za-z_$][\w$]*)|['"]([A-Za-z_$][\w$]*)['"]`)
)

// AnalyzeFile reports the floor-to-cents calls of the file over a field the
// backend rounds half up.
func (r *ClientFloorsServerRoundedAmountRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if len(r.halfUp) == 0 || !productionFrontendFile(ctx) {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	report := func(pos int, field string) {
		violations = jsReport(violations, r.BaseRule, ctx, f.line(pos),
			"The amount floored here comes from "+field+", which the backend already rounds half up — the floor keeps that rounding, and this screen disagrees by a cent with those that floor the raw figure",
			"Send the unrounded amount and round it in one place, or round it down on the server with the same rule as the screens")
	}
	for _, m := range jsFloorCentsCall.FindAllStringIndex(f.code, -1) {
		if def := f.code[max(0, m[0]-9):m[0]]; strings.HasSuffix(strings.TrimSpace(def), "function") {
			continue
		}
		if field := r.flooredField(f, m[1]-1); field != "" {
			report(m[0], field)
		}
	}
	for _, m := range jsMathFloorCents.FindAllStringIndex(f.code, -1) {
		closeAt, ok := f.closing(m[1] - 1)
		if !ok || !jsCentScale.MatchString(f.code[m[1]:closeAt]) {
			continue
		}
		if field := r.flooredField(f, m[1]-1); field != "" {
			report(m[0], field)
		}
	}
	return violations
}

// flooredField returns the half-up field the argument of the call at open
// reads: named in the argument, or in the definition of the variable the
// argument is.
func (r *ClientFloorsServerRoundedAmountRule) flooredField(f jsFlat, open int) string {
	args := f.callArgs(open)
	if len(args) == 0 {
		return ""
	}
	arg := strings.TrimSpace(f.text[args[0].start:args[0].end])
	if field := r.mentionedField(arg); field != "" {
		return field
	}
	name := strings.TrimSpace(strings.SplitN(arg, "*", 2)[0])
	if !jsIdentifier.MatchString(name) {
		return ""
	}
	fn, ok := f.enclosingFunction(open)
	if !ok {
		return ""
	}
	body := f.text[fn.brace:open]
	def := regexp.MustCompile(`\b(?:const|let|var)\s+` + regexp.QuoteMeta(name) + `\s*(?::[^=]+)?=\s*([^\n;]+)`)
	if m := def.FindStringSubmatch(body); m != nil {
		return r.mentionedField(m[1])
	}
	return ""
}

// mentionedField returns the first half-up field an expression reads
// (x.field) or names ('field').
func (r *ClientFloorsServerRoundedAmountRule) mentionedField(expr string) string {
	for _, m := range jsMemberName.FindAllStringSubmatch(expr, -1) {
		for _, name := range m[1:] {
			if name != "" && r.halfUp[name] {
				return name
			}
		}
	}
	return ""
}
