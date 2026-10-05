package patterns

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(newTSRule("ts-response-field-defaults-to-empty",
		"Detects a response field answered with [] or 0 when it is not an array or a number (Array.isArray(r.items) ? r.items : []) — a malformed response shows as no data",
		checkResponseFieldDefault))
	rules.Register(newTSRule("ts-coerced-number-fallback-dead",
		"Detects Number(x).toFixed(...) || '-' and Number(x) ?? y — the coerced value is never falsy or nullish, and the fallback never shows",
		checkCoercedNumberFallback))
	rules.Register(newTSRule("ts-partial-body-sent-with-put",
		"Detects a Partial<T> parameter sent as the body of a PUT — PUT replaces the record, and every field the caller left out is emptied",
		checkPartialPut))
	rules.Register(newTSRule("ts-form-number-unchecked-in-payload",
		"Detects parseFloat/Number of a value put into a request payload with no NaN check in the function — text in a number field is sent as null",
		checkFormNumberPayload))
	rules.Register(newTSRule("ts-url-filter-enum-unvalidated",
		"Detects a status, direction or other enum filter taken as is from a link or saved state while a sibling filter of the same object is checked against its allowed values",
		checkURLFilterEnum))
}

// tsRule is a rule over one TS/JS file read as jsFlat: a production
// frontend file, or a test file for the rules about tests.
type tsRule struct {
	*rules.BaseRule
	accept func(ctx *core.FileContext) bool
	check  func(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation
}

func newTSRule(name, description string, check func(*tsRule, *core.FileContext, jsFlat) []*core.Violation) *tsRule {
	return &tsRule{BaseRule: rules.NewBaseRule(name, "patterns", description, core.SeverityMedium), accept: productionFrontendFile, check: check}
}

// newTSTestRule makes a rule over the TS/JS test and e2e files and the test
// runner configs.
func newTSTestRule(name, description string, check func(*tsRule, *core.FileContext, jsFlat) []*core.Violation) *tsRule {
	return &tsRule{BaseRule: rules.NewBaseRule(name, "patterns", description, core.SeverityMedium), accept: frontendTestFile, check: check}
}

// AnalyzeFile reads a TS/JS file the rule accepts and checks it.
func (r *tsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !r.accept(ctx) {
		return nil
	}
	return r.check(r, ctx, newJSFlat(ctx))
}

const jsMemberPath = `[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)+`

var (
	responseArrayDefault  = regexp.MustCompile(`Array\.isArray\(\s*(` + jsMemberPath + `)\s*\)\s*\?\s*(` + jsMemberPath + `)(?:\s+as\s+[\w$<>\[\]., |]+?)?\s*:\s*\[\s*\]`)
	responseNumberDefault = regexp.MustCompile(`typeof\s+(` + jsMemberPath + `)\s*===?\s*['"]number['"]\s*\?\s*(` + jsMemberPath + `)(?:\s+as\s+number)?\s*:\s*0\b`)
)

// checkResponseFieldDefault reports a field of an object answered with an
// empty array or zero when its type is wrong.
func checkResponseFieldDefault(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	var out []*core.Violation
	for _, re := range []*regexp.Regexp{responseArrayDefault, responseNumberDefault} {
		for _, m := range re.FindAllStringSubmatchIndex(f.text, -1) {
			tested, used := f.text[m[2]:m[3]], f.text[m[4]:m[5]]
			if tested != used {
				continue
			}
			out = jsReport(out, r.BaseRule, ctx, f.line(m[0]),
				tested+" is replaced by an empty value when it has the wrong type — a malformed response shows as no data",
				"Throw on a response of the wrong shape, and let the caller show the error")
		}
	}
	return out
}

var (
	numberCoercion   = regexp.MustCompile(`\b(?:Number|parseFloat|parseInt)\s*\(`)
	numberMethodTail = regexp.MustCompile(`^(?:\s*\.\s*(?:toFixed|toLocaleString|toPrecision|toString)\s*\()`)
	fallbackOperator = regexp.MustCompile(`^\s*(\|\||\?\?)`)
)

// checkCoercedNumberFallback reports a fallback after a coerced number that
// can never be taken: a formatted number is a non-empty string even for NaN,
// and a number is never nullish.
func checkCoercedNumberFallback(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	var out []*core.Violation
	for _, m := range numberCoercion.FindAllStringIndex(f.code, -1) {
		if m[0] > 0 && f.code[m[0]-1] == '.' {
			continue // Number.isFinite(...) and the like
		}
		end, ok := f.closing(m[1] - 1)
		if !ok {
			continue
		}
		formatted := false
		for {
			tail := numberMethodTail.FindStringIndex(f.code[end+1:])
			if tail == nil {
				break
			}
			if end, ok = f.closing(end + tail[1]); !ok {
				break
			}
			formatted = true
		}
		if !ok {
			continue
		}
		op := fallbackOperator.FindStringSubmatch(f.code[end+1:])
		if op == nil || (op[1] == "||" && !formatted) {
			continue // Number(x) || 0 does catch NaN and 0
		}
		out = jsReport(out, r.BaseRule, ctx, f.line(m[0]),
			"The value before "+op[1]+" is a coerced number that is never falsy or nullish — the fallback never shows, and NaN reaches the screen",
			"Check Number.isFinite on the number and choose the fallback before formatting it")
	}
	return out
}

var (
	partialParam = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\??\s*:\s*Partial\s*<`)
	putMethod    = regexp.MustCompile(`['"]PUT['"]`)
)

// checkPartialPut reports a Partial<T> parameter of a function whose body
// sends it with PUT.
func checkPartialPut(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	var out []*core.Violation
	for _, m := range partialParam.FindAllStringSubmatchIndex(f.code, -1) {
		name := f.code[m[2]:m[3]]
		body, ok := paramFunctionBody(f, m[0])
		if !ok {
			continue
		}
		text := f.text[body.start:body.end]
		uses := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(name) + `\b`)
		if !putMethod.MatchString(text) || !uses.MatchString(f.code[body.start:body.end]) {
			continue
		}
		out = jsReport(out, r.BaseRule, ctx, f.line(m[0]),
			name+" is a Partial and goes out as the body of a PUT — the server replaces the record, and every field left out is emptied",
			"Send the full object (the record as read, with the edit applied), or use PATCH where the server merges the fields")
	}
	return out
}

// paramFunctionBody returns the body of the function whose parameter list
// holds the offset.
func paramFunctionBody(f jsFlat, pos int) (jsSpanRange, bool) {
	depth := 0
	open := -1
	for i := pos - 1; i >= 0 && open < 0; i-- {
		switch f.code[i] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth == 0 {
				if f.code[i] != '(' {
					return jsSpanRange{}, false
				}
				open = i
			}
			depth--
		}
	}
	if open < 0 {
		return jsSpanRange{}, false
	}
	closeParen, ok := f.closing(open)
	if !ok {
		return jsSpanRange{}, false
	}
	// The body opens at the first '{' after the list and an optional return
	// type that holds no braces of its own.
	brace := strings.IndexAny(f.code[closeParen:], "{;")
	if brace < 0 || f.code[closeParen+brace] != '{' {
		return jsSpanRange{}, false
	}
	start := closeParen + brace
	end, ok := f.closing(start)
	return jsSpanRange{start, end}, ok
}

var (
	payloadNumberProperty = regexp.MustCompile(`^\s*[A-Za-z_$][\w$]*\s*:\s*(?:[^?:]+\?\s*)?(?:parseFloat|Number|parseInt)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*(?::\s*(?:undefined|null)\s*)?$`)
	payloadNumberAssign   = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*=\s*(?:parseFloat|Number|parseInt)\s*\(`)
	nanCheck              = regexp.MustCompile(`\b(?:isNaN|isFinite)\s*\(`)
)

// checkFormNumberPayload reports a parsed number put into an object passed
// to an awaited call (a request), or assigned to a field of a local object,
// in a function that never checks a parsed number for NaN.
func checkFormNumberPayload(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	var out []*core.Violation
	report := func(pos int) {
		if fn, ok := f.enclosingFunction(pos); ok {
			if end, ok := f.closing(fn.brace); ok && nanCheck.MatchString(f.code[fn.brace:end]) {
				return
			}
		}
		out = jsReport(out, r.BaseRule, ctx, f.line(pos),
			"A parsed number goes into the payload unchecked — text in the field is NaN, which JSON sends as null, and the server clears the value",
			"Check Number.isFinite on the parsed value and show the field error before sending")
	}
	for open := strings.IndexByte(f.code, '{'); open >= 0; {
		if callArgumentObject(f, open) {
			if end, ok := f.closing(open); ok {
				for _, item := range f.items(open, end) {
					text := f.code[item.start:item.end]
					if payloadNumberProperty.MatchString(text) && !hasFallback(f, item) {
						report(item.start + len(text) - len(strings.TrimLeft(text, " \t\n")))
					}
				}
			}
		}
		next := strings.IndexByte(f.code[open+1:], '{')
		if next < 0 {
			break
		}
		open += next + 1
	}
	for _, m := range payloadNumberAssign.FindAllStringSubmatchIndex(f.code, -1) {
		name := f.code[m[2]:m[3]]
		fn, ok := f.enclosingFunction(m[0])
		if !ok {
			continue
		}
		declared := regexp.MustCompile(`\b(?:const|let)\s+` + regexp.QuoteMeta(name) + `\b[^=]*=\s*\{`)
		if declared.MatchString(f.code[fn.brace:m[0]]) {
			report(m[2])
		}
	}
	return out
}

var awaitedCallee = regexp.MustCompile(`\bawait\s+[\w$.?]+\s*$`)

// callArgumentObject reports an object literal written as an argument of an
// awaited call: await api.create({ ... }), await api.update(id, { ... }).
func callArgumentObject(f jsFlat, open int) bool {
	paren, ok := f.enclosingParen(open)
	if !ok || !strings.HasSuffix(strings.TrimRight(f.code[:open], " \t\n"), "(") && !strings.HasSuffix(strings.TrimRight(f.code[:open], " \t\n"), ",") {
		return false
	}
	return awaitedCallee.MatchString(f.code[:paren])
}

// hasFallback reports a property value ending in || or ?? fallback.
func hasFallback(f jsFlat, item jsSpanRange) bool {
	text := f.code[item.start:item.end]
	return strings.Contains(text, "||") || strings.Contains(text, "??")
}

var (
	enumFilterKey      = regexp.MustCompile(`^(?:status|state|direction|type|kind|side|mode|category|level|stage|phase)$`)
	filterProperty     = regexp.MustCompile(`(?s)^\s*([A-Za-z_$][\w$]*)\s*:\s*(.*?)\s*$`)
	rawFilterValue     = regexp.MustCompile(`(?s)^(?:typeof\s+[\w$.]+\s*===?\s*['"]string['"]\s*\?\s*[\w$.]+\s*:\s*['"]{2}|[\w$]+\.get\(\s*['"][\w-]+['"]\s*\)(?:\s*(?:\?\?|\|\|)\s*['"]{2})?|[\w$]+\.[\w$]+(?:\s*(?:\?\?|\|\|)\s*['"]{2})?)$`)
	validatorCall      = regexp.MustCompile(`^([A-Za-z_$][\w$]*)\s*\(`)
	allowedValuesCheck = regexp.MustCompile(`\.(?:has|includes)\s*\(`)
)

// checkURLFilterEnum reports raw enum filters of an object literal in which
// another filter goes through a function that checks the allowed values.
func checkURLFilterEnum(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	var out []*core.Violation
	validators := make(map[string]bool)
	for open := strings.IndexByte(f.code, '{'); open >= 0; {
		if end, ok := f.closing(open); ok {
			out = append(out, rawEnumFilters(r, ctx, f, open, end, validators)...)
		}
		next := strings.IndexByte(f.code[open+1:], '{')
		if next < 0 {
			break
		}
		open += next + 1
	}
	return out
}

func rawEnumFilters(r *tsRule, ctx *core.FileContext, f jsFlat, open, end int, validators map[string]bool) []*core.Violation {
	var raw []jsSpanRange
	checked := false
	for _, item := range f.items(open, end) {
		m := filterProperty.FindStringSubmatch(f.text[item.start:item.end])
		if m == nil {
			continue
		}
		if call := validatorCall.FindStringSubmatch(m[2]); call != nil && checksAllowedValues(f, call[1], validators) {
			checked = true
			continue
		}
		if enumFilterKey.MatchString(m[1]) && rawFilterValue.MatchString(m[2]) {
			raw = append(raw, item)
		}
	}
	if !checked {
		return nil
	}
	var out []*core.Violation
	for _, item := range raw {
		text := f.text[item.start:item.end]
		pos := item.start + len(text) - len(strings.TrimLeft(text, " \t\n"))
		out = jsReport(out, r.BaseRule, ctx, f.line(pos),
			"The filter is taken as is while its sibling is checked against its allowed values — a value from an old link or saved state goes to the API and empties the list",
			"Check the value against the allowed set (in its canonical case) and show the rejected one")
	}
	return out
}

// checksAllowedValues reports a function of the file whose definition checks
// its input against a set or a list of allowed values.
func checksAllowedValues(f jsFlat, name string, cache map[string]bool) bool {
	if known, ok := cache[name]; ok {
		return known
	}
	def := regexp.MustCompile(`\b(?:const|let|function)\s+` + regexp.QuoteMeta(name) + `\b`).FindStringIndex(f.code)
	found := false
	if def != nil {
		end := def[1] + 400
		if end > len(f.code) {
			end = len(f.code)
		}
		found = allowedValuesCheck.MatchString(f.code[def[1]:end])
	}
	cache[name] = found
	return found
}

// TSNumberFieldForDecimalJSONRule detects a TypeScript response field typed
// number whose Go counterpart is a decimal:
//
//	type NAVSnapshot struct { UnitPrice SafeDecimal `json:"unitPrice"` }
//	export interface NAVSnapshot { unitPrice: number }
//
// A decimal marshals as a JSON string (shopspring's default, kept by the
// wrappers around it), so the field holds "1.2345" while the compiler
// believes it is a number: unitPrice.toFixed(4) throws, and a + b
// concatenates. An interface matches a Go struct of the same name, a field
// the struct's json name; a project that sets
// decimal.MarshalJSONWithoutQuotes = true sends numbers and is left alone.
type TSNumberFieldForDecimalJSONRule struct {
	*rules.BaseRule
	// decimals maps a struct name to the json names of its decimal fields.
	decimals map[string]map[string]bool
}

// NewTSNumberFieldForDecimalJSONRule creates the rule
func NewTSNumberFieldForDecimalJSONRule() *TSNumberFieldForDecimalJSONRule {
	r := &TSNumberFieldForDecimalJSONRule{BaseRule: rules.NewBaseRule(
		"ts-number-field-for-decimal-json",
		"patterns",
		"Detects a TypeScript interface field typed number whose Go struct of the same name holds a decimal there — the JSON carries a string, and number methods throw on it",
		core.SeverityMedium,
	)}
	r.ResetState()
	return r
}

func init() { rules.Register(NewTSNumberFieldForDecimalJSONRule()) }

// ResetState drops the root's structs.
func (r *TSNumberFieldForDecimalJSONRule) ResetState() {
	r.decimals = make(map[string]map[string]bool)
}

var decimalTypeName = regexp.MustCompile(`Decimal$`)

// UseProjectFiles collects the decimal json fields of the Go structs.
func (r *TSNumberFieldForDecimalJSONRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	conflicts := make(map[string]map[string]bool)
	for _, ctx := range files {
		if !productionGoFile(ctx) {
			continue
		}
		if strings.Contains(string(ctx.Content), "MarshalJSONWithoutQuotes = true") {
			r.ResetState()
			return
		}
		ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := spec.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range st.Fields.List {
				name, ok := jsonFieldName(field, false)
				if !ok || len(field.Names) != 1 || name == "" || name == "-" {
					continue
				}
				decimal := decimalTypeName.MatchString(typeIdentName(field.Type))
				set := r.decimals
				if !decimal {
					set = conflicts
				}
				if set[spec.Name.Name] == nil {
					set[spec.Name.Name] = make(map[string]bool)
				}
				set[spec.Name.Name][name] = true
			}
			return true
		})
	}
	for structName, fields := range conflicts {
		for name := range fields {
			delete(r.decimals[structName], name)
		}
	}
}

// typeIdentName returns the last identifier of a field type: SafeDecimal
// for models.SafeDecimal, *SafeDecimal and []SafeDecimal stay out.
func typeIdentName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.StarExpr:
		return typeIdentName(t.X)
	}
	return ""
}

var (
	tsTypeStart   = regexp.MustCompile(`\b(?:interface\s+([A-Z][\w$]*)\b[^{]*|type\s+([A-Z][\w$]*)\s*=\s*)\{`)
	tsNumberField = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)\s*\??\s*:\s*number(?:\s*\|\s*(?:null|undefined))*\s*[;,]?\s*$`)
)

// AnalyzeFile reports the number fields of the file's interfaces that their
// Go structs hold as decimals.
func (r *TSNumberFieldForDecimalJSONRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if len(r.decimals) == 0 || !productionFrontendFile(ctx) {
		return nil
	}
	f := newJSFlat(ctx)
	var out []*core.Violation
	for _, m := range tsTypeStart.FindAllStringSubmatchIndex(f.code, -1) {
		name := ""
		for _, g := range []int{2, 4} {
			if m[g] >= 0 {
				name = f.code[m[g]:m[g+1]]
			}
		}
		fields := r.decimals[name]
		if len(fields) == 0 {
			continue
		}
		end, ok := f.closing(m[1] - 1)
		if !ok {
			continue
		}
		for _, line := range strings.Split(f.code[m[1]:end], "\n") {
			fm := tsNumberField.FindStringSubmatch(line)
			if fm == nil || !fields[fm[1]] {
				continue
			}
			pos := m[1] + strings.Index(f.code[m[1]:end], line)
			out = jsReport(out, r.BaseRule, ctx, f.line(pos),
				name+"."+fm[1]+" is typed number, and the Go struct "+name+" holds a decimal there, which arrives as a JSON string — number methods throw on it",
				"Type the field string (or number | string) and convert it where a number is needed")
		}
	}
	return out
}
