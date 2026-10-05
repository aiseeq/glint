package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDecimalInputSeparatorNormalizedByReplaceRule())
	rules.Register(NewParseTruncatesInputAtSeparatorRule())
	rules.Register(NewExternalRateAcceptedWithoutPositivityCheckRule())
	rules.Register(NewEnvBoolParsedByStringEqualityRule())
	rules.Register(NewAmbiguousDateLayoutsFirstMatchRule())
	rules.Register(NewMissingTimestampDefaultedToNowRule())
	rules.Register(NewConfigLiteralOmitsRequiredFieldRule())
}

// valueAssignments maps the local variables of a body to every expression
// assigned to them one to one (v := e, v = e, var v = e).
func valueAssignments(info *types.Info, body *ast.BlockStmt) map[types.Object][]ast.Expr {
	assigned := make(map[types.Object][]ast.Expr)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
					if obj := info.ObjectOf(ident); obj != nil {
						assigned[obj] = append(assigned[obj], node.Rhs[i])
					}
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) != len(node.Values) {
				return true
			}
			for i, name := range node.Names {
				if obj := info.ObjectOf(name); obj != nil {
					assigned[obj] = append(assigned[obj], node.Values[i])
				}
			}
		}
		return true
	})
	return assigned
}

// findInFlow returns the first node of expr, or of a value assigned to a
// variable expr reads, that match accepts.
func findInFlow(info *types.Info, assigned map[types.Object][]ast.Expr, expr ast.Expr, match func(ast.Node) bool) ast.Node {
	seen := make(map[types.Object]bool)
	var visit func(ast.Expr, int) ast.Node
	visit = func(e ast.Expr, depth int) ast.Node {
		var found ast.Node
		ast.Inspect(e, func(n ast.Node) bool {
			if found != nil {
				return false
			}
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			if n != nil && match(n) {
				found = n
				return false
			}
			ident, ok := n.(*ast.Ident)
			if !ok || depth == 0 {
				return true
			}
			obj := info.ObjectOf(ident)
			if obj == nil || seen[obj] {
				return true
			}
			seen[obj] = true
			for _, value := range assigned[obj] {
				if hit := visit(value, depth-1); hit != nil {
					found = hit
					return false
				}
			}
			return true
		})
		return found
	}
	return visit(expr, 4)
}

// isNumberParse reports a call that reads a number from text: the decimal
// constructors and strconv's parsers.
func isNumberParse(info *types.Info, call *ast.CallExpr) bool {
	fn := staticFunc(info, call)
	if fn == nil || fn.Pkg() == nil || len(call.Args) == 0 {
		return false
	}
	switch fn.Pkg().Path() {
	case shopspringDecimalPath:
		return fn.Name() == "NewFromString" || fn.Name() == "RequireFromString"
	case "strconv":
		return fn.Name() == "ParseFloat" || fn.Name() == "ParseInt" || fn.Name() == "ParseUint" || fn.Name() == "Atoi"
	}
	return false
}

// numberParses returns the number parsers called in a body.
func numberParses(info *types.Info, body *ast.BlockStmt) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isNumberParse(info, call) {
			calls = append(calls, call)
		}
		return true
	})
	return calls
}

// NewDecimalInputSeparatorNormalizedByReplaceRule creates
// decimal-input-separator-normalized-by-replace: a comma or a dot removed
// from a number before it is parsed. The same character is the decimal
// separator in one notation and the thousands separator in another, so
// "1,5" becomes 15 and "1.250,00" becomes 125000:
//
//	amount, err := decimal.NewFromString(strings.ReplaceAll(amountStr, ",", ""))
func NewDecimalInputSeparatorNormalizedByReplaceRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"decimal-input-separator-normalized-by-replace",
			"patterns",
			"Detects a comma or a dot removed from a number before parsing — the same character is a decimal separator in another notation, and 1,5 becomes 15",
			core.SeverityHigh,
		),
		suggestion: "Parse the number with one function that recognizes the notation (the last separator followed by up to two digits is the decimal one) and rejects input it cannot read unambiguously",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		assigned := valueAssignments(scope.info, fn.Body)
		var findings []funcFinding
		reported := make(map[ast.Node]bool)
		for _, parse := range numberParses(scope.info, fn.Body) {
			hit := findInFlow(scope.info, assigned, parse.Args[0], func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				return ok && removesSeparator(scope.info, call)
			})
			replace, ok := hit.(*ast.CallExpr)
			if !ok || reported[hit] || scrapedText(scope.info, assigned, replace.Args[0]) {
				continue
			}
			reported[hit] = true
			findings = append(findings, funcFinding{node: hit, message: "A separator is removed from the number before it is parsed — in another notation it is the decimal separator, and 1,5 is read as 15"})
		}
		return findings
	}
	return r
}

// removesSeparator reports strings.ReplaceAll(s, ",", "") or
// strings.Replace(s, ".", "", n): a comma or a dot deleted from text.
func removesSeparator(info *types.Info, call *ast.CallExpr) bool {
	if !isPkgFunc(info, call, "strings", "ReplaceAll") && !isPkgFunc(info, call, "strings", "Replace") {
		return false
	}
	if len(call.Args) < 3 {
		return false
	}
	old, ok := stringLiteral(call.Args[1])
	if !ok || (old != "," && old != ".") {
		return false
	}
	replacement, ok := stringLiteral(call.Args[2])
	return ok && replacement == ""
}

// scrapedText reports text taken out of a page by a regular expression: a
// machine-rendered number in the one notation of its source, not typed input.
func scrapedText(info *types.Info, assigned map[types.Object][]ast.Expr, expr ast.Expr) bool {
	return findInFlow(info, assigned, expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return false
		}
		fn := staticFunc(info, call)
		return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "regexp" && strings.HasPrefix(fn.Name(), "Find")
	}) != nil
}

// NewParseTruncatesInputAtSeparatorRule creates
// parse-truncates-input-at-separator: text cut at a separator and its head
// parsed as a number while the tail is never looked at. "1 000.50" is read as
// 1, and anything after the number passes unseen:
//
//	if i := strings.IndexByte(value, ' '); i > 0 {
//		value = value[:i]
//	}
//	parsed, err := decimal.NewFromString(value)
func NewParseTruncatesInputAtSeparatorRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"parse-truncates-input-at-separator",
			"patterns",
			"Detects a number parsed from the text before a separator while the rest is never checked — \"1 000.50\" is read as 1",
			core.SeverityHigh,
		),
		suggestion: "Check what follows the separator (a known unit or currency code) and reject any other tail instead of dropping it",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		assigned := valueAssignments(scope.info, fn.Body)
		var findings []funcFinding
		reported := make(map[ast.Node]bool)
		for _, parse := range numberParses(scope.info, fn.Body) {
			hit := findInFlow(scope.info, assigned, parse.Args[0], func(n ast.Node) bool {
				return headOfSeparator(scope.info, assigned, fn.Body, n)
			})
			if hit == nil || reported[hit] {
				continue
			}
			reported[hit] = true
			findings = append(findings, funcFinding{node: hit, message: "The number is parsed from the text before the separator and the rest is dropped unchecked — \"1 000.50\" is read as 1"})
		}
		return findings
	}
	return r
}

// separatorIndexFuncs find the position of a separator in a string.
var separatorIndexFuncs = []string{"Index", "IndexByte", "IndexRune", "IndexAny"}

// headOfSeparator reports s[:i] with i the position strings.Index* found in
// s, whose tail (s[i:], s[i+1:]) the body never reads.
func headOfSeparator(info *types.Info, assigned map[types.Object][]ast.Expr, body *ast.BlockStmt, n ast.Node) bool {
	slice, ok := n.(*ast.SliceExpr)
	if !ok || slice.Low != nil || slice.High == nil {
		return false
	}
	index, ok := ast.Unparen(slice.High).(*ast.Ident)
	if !ok {
		return false
	}
	obj := info.ObjectOf(index)
	values := assigned[obj]
	if len(values) != 1 {
		return false
	}
	call, ok := ast.Unparen(values[0]).(*ast.CallExpr)
	if !ok || !slices.ContainsFunc(separatorIndexFuncs, func(name string) bool { return isPkgFunc(info, call, "strings", name) }) {
		return false
	}
	return !readsTailAt(info, body, obj)
}

// readsTailAt reports a slice of the body starting at the index: s[i:],
// s[i+1:].
func readsTailAt(info *types.Info, body *ast.BlockStmt, index types.Object) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if slice, ok := n.(*ast.SliceExpr); ok && slice.Low != nil && mentionsObject(info, slice.Low, index) {
			found = true
		}
		return !found
	})
	return found
}

// NewExternalRateAcceptedWithoutPositivityCheckRule creates
// external-rate-accepted-without-positivity-check: a rate or a price parsed
// from a provider's payload and stored with no check that it is positive. A
// zero or negative value in the feed becomes a zero quote or a division by
// zero further on:
//
//	rate, err := decimal.NewFromString(v.Rate)
//	...
//	rates[v.Code] = rate
func NewExternalRateAcceptedWithoutPositivityCheckRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"external-rate-accepted-without-positivity-check",
			"patterns",
			"Detects a rate or a price parsed from a decoded payload and stored with no check that it is positive — a zero in the feed becomes a zero quote or a division by zero",
			core.SeverityMedium,
		),
		suggestion: "Reject a rate that is not positive (IsPositive) where it is parsed, before it is stored",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		parsed := payloadNumbers(scope.info, fn.Body)
		if len(parsed) == 0 {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != len(assign.Rhs) {
				return true
			}
			for i, lhs := range assign.Lhs {
				value, ok := ast.Unparen(assign.Rhs[i]).(*ast.Ident)
				if !ok {
					continue
				}
				obj := scope.info.ObjectOf(value)
				if !parsed[obj] || !namesRateStore(lhs) || signChecked(scope.info, fn.Body, obj) {
					continue
				}
				findings = append(findings, funcFinding{node: assign, message: "The rate " + value.Name + " is parsed from the payload and stored with no check that it is positive — a zero in the feed becomes a zero quote or a division by zero"})
			}
			return true
		})
		return findings
	}
	return r
}

// payloadNumbers returns the variables a number parser defined from a field
// of a decoded payload: a field carrying a json or xml tag.
func payloadNumbers(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	parsed := make(map[types.Object]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || !isNumberParse(info, call) || !readsPayloadField(info, call.Args[0], valueAssignments(info, body)) {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name != "_" {
			parsed[info.ObjectOf(ident)] = true
		}
		return true
	})
	return parsed
}

// readsPayloadField reports an expression reading, directly or through a
// variable, a struct field with a json or xml tag.
func readsPayloadField(info *types.Info, expr ast.Expr, assigned map[types.Object][]ast.Expr) bool {
	return findInFlow(info, assigned, expr, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		tag := structFieldTag(info, sel)
		return reflect.StructTag(tag).Get("json") != "" || reflect.StructTag(tag).Get("xml") != ""
	}) != nil
}

// structFieldTag returns the tag of the struct field a selector reads.
func structFieldTag(info *types.Info, sel *ast.SelectorExpr) string {
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.FieldVal {
		return ""
	}
	t := selection.Recv()
	tag := ""
	for _, idx := range selection.Index() {
		if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
			t = ptr.Elem()
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok || idx >= st.NumFields() {
			return ""
		}
		tag = st.Tag(idx)
		t = st.Field(idx).Type()
	}
	return tag
}

// rateStoreWords name a value that holds a rate or a price.
var rateStoreWords = map[string]bool{"rate": true, "rates": true, "price": true, "prices": true, "quote": true, "quotes": true}

// namesRateStore reports a store target named for rates: rates[code],
// p.Rate, quote.Price.
func namesRateStore(lhs ast.Expr) bool {
	switch target := ast.Unparen(lhs).(type) {
	case *ast.IndexExpr:
		return namesRateStore(target.X)
	case *ast.SelectorExpr:
		return hasWordFrom(target.Sel.Name, rateStoreWords)
	case *ast.Ident:
		return hasWordFrom(target.Name, rateStoreWords)
	}
	return false
}

// signChecked reports a body testing the variable's sign: v.IsPositive(),
// v.Sign(), v <= 0, v.Cmp(...).
func signChecked(info *types.Info, body *ast.BlockStmt, obj types.Object) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			sel, ok := ast.Unparen(node.Fun).(*ast.SelectorExpr)
			if ok && decimalGuards[sel.Sel.Name] && (mentionsObject(info, sel.X, obj) || slices.ContainsFunc(node.Args, func(a ast.Expr) bool { return mentionsObject(info, a, obj) })) {
				found = true
			}
		case *ast.BinaryExpr:
			switch node.Op {
			case token.LSS, token.LEQ, token.GTR, token.GEQ, token.EQL, token.NEQ:
				if mentionsObject(info, node.X, obj) || mentionsObject(info, node.Y, obj) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// NewEnvBoolParsedByStringEqualityRule creates
// env-bool-parsed-by-string-equality: a boolean setting read as
// os.Getenv(key) == "true". Every other value - TRUE, 1, yes, a typo - is
// silently false instead of an error, and the switch stays off:
//
//	adminEnabled = os.Getenv("ADMIN_ENABLED") == "true"
func NewEnvBoolParsedByStringEqualityRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"env-bool-parsed-by-string-equality",
			"patterns",
			"Detects a boolean environment setting read by comparing it with \"true\" — TRUE, 1 or a typo silently mean false instead of failing the start",
			core.SeverityMedium,
		),
		suggestion: "Parse the value with strconv.ParseBool and fail on an error; keep the default only for an unset variable",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		assigned := valueAssignments(scope.info, fn.Body)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			value, ok := truthLiteralComparison(scope.info, n)
			if !ok {
				return true
			}
			env := findInFlow(scope.info, assigned, value, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				return ok && (isPkgFunc(scope.info, call, "os", "Getenv") || isPkgFunc(scope.info, call, "os", "LookupEnv"))
			})
			if env == nil || envValueOtherwiseRead(scope.info, fn.Body, value, n) {
				return true
			}
			findings = append(findings, funcFinding{node: n, message: "The boolean setting is read by comparing it with a literal — TRUE, 1 or a typo silently mean false instead of failing the start"})
			return true
		})
		return findings
	}
	return r
}

// truthLiterals are the spellings of true a comparison accepts.
var truthLiterals = map[string]bool{"true": true, "1": true, "yes": true, "on": true}

// truthLiteralComparison returns the value of v == "true" or
// strings.EqualFold(v, "true").
func truthLiteralComparison(info *types.Info, n ast.Node) (ast.Expr, bool) {
	var left, right ast.Expr
	switch node := n.(type) {
	case *ast.BinaryExpr:
		if node.Op != token.EQL && node.Op != token.NEQ {
			return nil, false
		}
		left, right = node.X, node.Y
	case *ast.CallExpr:
		if !isPkgFunc(info, node, "strings", "EqualFold") || len(node.Args) != 2 {
			return nil, false
		}
		left, right = node.Args[0], node.Args[1]
	default:
		return nil, false
	}
	if text, ok := stringLiteral(right); ok && truthLiterals[strings.ToLower(text)] {
		return left, true
	}
	if text, ok := stringLiteral(left); ok && truthLiterals[strings.ToLower(text)] {
		return right, true
	}
	return nil, false
}

// envValueOtherwiseRead reports a variable compared with the truth literal
// that the body also reads elsewhere: compared with false, switched on,
// parsed.
func envValueOtherwiseRead(info *types.Info, body *ast.BlockStmt, value ast.Expr, comparison ast.Node) bool {
	ident, ok := ast.Unparen(value).(*ast.Ident)
	if !ok {
		return false
	}
	obj := info.ObjectOf(ident)
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if n == comparison {
			return false
		}
		switch node := n.(type) {
		case *ast.SwitchStmt:
			if node.Tag != nil && mentionsObject(info, node.Tag, obj) {
				found = true
			}
		case *ast.BinaryExpr:
			if _, ok := truthLiteralComparison(info, node); !ok && (node.Op == token.EQL || node.Op == token.NEQ) {
				if (mentionsObject(info, node.X, obj) || mentionsObject(info, node.Y, obj)) && !comparesWithEmpty(node, ident.Name) {
					found = true
				}
			}
		case *ast.CallExpr:
			if _, ok := truthLiteralComparison(info, node); ok {
				return false
			}
			if isPkgFunc(info, node, "strconv", "ParseBool") && len(node.Args) == 1 && mentionsObject(info, node.Args[0], obj) {
				found = true
			}
		}
		return !found
	})
	return found
}

// NewAmbiguousDateLayoutsFirstMatchRule creates
// ambiguous-date-layouts-first-match: a list of date layouts holding a
// day-first and a month-first form with the same separators, tried until
// one parses. 03/04/2026 parses with the first of them, so April 3 or
// March 4 depends on the list's order:
//
//	for _, layout := range []string{"2006-01-02", "02/01/2006", "01/02/2006"} {
//		if t, err := time.Parse(layout, value); err == nil {
func NewAmbiguousDateLayoutsFirstMatchRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"ambiguous-date-layouts-first-match",
			"patterns",
			"Detects date layouts tried first-match-wins that hold both a day-first and a month-first form with one separator — 03/04 is read by whichever comes first",
			core.SeverityHigh,
		),
		suggestion: "Refuse a date that both forms read differently, or accept one unambiguous form (YYYY-MM-DD)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			loop, ok := n.(*ast.RangeStmt)
			if !ok || loop.Value == nil || !parsesDateWithin(scope.info, loop.Body) {
				return true
			}
			list := rangedStringList(scope.info, fn.Body, loop.X)
			if list == nil {
				return true
			}
			if first, second, ok := swappedDayMonth(list); ok {
				findings = append(findings, funcFinding{node: list, message: "The layouts " + first + " and " + second + " both read a date like 03/04 and the first that parses wins — the day and the month swap depending on the list's order"})
			}
			return true
		})
		return findings
	}
	return r
}

// parsesDateWithin reports a body calling time.Parse or ParseInLocation.
func parsesDateWithin(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && (isPkgFunc(info, call, "time", "Parse") || isPkgFunc(info, call, "time", "ParseInLocation")) {
			found = true
		}
		return !found
	})
	return found
}

// rangedStringList returns the []string literal a loop ranges over: written
// in place, or the value of a local variable.
func rangedStringList(info *types.Info, body *ast.BlockStmt, x ast.Expr) *ast.CompositeLit {
	if lit, ok := ast.Unparen(x).(*ast.CompositeLit); ok {
		return lit
	}
	ident, ok := ast.Unparen(x).(*ast.Ident)
	if !ok {
		return nil
	}
	obj := info.ObjectOf(ident)
	if values := valueAssignments(info, body)[obj]; len(values) == 1 {
		lit, _ := ast.Unparen(values[0]).(*ast.CompositeLit)
		return lit
	}
	return nil
}

// swappedDayMonth returns two layouts of the list that differ only by the
// order of day (02) and month (01).
func swappedDayMonth(list *ast.CompositeLit) (string, string, bool) {
	var layouts []string
	for _, elt := range list.Elts {
		if text, ok := stringLiteral(elt); ok {
			layouts = append(layouts, text)
		}
	}
	for i, first := range layouts {
		if !strings.Contains(first, "01") || !strings.Contains(first, "02") {
			continue
		}
		swapped := strings.NewReplacer("01", "02", "02", "01").Replace(first)
		for _, second := range layouts[i+1:] {
			if second == swapped && swapped != first {
				return first, second, true
			}
		}
	}
	return "", "", false
}

// timestampWords name a field that tells when a value was true.
var timestampWords = map[string]bool{"timestamp": true, "time": true, "date": true, "asof": true, "at": true, "updated": true, "fetched": true}

// NewMissingTimestampDefaultedToNowRule creates
// missing-timestamp-defaulted-to-now: the time of a provider's answer,
// missing from the response, replaced with the current time. A stale or
// cached value is then presented as fresh:
//
//	resp, err := h.client.Convert(from, to, amount)
//	...
//	if resp.Timestamp == "" {
//		resp.Timestamp = time.Now().UTC().Format(time.RFC3339)
//	}
func NewMissingTimestampDefaultedToNowRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"missing-timestamp-defaulted-to-now",
			"patterns",
			"Detects the missing time of a provider's answer filled with the current time — an old or cached value is presented as fresh",
			core.SeverityMedium,
		),
		suggestion: "Treat a missing timestamp as an error, or take it from where the value was stored (its fetch time)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		answers := callAnswers(scope.info, fn.Body)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			check, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			field := emptyFieldTested(check.Cond)
			if field == nil || !hasWordFrom(field.Sel.Name, timestampWords) {
				return true
			}
			root, ok := ast.Unparen(field.X).(*ast.Ident)
			if !ok || !answers[scope.info.ObjectOf(root)] {
				return true
			}
			for _, stmt := range check.Body.List {
				assign, ok := stmt.(*ast.AssignStmt)
				if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || !sameSelector(assign.Lhs[0], field) || !fromClock(scope.info, assign.Rhs[0]) {
					continue
				}
				findings = append(findings, funcFinding{node: assign, message: "The answer's missing " + field.Sel.Name + " is filled with the current time — an old or cached value is presented as fresh"})
			}
			return true
		})
		return findings
	}
	return r
}

// callAnswers returns the local variables holding the answer of a call that
// can fail: resp, err := client.Get(...).
func callAnswers(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	answers := make(map[types.Object]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || !returnsError(call, info) {
			return true
		}
		if _, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr); !isSel {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name != "_" {
			answers[info.ObjectOf(ident)] = true
		}
		return true
	})
	return answers
}

// emptyFieldTested returns the field of x.F == "", x.F.IsZero() or
// x.F == nil.
func emptyFieldTested(cond ast.Expr) *ast.SelectorExpr {
	switch c := ast.Unparen(cond).(type) {
	case *ast.BinaryExpr:
		if c.Op != token.EQL {
			return nil
		}
		sel, ok := ast.Unparen(c.X).(*ast.SelectorExpr)
		if !ok {
			return nil
		}
		if text, ok := stringLiteral(c.Y); (ok && text == "") || isNilIdent(c.Y) {
			return sel
		}
	case *ast.CallExpr:
		method, ok := ast.Unparen(c.Fun).(*ast.SelectorExpr)
		if !ok || method.Sel.Name != "IsZero" || len(c.Args) != 0 {
			return nil
		}
		sel, _ := ast.Unparen(method.X).(*ast.SelectorExpr)
		return sel
	}
	return nil
}

// sameSelector reports an expression spelled as the selector x.F.
func sameSelector(expr ast.Expr, sel *ast.SelectorExpr) bool {
	other, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok || other.Sel.Name != sel.Sel.Name {
		return false
	}
	left, lok := ast.Unparen(other.X).(*ast.Ident)
	right, rok := ast.Unparen(sel.X).(*ast.Ident)
	return lok && rok && left.Name == right.Name
}

// poolDefaultFields are pgxpool settings whose library default is not zero:
// a zero copied over them is not "unset".
var poolDefaultFields = map[string]bool{"MaxConnLifetime": true, "MaxConnIdleTime": true, "HealthCheckPeriod": true, "MaxConns": true}

// requiredField is a field of a configuration a constructor needs set: it
// refuses a zero there, or copies it over a library default.
type requiredField struct {
	name   string
	reason string
}

// NewConfigLiteralOmitsRequiredFieldRule creates
// config-literal-omits-required-field: a configuration literal passed to a
// constructor that leaves out a field the constructor refuses when zero or
// copies over a library setting whose default is not zero. That call site
// fails at start, or builds a client with a zero where the library had a
// working default:
//
//	db, err := storage.NewPostgres(config.DBConfig{DSN: dsn, MaxOpenConns: 2})
//
//	func NewPostgres(cfg config.DBConfig) (*Postgres, error) {
//		if cfg.ConnMaxLifetime <= 0 {
//			return nil, fmt.Errorf(...)
//		}
//		poolCfg.MaxConnLifetime = cfg.ConnMaxLifetime
func NewConfigLiteralOmitsRequiredFieldRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"config-literal-omits-required-field",
			"patterns",
			"Detects a configuration literal passed to a constructor without a field the constructor refuses when zero or copies over a non-zero library default — that call site fails at start or runs with a zero setting",
			core.SeverityMedium,
		),
		suggestion: "Set the field in the literal (or build the configuration with the loader every other caller uses)",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		required := make(map[*types.Func]map[int][]requiredField)
		for obj, decl := range decls {
			if fields := constructorRequiredFields(decl); len(fields) > 0 {
				required[obj] = fields
			}
		}
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			if fn.Body == nil || len(required) == 0 {
				return nil
			}
			var findings []funcFinding
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee := staticFunc(scope.info, call)
				if callee == nil {
					return true
				}
				byIndex := required[callee.Origin()]
				for _, index := range slices.Sorted(maps.Keys(byIndex)) {
					fields := byIndex[index]
					if index >= len(call.Args) {
						continue
					}
					lit := configLiteral(call.Args[index])
					if lit == nil {
						continue
					}
					for _, field := range fields {
						if !literalSets(lit, field.name) {
							findings = append(findings, funcFinding{node: lit, message: "The configuration leaves out " + field.name + ", which " + callee.Name() + " " + field.reason})
						}
					}
				}
				return true
			})
			return findings
		}
	}
	return r
}

// configLiteral returns a keyed struct literal passed as T{...} or &T{...}.
func configLiteral(arg ast.Expr) *ast.CompositeLit {
	expr := ast.Unparen(arg)
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = ast.Unparen(unary.X)
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok || len(lit.Elts) == 0 {
		return nil
	}
	if _, keyed := lit.Elts[0].(*ast.KeyValueExpr); !keyed {
		return nil
	}
	return lit
}

// literalSets reports a keyed literal naming the field.
func literalSets(lit *ast.CompositeLit, field string) bool {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok && isIdentNamed(kv.Key, field) {
			return true
		}
	}
	return false
}

// constructorRequiredFields returns, by parameter index, the fields of a
// struct parameter the function refuses when zero or copies over a pool
// setting with a non-zero default.
func constructorRequiredFields(decl typedFuncDecl) map[int][]requiredField {
	fn := decl.decl
	if fn.Body == nil || fn.Type.Params == nil {
		return nil
	}
	params := make(map[types.Object]int)
	index := 0
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if obj := decl.info.ObjectOf(name); obj != nil && isStructParam(obj.Type()) {
				params[obj] = index
			}
			index++
		}
		if len(field.Names) == 0 {
			index++
		}
	}
	if len(params) == 0 {
		return nil
	}
	required := make(map[int][]requiredField)
	add := func(sel *ast.SelectorExpr, reason string) {
		root, ok := ast.Unparen(sel.X).(*ast.Ident)
		if !ok {
			return
		}
		at, ok := params[decl.info.ObjectOf(root)]
		if !ok || slices.ContainsFunc(required[at], func(f requiredField) bool { return f.name == sel.Sel.Name }) {
			return
		}
		required[at] = append(required[at], requiredField{name: sel.Sel.Name, reason: reason})
	}
	for _, stmt := range fn.Body.List {
		switch s := stmt.(type) {
		case *ast.IfStmt:
			if sel := zeroRefused(decl.info, s); sel != nil {
				add(sel, "refuses when it is zero — this call fails at start")
			}
		case *ast.AssignStmt:
			if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
				continue
			}
			target, ok := s.Lhs[0].(*ast.SelectorExpr)
			if !ok || !poolDefaultFields[target.Sel.Name] || !isPoolConfig(decl.info.TypeOf(target.X)) {
				continue
			}
			if sel := convertedSelector(s.Rhs[0]); sel != nil {
				add(sel, "copies over the pool's non-zero default "+target.Sel.Name+" — this call runs with a zero there")
			}
		}
	}
	return required
}

// isStructParam reports a struct type or a pointer to one.
func isStructParam(t types.Type) bool {
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	_, ok := t.Underlying().(*types.Struct)
	_, named := types.Unalias(t).(*types.Named)
	return ok && named
}

// isPoolConfig reports a pgxpool configuration.
func isPoolConfig(t types.Type) bool {
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && strings.HasSuffix(named.Obj().Pkg().Path(), "/pgxpool")
}

// convertedSelector returns x.F of x.F or of a conversion int32(x.F).
func convertedSelector(expr ast.Expr) *ast.SelectorExpr {
	expr = ast.Unparen(expr)
	if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) == 1 {
		expr = ast.Unparen(call.Args[0])
	}
	sel, _ := expr.(*ast.SelectorExpr)
	return sel
}

// zeroRefused returns the field of `if p.F <= 0 { return ..., err }`: a
// zero (or empty) value refused with an error.
func zeroRefused(info *types.Info, check *ast.IfStmt) *ast.SelectorExpr {
	cmp, ok := ast.Unparen(check.Cond).(*ast.BinaryExpr)
	if !ok || len(check.Body.List) == 0 {
		return nil
	}
	ret, ok := check.Body.List[len(check.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) == 0 || isNilIdent(ret.Results[len(ret.Results)-1]) {
		return nil
	}
	if t := info.TypeOf(ret.Results[len(ret.Results)-1]); t == nil || !types.Identical(t, types.Universe.Lookup("error").Type()) {
		return nil
	}
	sel, ok := ast.Unparen(cmp.X).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	lit, ok := ast.Unparen(cmp.Y).(*ast.BasicLit)
	if !ok {
		return nil
	}
	switch {
	case (cmp.Op == token.LEQ || cmp.Op == token.EQL) && lit.Value == "0":
		return sel
	case cmp.Op == token.LSS && lit.Value == "1":
		return sel
	case cmp.Op == token.EQL && lit.Kind == token.STRING && lit.Value == `""`:
		return sel
	}
	return nil
}
