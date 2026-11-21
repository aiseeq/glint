package frontendrules

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// TSConstantKeyReadUncheckedRule finds dictionary lookups by literal string
// keys whose values are dereferenced without establishing that the key exists.
type TSConstantKeyReadUncheckedRule struct{ *rules.BaseRule }

// NewTSConstantKeyReadUncheckedRule creates the rule.
func NewTSConstantKeyReadUncheckedRule() *TSConstantKeyReadUncheckedRule {
	return &TSConstantKeyReadUncheckedRule{BaseRule: rules.NewBaseRule(
		"ts-constant-key-read-unchecked", "patterns",
		"Detects unchecked reads of dictionary entries by constant string key that can become undefined",
		core.SeverityMedium,
	)}
}

var (
	tsConstKeyRead = regexp.MustCompile(`\b((?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Za-z_$][\w$]*)\s*\[\s*(['"])([^'"\n]+)['"]\s*\]`)
	tsAliasRead    = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*((?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Za-z_$][\w$]*)\s*\[\s*(['"])([^'"\n]+)['"]\s*\]`)
	tsTypeAlias    = regexp.MustCompile(`\btype\s+([A-Za-z_$][\w$]*)\s*=\s*Record\s*<\s*string\s*,`)
	tsInterface    = regexp.MustCompile(`\binterface\s+([A-Za-z_$][\w$]*)\s*\{[^}]*\[\s*[A-Za-z_$][\w$]*\s*:\s*string\s*\]`)
	tsJsonDecl     = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*[^;\n]*\b(?:JSON\s*\.\s*parse|\.\s*json\s*\()`)
	tsIfStart      = regexp.MustCompile(`\bif\s*\(`)
	tsFunctionDecl = regexp.MustCompile(`\bfunction\s*\*?\s*[A-Za-z_$][\w$]*\s*\(`)
	tsParamRecord  = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*Record\s*<\s*string\s*,`)
	tsParamIndex   = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*\{\s*\[\s*[A-Za-z_$][\w$]*\s*:\s*string\s*\]`)
	tsParamNamed   = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)`)
	tsObjectDecl   = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\b[^=]*=\s*\{`)
	tsObjectKey    = regexp.MustCompile(`(?:^|[,\n])\s*(?:['"]([A-Za-z_$][\w$]*)['"]|([A-Za-z_$][\w$]*))\s*:`)
	tsTemplateNull = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*null\b`)
	tsTypeBody     = regexp.MustCompile(`(?s)\b(?:interface|type)\s+([A-Za-z_$][\w$]*)\s*(?:=\s*)?\{([^}]*)\}`)
	tsRecordField  = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*Record\s*<\s*string\s*,`)
	tsInlineObject = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*\{([^}]*)\}`)
	tsDestructure  = regexp.MustCompile(`(?:const|let|var)\s+\{[^}]*\}\s*=\s*$`)
)

// AnalyzeFile reports unchecked constant-key reads in production TS/JS. The
// scripts of a Go HTML template come here as a virtual JavaScript file.
func (r *TSConstantKeyReadUncheckedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	if ctx.IsGenerated() {
		return nil
	}
	f := patternkit.NewJSFlat(ctx)
	analyzer := tsConstantReadAnalyzer{
		rule:        r,
		ctx:         ctx,
		file:        f,
		dictTypes:   tsDictionaryTypes(f.Code),
		dictNames:   make(map[[2]int]map[string]bool),
		topLevelEnd: tsTopLevelEnd(f.Code, ctx.VirtualJavaScript),
	}
	return analyzer.analyze()
}

type tsConstantReadAnalyzer struct {
	rule        *TSConstantKeyReadUncheckedRule
	ctx         *core.FileContext
	file        patternkit.JsFlat
	dictTypes   map[string]bool
	dictNames   map[[2]int]map[string]bool
	topLevelEnd int
}

type tsReadScope struct {
	start, end int
	localStart int
	localEnd   int
	body       string
	text       string
	dictCode   string
	cacheKey   [2]int
	inFunction bool
}

func tsTopLevelEnd(code string, templateScript bool) int {
	if templateScript {
		if functions := tsFunctionDecl.FindStringIndex(code); functions != nil {
			return functions[0]
		}
	}
	return len(code)
}

func (a *tsConstantReadAnalyzer) analyze() []*core.Violation {
	var out []*core.Violation
	for _, match := range tsConstKeyRead.FindAllStringSubmatchIndex(a.file.Code, -1) {
		if violation := a.analyzeMatch(match); violation != nil {
			out = append(out, violation...)
		}
	}
	return out
}

func (a *tsConstantReadAnalyzer) analyzeMatch(match []int) []*core.Violation {
	base := strings.Join(strings.Fields(a.file.Code[match[2]:match[3]]), "")
	key := a.file.Text[match[6]:match[7]]
	scope, ok := a.readScope(match)
	if !ok || !a.isDictionary(scope, base) || tsLocalObjectHasKey(scope.body, scope.text, base, key) {
		return nil
	}
	if tsWrittenBefore(scope.text, scope.localStart, base, key) || tsOptionalRead(scope.body, scope.localEnd) {
		return nil
	}
	if tsDerefAfter(a.file.Code, match[1]) {
		return a.analyzeDirectRead(match[0], scope, base, key)
	}
	if tsDestructuredRead(scope.body, scope.localStart) {
		if tsGuardedRead(scope.text, scope.localStart, base, key) || tsDestructuredFallback(scope.body, scope.localEnd) {
			return nil
		}
		return a.report(match[0], "Dictionary key "+key+" may be absent, so destructuring reads an undefined value")
	}
	return a.analyzeAliasRead(scope, base, key)
}

func (a *tsConstantReadAnalyzer) readScope(match []int) (tsReadScope, bool) {
	scope := tsReadScope{start: 0, end: len(a.file.Code), dictCode: a.file.Code, cacheKey: [2]int{0, len(a.file.Code)}}
	fn, inFunction := a.file.EnclosingFunction(match[0])
	if inFunction {
		fnEnd, balanced := a.file.Closing(fn.Brace)
		if !balanced || match[0] < fn.Brace || match[1] > fnEnd {
			return tsReadScope{}, false
		}
		scope.start, scope.end = fn.Brace+1, fnEnd
		scope.dictCode = a.file.Code[fn.Start:fnEnd]
		scope.cacheKey = [2]int{fn.Start, fnEnd}
		scope.inFunction = true
	}
	if a.ctx.VirtualJavaScript && !inFunction {
		scope.end = a.topLevelEnd
		scope.dictCode = a.file.Code[:a.topLevelEnd]
		scope.cacheKey[1] = a.topLevelEnd
	}
	scope.body = a.file.Code[scope.start:scope.end]
	scope.text = a.file.Text[scope.start:scope.end]
	scope.localStart = match[0] - scope.start
	scope.localEnd = match[1] - scope.start
	return scope, true
}

func (a *tsConstantReadAnalyzer) isDictionary(scope tsReadScope, base string) bool {
	names := a.namesForScope(scope.cacheKey, scope.dictCode, a.ctx.VirtualJavaScript && scope.cacheKey[0] == 0)
	root := strings.Split(base, ".")[0]
	if names[root] || names[base] {
		return true
	}
	if a.ctx.VirtualJavaScript && scope.inFunction {
		topKey := [2]int{0, a.topLevelEnd}
		topNames := a.namesForScope(topKey, a.file.Code[:a.topLevelEnd], true)
		return topNames[root] || topNames[base]
	}
	return false
}

func (a *tsConstantReadAnalyzer) namesForScope(key [2]int, code string, templateScript bool) map[string]bool {
	names, ok := a.dictNames[key]
	if !ok {
		names = tsDictionaryNames(code, templateScript, a.dictTypes)
		a.dictNames[key] = names
	}
	return names
}

func (a *tsConstantReadAnalyzer) analyzeDirectRead(pos int, scope tsReadScope, base, key string) []*core.Violation {
	if tsGuardedRead(scope.text, scope.localStart, base, key) {
		return nil
	}
	return a.report(pos, "Dictionary key "+key+" may be absent, so this read is undefined and the property access or call fails")
}

func (a *tsConstantReadAnalyzer) analyzeAliasRead(scope tsReadScope, base, key string) []*core.Violation {
	var out []*core.Violation
	for _, alias := range tsAliasRead.FindAllStringSubmatchIndex(scope.body, -1) {
		if !a.matchAlias(alias, scope, base, key) {
			continue
		}
		if alias[0] > scope.localStart || alias[1] < scope.localEnd {
			continue
		}
		name := scope.body[alias[2]:alias[3]]
		if !tsAliasNeedsGuard(scope.body, scope.text, alias, name) {
			continue
		}
		out = append(out, a.reportAt(scope.start+alias[0], "Dictionary key "+key+" may be absent, leaving "+name+" undefined before it is dereferenced")...)
	}
	return out
}

func (a *tsConstantReadAnalyzer) matchAlias(alias []int, scope tsReadScope, base, key string) bool {
	aliasBase := strings.Join(strings.Fields(scope.body[alias[4]:alias[5]]), "")
	return aliasBase == base && a.file.Text[scope.start+alias[8]:scope.start+alias[9]] == key
}

func tsAliasNeedsGuard(body, text string, alias []int, name string) bool {
	statementEnd := tsStatementEnd(body, alias[1])
	fallback := strings.Contains(body[alias[1]:statementEnd], "||")
	return tsAliasDereferenced(body[alias[1]:], name) && !fallback && !tsAliasGuarded(text, alias[1], name)
}

func (a *tsConstantReadAnalyzer) report(pos int, message string) []*core.Violation {
	return a.reportAt(pos, message)
}

func (a *tsConstantReadAnalyzer) reportAt(pos int, message string) []*core.Violation {
	return patternkit.JsReport(nil, a.rule.BaseRule, a.ctx, a.file.Line(pos), message,
		"Check that the key exists before reading it, or use ?. and handle the missing value explicitly")
}

func tsDictionaryTypes(code string) map[string]bool {
	types := make(map[string]bool)
	for _, match := range tsTypeAlias.FindAllStringSubmatch(code, -1) {
		types[match[1]] = true
	}
	for _, match := range tsInterface.FindAllStringSubmatch(code, -1) {
		types[match[1]] = true
	}
	for _, match := range tsTypeBody.FindAllStringSubmatch(code, -1) {
		for _, field := range tsRecordField.FindAllStringSubmatch(match[2], -1) {
			types[match[1]+"."+field[1]] = true
		}
	}
	for _, field := range tsRecordField.FindAllStringSubmatch(code, -1) {
		types["this."+field[1]] = true
	}
	return types
}

func tsDictionaryNames(code string, templateScript bool, dictTypes map[string]bool) map[string]bool {
	names := make(map[string]bool)
	for _, match := range tsParamRecord.FindAllStringSubmatch(code, -1) {
		names[match[1]] = true
	}
	for _, match := range tsParamIndex.FindAllStringSubmatch(code, -1) {
		names[match[1]] = true
	}
	for _, match := range tsParamNamed.FindAllStringSubmatch(code, -1) {
		if dictTypes[match[2]] {
			names[match[1]] = true
		}
		prefix := match[2] + "."
		for path := range dictTypes {
			if after, ok := strings.CutPrefix(path, prefix); ok {
				names[match[1]+"."+after] = true
			}
		}
	}
	for _, match := range tsInlineObject.FindAllStringSubmatch(code, -1) {
		for _, field := range tsRecordField.FindAllStringSubmatch(match[2], -1) {
			names[match[1]+"."+field[1]] = true
		}
	}
	for path := range dictTypes {
		if strings.HasPrefix(path, "this.") {
			names[path] = true
		}
	}
	for _, match := range tsJsonDecl.FindAllStringSubmatch(code, -1) {
		names[match[1]] = true
	}
	if templateScript {
		for _, match := range tsTemplateNull.FindAllStringSubmatch(code, -1) {
			names[match[1]] = true
		}
	}
	return names
}

func tsLocalObjectHasKey(code, text, name, key string) bool {
	if strings.Contains(name, ".") {
		return false
	}
	var loc []int
	for _, match := range tsObjectDecl.FindAllStringSubmatchIndex(code, -1) {
		if code[match[2]:match[3]] == name {
			loc = match[:2]
			break
		}
	}
	if loc == nil {
		return false
	}
	open := strings.LastIndex(code[loc[0]:loc[1]], "{") + loc[0]
	flat := patternkit.JsFlat{Code: code}
	close, ok := flat.Closing(open)
	if !ok {
		return false
	}
	for _, match := range tsObjectKey.FindAllStringSubmatch(text[open+1:close], -1) {
		if match[1] == key || match[2] == key {
			return true
		}
	}
	return false
}

func tsOptionalRead(code string, end int) bool {
	for end < len(code) && (code[end] == ' ' || code[end] == '\t' || code[end] == '\n') {
		end++
	}
	return end < len(code) && code[end] == '?'
}

func tsDerefAfter(code string, end int) bool {
	for end < len(code) && (code[end] == ' ' || code[end] == '\t' || code[end] == '\n') {
		end++
	}
	return end < len(code) && code[end] == '.' && (end+1 >= len(code) || code[end+1] != '.')
}

func tsWrittenBefore(body string, pos int, base, key string) bool {
	prior := body[:pos]
	for _, quote := range []string{"'", `"`} {
		needle := base + "[" + quote + key + quote + "]"
		for from := 0; from < len(prior); {
			rel := strings.Index(prior[from:], needle)
			if rel < 0 {
				break
			}
			idx := from + rel
			after := strings.TrimSpace(prior[idx+len(needle):])
			if strings.HasPrefix(after, "??=") || (strings.HasPrefix(after, "=") && !strings.HasPrefix(after, "==") && !strings.HasPrefix(after, ">")) {
				return true
			}
			from = idx + len(needle)
		}
	}
	return false
}

func tsDestructuredRead(body string, pos int) bool {
	lineStart := strings.LastIndexAny(body[:pos], ";\n") + 1
	return tsDestructure.MatchString(body[lineStart:pos])
}

func tsDestructuredFallback(body string, end int) bool {
	statementEnd := tsStatementEnd(body, end)
	operator := compactJS(body[end:statementEnd])
	return strings.HasPrefix(operator, "||") || strings.HasPrefix(operator, "??")
}

// tsGuardedRead accepts a guard only when the read is in the branch where the
// key is present, or follows a guard-failure branch that terminates.
func tsGuardedRead(body string, pos int, base, key string) bool {
	for _, start := range tsIfStart.FindAllStringIndex(body[:pos], -1) {
		if tsGuardedByIf(body, pos, base, key, start[0]) {
			return true
		}
	}
	return tsGuardedByShortCircuit(body, pos, base, key)
}

func tsGuardedByIf(body string, pos int, base, key string, ifStart int) bool {
	branches, ok := tsFindIfBranches(body, ifStart)
	if !ok || branches.conditionEnd >= pos {
		return false
	}
	condStart := strings.IndexByte(body[ifStart:], '(') + ifStart + 1
	cond := compactJS(body[condStart:branches.conditionEnd])
	positive, negative := tsGuardPolarity(cond, base, key)
	if pos >= branches.then.start && pos < branches.then.end && positive {
		return true
	}
	if pos >= branches.then.end && (negative || tsHasNegativeOrGuard(cond, base, key)) && tsTerminates(body[branches.then.start:branches.then.end]) {
		return true
	}
	return branches.hasElse && pos >= branches.otherwise.start && pos < branches.otherwise.end && negative
}

func tsHasNegativeOrGuard(cond, base, key string) bool {
	for term := range strings.SplitSeq(cond, "||") {
		_, negative := tsGuardPolarity(term, base, key)
		if negative {
			return true
		}
	}
	return false
}

type tsIfBranch struct{ start, end int }

type tsIfBranchSet struct {
	conditionEnd int
	then         tsIfBranch
	otherwise    tsIfBranch
	hasElse      bool
}

func tsFindIfBranches(body string, ifStart int) (tsIfBranchSet, bool) {
	open := strings.IndexByte(body[ifStart:], '(') + ifStart
	flat := patternkit.JsFlat{Code: body}
	conditionEnd, ok := flat.Closing(open)
	if !ok {
		return tsIfBranchSet{}, false
	}
	thenStart := tsSkipSpace(body, conditionEnd+1)
	thenEnd, ok := tsBranchEnd(body, thenStart, flat)
	if !ok {
		return tsIfBranchSet{}, false
	}
	branches := tsIfBranchSet{conditionEnd: conditionEnd, then: tsIfBranch{start: thenStart, end: thenEnd}}
	elseStart := strings.TrimSpace(body[thenEnd:])
	if !strings.HasPrefix(elseStart, "else") {
		return branches, true
	}
	elseAt := thenEnd + strings.Index(body[thenEnd:], "else") + len("else")
	branches.otherwise.start = tsSkipSpace(body, elseAt)
	branches.otherwise.end, ok = tsBranchEnd(body, branches.otherwise.start, flat)
	branches.hasElse = ok
	return branches, ok
}

func tsSkipSpace(body string, pos int) int {
	for pos < len(body) && (body[pos] == ' ' || body[pos] == '\n' || body[pos] == '\t') {
		pos++
	}
	return pos
}

func tsBranchEnd(body string, start int, flat patternkit.JsFlat) (int, bool) {
	if start < len(body) && body[start] == '{' {
		end, ok := flat.Closing(start)
		return end + 1, ok
	}
	return tsStatementEnd(body, start), true
}

func tsGuardedByShortCircuit(body string, pos int, base, key string) bool {
	// Short-circuit expressions protect their right operand, and || supplies a
	// concrete fallback value for a saved lookup.
	lineStart := strings.LastIndexAny(body[:pos], ";\n{}") + 1
	prefix := compactJS(body[lineStart:pos])
	lookup := compactJS(base) + "['" + key + "']"
	if strings.Contains(prefix, lookup+"&&") || strings.Contains(prefix, lookup+"?") || strings.Contains(prefix, lookup+"||") {
		return true
	}
	baseExpr := compactJS(base)
	if strings.Contains(prefix, "'"+key+"'in"+baseExpr+"&&") || strings.Contains(prefix, `"`+key+`"in`+baseExpr+"&&") ||
		strings.Contains(prefix, lookup+"!==undefined&&") || strings.Contains(prefix, lookup+"!=undefined&&") {
		return true
	}
	if strings.Contains(prefix, "typeof"+lookup) && strings.Contains(prefix, "&&") {
		return true
	}
	return false
}

func compactJS(s string) string { return strings.Join(strings.Fields(s), "") }

func tsGuardPolarity(cond, base, key string) (bool, bool) {
	b := compactJS(base)
	forms := []string{b + "['" + key + "']", b + `["` + key + `"]`}
	for _, lookup := range forms {
		if positive, negative, ok := tsLookupGuardPolarity(cond, lookup); ok {
			return positive, negative
		}
	}
	if positive, negative, ok := tsKeyInGuardPolarity(cond, b, key); ok {
		return positive, negative
	}
	return tsOwnGuardPolarity(cond, b, key)
}

func tsLookupGuardPolarity(cond, lookup string) (bool, bool, bool) {
	if cond == lookup {
		return true, false, true
	}
	if strings.HasPrefix(cond, "!") && cond[1:] == lookup {
		return false, true, true
	}
	if strings.HasPrefix(cond, "!(") && strings.HasSuffix(cond, ")") && cond[2:len(cond)-1] == lookup {
		return false, true, true
	}
	if cond == lookup+"!==undefined" || cond == lookup+"!=undefined" || cond == lookup+"!==null" || cond == lookup+"!=null" {
		return true, false, true
	}
	if cond == lookup+"===undefined" || cond == lookup+"==undefined" || cond == lookup+"===null" || cond == lookup+"==null" {
		return false, true, true
	}
	if cond == "typeof"+lookup+"===\"undefined\"" || cond == "typeof"+lookup+"==='undefined'" ||
		cond == "typeof"+lookup+"==\"undefined\"" || cond == "typeof"+lookup+"=='undefined'" {
		return false, true, true
	}
	return false, false, false
}

func tsKeyInGuardPolarity(cond, base, key string) (bool, bool, bool) {
	keyIn := "'" + key + "'in" + base
	if cond == keyIn || cond == `"`+key+`"in`+base {
		return true, false, true
	}
	if strings.HasPrefix(cond, "!(") && strings.HasSuffix(cond, ")") {
		inner := cond[2 : len(cond)-1]
		if inner == keyIn || inner == `"`+key+`"in`+base {
			return false, true, true
		}
	}
	return false, false, false
}

func tsOwnGuardPolarity(cond, base, key string) (bool, bool) {
	objectHas := "Object.hasOwn(" + base + ",'" + key + "')"
	keysHas := "Object.keys(" + base + ").includes('" + key + "')"
	legacyHas := base + ".hasOwnProperty('" + key + "')"
	if cond == objectHas || cond == keysHas || cond == legacyHas {
		return true, false
	}
	if strings.HasPrefix(cond, "!") && (cond[1:] == objectHas || cond[1:] == keysHas || cond[1:] == legacyHas) {
		return false, true
	}
	return false, false
}

func tsStatementEnd(body string, start int) int {
	for i := start; i < len(body); i++ {
		if body[i] == ';' || body[i] == '\n' {
			return i + 1
		}
		if body[i] == '{' || body[i] == '}' {
			return i
		}
	}
	return len(body)
}

func tsTerminates(stmt string) bool {
	trimmed := strings.TrimSpace(stmt)
	trimmed = strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(trimmed, "}"), "{"))
	trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, ";"))
	if end := strings.LastIndexAny(trimmed, ";\n"); end >= 0 {
		trimmed = strings.TrimSpace(trimmed[end+1:])
	}
	return strings.HasPrefix(trimmed, "return") || strings.HasPrefix(trimmed, "throw")
}

func tsAliasDereferenced(after, name string) bool {
	_, ok := tsAliasDerefIndex(after, name)
	return ok
}

func tsAliasDerefIndex(after, name string) (int, bool) {
	for from := 0; from < len(after); {
		rel := strings.Index(after[from:], name)
		if rel < 0 {
			return 0, false
		}
		pos := from + rel
		end := pos + len(name)
		beforeOK := pos == 0 || (!isJSIdent(after[pos-1]) && after[pos-1] != '.')
		afterOK := end == len(after) || !isJSIdent(after[end])
		i := end
		for i < len(after) && (after[i] == ' ' || after[i] == '\t' || after[i] == '\n') {
			i++
		}
		if beforeOK && afterOK && i < len(after) && after[i] == '.' && (i+1 == len(after) || after[i+1] != '.') {
			return pos, true
		}
		from = end
	}
	return 0, false
}

func isJSIdent(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func tsAliasGuarded(body string, declEnd int, name string) bool {
	deref, found := tsAliasDerefIndex(body[declEnd:], name)
	if !found {
		return false
	}
	prior := body[declEnd : declEnd+deref]
	readPos := declEnd + deref
	for _, start := range tsIfStart.FindAllStringIndex(body[:readPos], -1) {
		open := strings.IndexByte(body[start[0]:], '(') + start[0]
		flat := patternkit.JsFlat{Code: body}
		close, ok := flat.Closing(open)
		if !ok || close >= readPos {
			continue
		}
		cond := compactJS(body[open+1 : close])
		thenStart := close + 1
		for thenStart < len(body) && (body[thenStart] == ' ' || body[thenStart] == '\n' || body[thenStart] == '\t') {
			thenStart++
		}
		thenEnd := tsStatementEnd(body, thenStart)
		if thenStart < len(body) && body[thenStart] == '{' {
			thenEnd, ok = flat.Closing(thenStart)
			if !ok {
				continue
			}
			thenEnd++
		}
		if cond == name && readPos >= thenStart && readPos < thenEnd {
			return true
		}
		if (cond == "!"+name || cond == name+"===undefined" || cond == name+"==null") && readPos >= thenEnd && tsTerminates(body[thenStart:thenEnd]) {
			return true
		}
	}
	p := compactJS(prior)
	return strings.Contains(p, name+"&&") || strings.Contains(p, name+"?") || strings.Contains(p, name+"||") || strings.Contains(p, "!"+name)
}
