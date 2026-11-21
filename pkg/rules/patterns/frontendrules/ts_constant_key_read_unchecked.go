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
	tsConstKeyRead         = regexp.MustCompile("\\b((?:[A-Za-z_$][\\w$]*\\s*(?:\\?\\.)?\\s*\\.\\s*)*[A-Za-z_$][\\w$]*(?:\\?\\.)?)\\s*\\[\\s*(['\"`])([^'\"`\\n]+)['\"`]\\s*\\]")
	tsAliasRead            = regexp.MustCompile("\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*((?:[A-Za-z_$][\\w$]*\\s*(?:\\?\\.)?\\s*\\.\\s*)*[A-Za-z_$][\\w$]*(?:\\?\\.)?)\\s*\\[\\s*(['\"`])([^'\"`\\n]+)['\"`]\\s*\\]")
	tsTypeAlias            = regexp.MustCompile(`\btype\s+([A-Za-z_$][\w$]*)\s*=\s*(?:Readonly\s*<\s*)?(?:Record\s*<\s*string\s*,|\{\s*\[\s*[A-Za-z_$][\w$]*\s*:\s*string\s*\])`)
	tsInterface            = regexp.MustCompile(`\binterface\s+([A-Za-z_$][\w$]*)\s*\{[^}]*\[\s*[A-Za-z_$][\w$]*\s*:\s*string\s*\]`)
	tsJsonDecl             = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*[^;\n]*\b(?:JSON\s*\.\s*parse|\.\s*json\s*\()`)
	tsIfStart              = regexp.MustCompile(`\bif\s*\(`)
	tsWhileStart           = regexp.MustCompile(`\bwhile\s*\(`)
	tsClassStart           = regexp.MustCompile(`\bclass\s+[A-Za-z_$][\w$]*[^\{]*\{`)
	tsTypeAliasStart       = regexp.MustCompile(`\btype\s+[A-Za-z_$][\w$]*\s*=\s*$`)
	tsFunctionDecl         = regexp.MustCompile(`\bfunction\s*\*?\s*[A-Za-z_$][\w$]*\s*\(`)
	tsParamRecord          = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\??\s*:\s*(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,`)
	tsParamIndex           = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\??\s*:\s*\{\s*\[\s*[A-Za-z_$][\w$]*\s*:\s*string\s*\]`)
	tsParamNamed           = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\??\s*:\s*([A-Za-z_$][\w$]*)`)
	tsObjectDecl           = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\b[^=;\n]*=\s*\{`)
	tsClassFieldObjectDecl = regexp.MustCompile(`\b(?:public\s+|private\s+|protected\s+|readonly\s+)*([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=\s*\{`)
	tsObjectKey            = regexp.MustCompile(`(?:^|[,\n])\s*(?:['"]([^'"\n]+)['"]|([A-Za-z_$][\w$]*))\s*:`)
	tsIndexedInGuard       = regexp.MustCompile(`['"]([^'"\n]+)['"]\s+in\s+([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)`)
	tsIndexedLookupGuard   = regexp.MustCompile(`([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\[\s*['"]([^'"\n]+)['"]\s*\]`)
	tsTemplateNull         = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*null\b`)
	tsTypeBody             = regexp.MustCompile(`(?s)\b(?:interface|type)\s+([A-Za-z_$][\w$]*)\s*(?:=\s*)?\{([^}]*)\}`)
	tsRecordField          = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,`)
	tsInlineObject         = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*\{([^}]*)\}`)
	tsDestructure          = regexp.MustCompile(`(?:const|let|var)\s+\{[^}]*\}\s*=\s*$`)
	tsTypedDictDecl        = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,|:\s*([A-Za-z_$][\w$]*))\s*=`)
	tsDestructureAlias     = regexp.MustCompile(`(?:const|let|var)\s+\{[^}]*\}\s*=\s*([A-Za-z_$][\w$]*)\b`)
	tsAssertRecord         = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*\bas\s+(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,`)
	tsUseStateRecord       = regexp.MustCompile(`\b(?:const|let|var)\s*\[\s*([A-Za-z_$][\w$]*)\s*(?:,[^\]]*)?\]\s*=\s*useState\s*<\s*(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,`)
	tsDestructuredParam    = regexp.MustCompile(`\{\s*([A-Za-z_$][\w$]*)\s*\}\s*:\s*([A-Za-z_$][\w$]*)`)
	tsAnnotatedDecl        = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)\s*=`)
	tsFunctionRecordReturn = regexp.MustCompile(`(?:\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\))\s*:\s*(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,`)
	tsCallDecl             = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\(`)
	tsQuoteNormalizer      = strings.NewReplacer("\"", "'", "`", "'")
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
	reads := tsConstKeyRead.FindAllStringSubmatchIndex(f.Code, -1)
	if len(reads) == 0 {
		return nil
	}
	globalCode := f.Code
	if !ctx.VirtualJavaScript {
		if first := tsFunctionDecl.FindStringIndex(f.Code); first != nil {
			globalCode = f.Code[:first[0]]
		}
	}
	dictTypes := tsDictionaryTypes(f.Code)
	globalNames := tsDictionaryNames(globalCode, ctx.VirtualJavaScript, dictTypes)
	tsAddCallReturnNames(f.Code, globalNames)
	analyzer := tsConstantReadAnalyzer{
		rule:         r,
		ctx:          ctx,
		file:         f,
		globalCode:   globalCode,
		dictTypes:    dictTypes,
		globalNames:  globalNames,
		dictNames:    make(map[[2]int]map[string]bool),
		objectKeys:   make(map[[2]int]map[string]map[string]bool),
		guardIndexes: make(map[[2]int]*tsGuardIndex),
		aliasReads:   make(map[[2]int][][]int),
		reads:        reads,
	}
	return analyzer.analyze()
}

type tsConstantReadAnalyzer struct {
	rule         *TSConstantKeyReadUncheckedRule
	ctx          *core.FileContext
	file         patternkit.JsFlat
	globalCode   string
	dictTypes    map[string]bool
	globalNames  map[string]bool
	dictNames    map[[2]int]map[string]bool
	objectKeys   map[[2]int]map[string]map[string]bool
	guardIndexes map[[2]int]*tsGuardIndex
	aliasReads   map[[2]int][][]int
	reads        [][]int
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

func (a *tsConstantReadAnalyzer) analyze() []*core.Violation {
	var out []*core.Violation
	for _, match := range a.reads {
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
	if ok && tsTypeIndexedAccess(scope.body, scope.localStart) {
		return nil
	}
	globalCode, globalText := a.globalCode, a.file.Text[:len(a.globalCode)]
	globalKey := [2]int{0, len(globalCode)}
	if strings.HasPrefix(base, "this.") {
		globalCode, globalText = a.file.Code, a.file.Text
		globalKey = [2]int{0, len(a.file.Code)}
	}
	if !ok || !a.isDictionary(scope, base) || a.localObjectHasKey(scope.cacheKey, scope.body, scope.text, base, key) ||
		a.localObjectHasKey(globalKey, globalCode, globalText, base, key) {
		return nil
	}
	if tsWrittenBefore(scope.text, scope.localStart, base, key) || tsOptionalRead(scope.body, scope.localEnd) {
		return nil
	}
	if tsDerefAfter(a.file.Code, match[1]) {
		return a.analyzeDirectRead(match[0], scope, base, key)
	}
	if tsDestructuredRead(scope.body, scope.localStart) {
		if a.guarded(scope, scope.localStart, base, key) || tsOuterGuardedRead(a.file, match[0], base, key) || tsDestructuredFallback(scope.body, scope.localEnd) {
			return nil
		}
		return a.report(match[0], "Dictionary key "+key+" may be absent, so destructuring reads an undefined value")
	}
	return a.analyzeAliasRead(scope, base, key)
}

func (a *tsConstantReadAnalyzer) guarded(scope tsReadScope, pos int, base, key string) bool {
	index := a.guardIndexes[scope.cacheKey]
	if index == nil {
		index = newTSGuardIndex(scope.text)
		a.guardIndexes[scope.cacheKey] = index
	}
	return index.guarded(pos, base, key)
}

func (a *tsConstantReadAnalyzer) localObjectHasKey(cacheKey [2]int, code, text, name, key string) bool {
	objects, ok := a.objectKeys[cacheKey]
	if !ok {
		objects = tsObjectLiteralKeys(code, text)
		a.objectKeys[cacheKey] = objects
	}
	return objects[name][key]
}

func tsTypeIndexedAccess(body string, pos int) bool {
	start := strings.LastIndexAny(body[:pos], ";\n") + 1
	return tsTypeAliasStart.MatchString(body[start:pos])
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
		// Names come from the declarations before the first function; the
		// read itself may stand anywhere at the top level.
		scope.dictCode = a.file.Code
		scope.cacheKey[1] = len(a.file.Code)
	}
	scope.body = a.file.Code[scope.start:scope.end]
	scope.text = a.file.Text[scope.start:scope.end]
	scope.localStart = match[0] - scope.start
	scope.localEnd = match[1] - scope.start
	return scope, true
}

func (a *tsConstantReadAnalyzer) isDictionary(scope tsReadScope, base string) bool {
	names := a.namesForScope(scope.cacheKey, scope.dictCode, a.ctx.VirtualJavaScript && scope.cacheKey[0] == 0)
	canonical := strings.ReplaceAll(base, "?.", ".")
	root := strings.Split(canonical, ".")[0]
	if strings.HasPrefix(canonical, "this.") && tsClassHasRecordField(a.file.Code, scope.start, strings.TrimPrefix(canonical, "this."), a.dictTypes) {
		return true
	}
	if names[root] || names[canonical] {
		return true
	}
	if a.globalNames[root] || a.globalNames[canonical] {
		return true
	}
	if a.ctx.VirtualJavaScript && scope.inFunction {
		topKey := [2]int{0, len(a.file.Code)}
		topNames := a.namesForScope(topKey, a.file.Code, true)
		if topNames[root] || topNames[canonical] {
			return true
		}
	}
	if scope.inFunction {
		for pos := scope.start - 1; pos >= 0; {
			fn, ok := a.file.EnclosingFunction(pos)
			if !ok {
				break
			}
			end, balanced := a.file.Closing(fn.Brace)
			if balanced && fn.Start <= scope.start && scope.start <= end {
				outer := a.namesForScope([2]int{fn.Start, end}, a.file.Code[fn.Start:end], false)
				if outer[root] || outer[canonical] {
					return true
				}
			}
			if fn.Start == 0 {
				break
			}
			pos = fn.Start - 1
		}
	}
	return false
}

func tsClassHasRecordField(code string, pos int, field string, dictTypes map[string]bool) bool {
	var class []int
	for _, match := range tsClassStart.FindAllStringIndex(code[:pos], -1) {
		class = match
	}
	if class == nil {
		return false
	}
	open := strings.LastIndexByte(code[class[0]:class[1]], '{') + class[0]
	flat := patternkit.JsFlat{Code: code}
	close, ok := flat.Closing(open)
	if !ok || pos > close {
		return false
	}
	for _, match := range tsRecordField.FindAllStringSubmatch(code[open+1:close], -1) {
		if match[1] == field {
			return true
		}
	}
	for _, match := range tsParamNamed.FindAllStringSubmatch(code[open+1:close], -1) {
		if match[1] == field && dictTypes[match[2]] {
			return true
		}
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
	if a.guarded(scope, scope.localStart, base, key) || tsOuterGuardedRead(a.file, scope.start+scope.localStart, base, key) {
		return nil
	}
	return a.report(pos, "Dictionary key "+key+" may be absent, so this read is undefined and the property access or call fails")
}

func (a *tsConstantReadAnalyzer) analyzeAliasRead(scope tsReadScope, base, key string) []*core.Violation {
	var out []*core.Violation
	aliases, ok := a.aliasReads[scope.cacheKey]
	if !ok {
		aliases = tsAliasRead.FindAllStringSubmatchIndex(scope.body, -1)
		a.aliasReads[scope.cacheKey] = aliases
	}
	for _, alias := range aliases {
		if !a.matchAlias(alias, scope, base, key) {
			continue
		}
		if alias[0] > scope.localStart || alias[1] < scope.localEnd {
			continue
		}
		name := scope.body[alias[2]:alias[3]]
		if !tsAliasNeedsGuard(scope.body, scope.text, alias, name, base, key) || tsOuterGuardedRead(a.file, scope.start+alias[0], base, key) {
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

func tsAliasNeedsGuard(body, text string, alias []int, name, base, key string) bool {
	statementEnd := tsStatementEnd(body, alias[1])
	fallback := strings.Contains(body[alias[1]:statementEnd], "||")
	destructured := false
	for _, m := range tsDestructureAlias.FindAllStringSubmatch(body[alias[1]:], -1) {
		if m[1] == name {
			destructured = true
			break
		}
	}
	return (tsAliasDereferenced(body[alias[1]:], name) || destructured) && !fallback &&
		!tsAliasGuarded(text, alias[1], name) && !tsGuardedRead(text, alias[0], base, key)
}

func tsOuterGuardedRead(file patternkit.JsFlat, pos int, base, key string) bool {
	fn, ok := file.EnclosingFunction(pos)
	for ok {
		parent, parentOK := file.EnclosingFunction(fn.Start)
		if !parentOK || parent.Brace == fn.Brace {
			return false
		}
		end, balanced := file.Closing(parent.Brace)
		if !balanced {
			return false
		}
		bodyStart := parent.Brace + 1
		if tsGuardedRead(file.Text[bodyStart:end], pos-bodyStart, base, key) {
			return true
		}
		fn, ok = parent, true
	}
	return false
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
	for _, match := range tsTypedDictDecl.FindAllStringSubmatch(code, -1) {
		if match[2] == "" || dictTypes[match[2]] {
			names[match[1]] = true
		}
	}
	for _, match := range tsParamIndex.FindAllStringSubmatch(code, -1) {
		names[match[1]] = true
	}
	for _, match := range tsParamNamed.FindAllStringSubmatch(code, -1) {
		if dictTypes[match[2]] {
			names[match[1]] = true
			names["this."+match[1]] = true
		}
		prefix := match[2] + "."
		for path := range dictTypes {
			if after, ok := strings.CutPrefix(path, prefix); ok {
				names[match[1]+"."+after] = true
			}
		}
	}
	for _, match := range tsDestructuredParam.FindAllStringSubmatch(code, -1) {
		field := match[2] + "." + match[1]
		if dictTypes[match[2]] || dictTypes[field] {
			names[match[1]] = true
		}
		for path := range dictTypes {
			if strings.HasPrefix(path, field+".") {
				names[match[1]] = true
			}
		}
	}
	for _, match := range tsInlineObject.FindAllStringSubmatch(code, -1) {
		for _, field := range tsRecordField.FindAllStringSubmatch(match[2], -1) {
			names[match[1]+"."+field[1]] = true
		}
	}
	tsAddJSONNames(code, dictTypes, names)
	for _, match := range tsAssertRecord.FindAllStringSubmatch(code, -1) {
		names[match[1]] = true
	}
	for _, match := range tsUseStateRecord.FindAllStringSubmatch(code, -1) {
		names[match[1]] = true
	}
	tsAddCallReturnNames(code, names)
	if templateScript {
		for _, match := range tsTemplateNull.FindAllStringSubmatch(code, -1) {
			names[match[1]] = true
		}
	}
	return names
}

func tsAddJSONNames(code string, dictTypes, names map[string]bool) {
	annotated := make(map[string]string)
	for _, match := range tsAnnotatedDecl.FindAllStringSubmatch(code, -1) {
		annotated[match[1]] = match[2]
	}
	for _, match := range tsJsonDecl.FindAllStringSubmatch(code, -1) {
		if typeName, ok := annotated[match[1]]; !ok || dictTypes[typeName] {
			names[match[1]] = true
		}
	}
}

func tsAddCallReturnNames(code string, names map[string]bool) {
	returns := make(map[string]bool)
	for _, match := range tsFunctionRecordReturn.FindAllStringSubmatch(code, -1) {
		name := match[1]
		if name == "" {
			name = match[2]
		}
		if name != "" {
			returns[name] = true
		}
	}
	for _, match := range tsCallDecl.FindAllStringSubmatch(code, -1) {
		if returns[match[2]] {
			names[match[1]] = true
		}
	}
}

func tsObjectLiteralKeys(code, text string) map[string]map[string]bool {
	objects := make(map[string]map[string]bool)
	flat := patternkit.JsFlat{Code: code}
	add := func(name string, match []int) {
		open := strings.LastIndex(code[match[0]:match[1]], "{") + match[0]
		close, ok := flat.Closing(open)
		if !ok {
			return
		}
		keys := make(map[string]bool)
		for _, keyMatch := range tsObjectKey.FindAllStringSubmatch(text[open+1:close], -1) {
			key := keyMatch[1]
			if key == "" {
				key = keyMatch[2]
			}
			keys[key] = true
		}
		objects[name] = keys
	}
	for _, match := range tsObjectDecl.FindAllStringSubmatchIndex(code, -1) {
		add(code[match[2]:match[3]], match[:2])
	}
	for _, match := range tsClassFieldObjectDecl.FindAllStringSubmatchIndex(code, -1) {
		add("this."+code[match[2]:match[3]], match[:2])
	}
	return objects
}

func tsOptionalRead(code string, end int) bool {
	for end < len(code) && (code[end] == ' ' || code[end] == '\t' || code[end] == '\n') {
		end++
	}
	return end < len(code) && code[end] == '?'
}

func tsDerefAfter(code string, end int) bool {
	end = tsSkipJSWhitespace(code, end)
	if end < len(code) && code[end] == '!' {
		end++
	}
	end = tsSkipTypeAssertion(code, tsSkipJSWhitespace(code, end))
	end = tsSkipBracketPostfix(code, end)
	end = tsSkipJSWhitespace(code, end)
	return end < len(code) && code[end] == '.' && (end+1 >= len(code) || code[end+1] != '.')
}

func tsSkipJSWhitespace(code string, pos int) int {
	for pos < len(code) && (code[pos] == ' ' || code[pos] == '\t' || code[pos] == '\n') {
		pos++
	}
	return pos
}

func tsSkipTypeAssertion(code string, pos int) int {
	if pos+2 > len(code) || code[pos:pos+2] != "as" || (pos+2 < len(code) && isJSIdent(code[pos+2])) {
		return pos
	}
	for pos < len(code) && code[pos] != ')' && code[pos] != '\n' {
		pos++
	}
	if pos < len(code) && code[pos] == ')' {
		pos++
	}
	return pos
}

func tsSkipBracketPostfix(code string, pos int) int {
	if pos >= len(code) || code[pos] != '[' {
		return pos
	}
	flat := patternkit.JsFlat{Code: code}
	if close, ok := flat.Closing(pos); ok {
		return close + 1
	}
	return pos
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
			if strings.HasPrefix(after, "??=") || strings.HasPrefix(after, "||=") || (strings.HasPrefix(after, "=") && !strings.HasPrefix(after, "==") && !strings.HasPrefix(after, ">")) {
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
	return newTSGuardIndex(body).guarded(pos, base, key)
}

type tsGuardBranch struct {
	start    int
	branches tsIfBranchSet
}

type tsGuardIndex struct {
	body    string
	flat    patternkit.JsFlat
	ifs     []tsGuardBranch
	byGuard map[string][]tsIndexedGuardBranch
	whiles  []int
}

type tsIndexedGuardBranch struct {
	branch             tsGuardBranch
	condition          string
	positive, negative bool
}

func newTSGuardIndex(body string) *tsGuardIndex {
	index := &tsGuardIndex{body: body, flat: patternkit.JsFlat{Code: body}, byGuard: make(map[string][]tsIndexedGuardBranch)}
	for _, start := range tsIfStart.FindAllStringIndex(body, -1) {
		branches, ok := tsFindIfBranches(body, start[0])
		if !ok {
			continue
		}
		item := tsGuardBranch{start: start[0], branches: branches}
		condStart := strings.IndexByte(body[start[0]:], '(') + start[0] + 1
		condition := body[condStart:branches.conditionEnd]
		matches := tsIndexedInGuard.FindAllStringSubmatch(condition, -1)
		lookups := tsIndexedLookupGuard.FindAllStringSubmatch(condition, -1)
		if len(matches) == 0 && len(lookups) == 0 {
			index.ifs = append(index.ifs, item)
			continue
		}
		for _, match := range matches {
			base := strings.Join(strings.Fields(match[2]), "")
			positive, negative := tsConditionGuard(condition, base, match[1])
			candidate := tsIndexedGuardBranch{branch: item, condition: compactJS(condition), positive: positive, negative: negative}
			index.byGuard[base+"\x00"+match[1]] = append(index.byGuard[base+"\x00"+match[1]], candidate)
		}
		for _, match := range lookups {
			base := strings.Join(strings.Fields(match[1]), "")
			positive, negative := tsConditionGuard(condition, base, match[2])
			candidate := tsIndexedGuardBranch{branch: item, condition: compactJS(condition), positive: positive, negative: negative}
			index.byGuard[base+"\x00"+match[2]] = append(index.byGuard[base+"\x00"+match[2]], candidate)
		}
	}
	for _, loop := range tsWhileStart.FindAllStringIndex(body, -1) {
		index.whiles = append(index.whiles, loop[0])
	}
	return index
}

func (index *tsGuardIndex) guarded(pos int, base, key string) bool {
	body := index.body
	for _, item := range index.byGuard[base+"\x00"+key] {
		if item.branch.start >= pos {
			break
		}
		if tsGuardedByBranchPolarity(body, pos, item.branch.branches, item.condition, item.positive, item.negative) {
			return true
		}
	}
	for _, item := range index.ifs {
		if item.start >= pos {
			break
		}
		if tsGuardedByBranches(body, pos, base, key, item.start, item.branches) {
			return true
		}
	}
	for _, loop := range index.whiles {
		if loop >= pos {
			break
		}
		open := strings.IndexByte(body[loop:], '(') + loop
		close, ok := index.flat.Closing(open)
		if !ok || close >= pos {
			continue
		}
		_, negative := tsConditionGuard(body[open+1:close], base, key)
		if !negative {
			continue
		}
		stmtStart := tsSkipSpace(body, close+1)
		stmtEnd, valid := tsBranchEnd(body, stmtStart, index.flat)
		if valid && stmtEnd <= pos {
			return true
		}
	}
	prior := compactJS(body[:pos])
	assertion := "assert('" + key + "'in" + compactJS(base)
	condition := assertion[len("assert("):]
	if strings.Contains(prior, assertion) || strings.Contains(prior, "assert("+compactJS(base)+"['"+key+"']") ||
		strings.Contains(prior, "invariant("+condition) || strings.Contains(prior, "tinyinvariant("+condition) {
		return true
	}
	return tsGuardedByTernary(body, pos, base, key) || tsGuardedByShortCircuit(body, pos, base, key)
}

func tsGuardedByBranches(body string, pos int, base, key string, ifStart int, branches tsIfBranchSet) bool {
	if branches.conditionEnd >= pos {
		return false
	}
	condStart := strings.IndexByte(body[ifStart:], '(') + ifStart + 1
	cond := compactJS(body[condStart:branches.conditionEnd])
	positive, negative := tsConditionGuard(cond, base, key)
	return tsGuardedByBranchPolarity(body, pos, branches, cond, positive, negative)
}

func tsGuardedByBranchPolarity(body string, pos int, branches tsIfBranchSet, cond string, positive, negative bool) bool {
	if branches.conditionEnd >= pos {
		return false
	}
	if pos >= branches.then.start && pos < branches.then.end && positive {
		return true
	}
	if pos >= branches.then.end && negative && tsTerminates(body[branches.then.start:branches.then.end]) {
		return true
	}
	if branches.hasElse && pos >= branches.otherwise.start && pos < branches.otherwise.end && negative {
		return true
	}
	if branches.hasElse && pos >= branches.otherwise.end && positive && tsTerminates(body[branches.otherwise.start:branches.otherwise.end]) {
		return true
	}
	// An assertion function establishes the condition for the rest of its scope.
	if pos >= branches.then.end && positive && tsAssertionCondition(body[branches.then.start:branches.then.end], cond) {
		return true
	}
	return false
}

func tsConditionGuard(cond, base, key string) (bool, bool) {
	cond = tsStripConditionParens(tsNormalizeQuotes(compactJS(cond)))
	if arrow := strings.LastIndex(cond, "=>"); arrow >= 0 {
		cond = cond[arrow+2:]
	}
	if ret := strings.LastIndex(cond, "return"); ret >= 0 {
		cond = cond[ret+len("return"):]
	}
	if jsx := strings.LastIndex(cond, "{"); jsx >= 0 {
		cond = cond[jsx+1:]
	}
	positive, negative := tsGuardPolarity(cond, base, key)
	if positive || negative {
		return positive, negative
	}
	for term := range strings.SplitSeq(cond, "&&") {
		term = tsStripConditionParens(term)
		if p, _ := tsGuardPolarity(term, base, key); p {
			return true, false
		}
	}
	for term := range strings.SplitSeq(cond, "||") {
		term = tsStripConditionParens(term)
		if _, n := tsGuardPolarity(term, base, key); n {
			return false, true
		}
	}
	return false, false
}

func tsStripConditionParens(cond string) string {
	cond = strings.TrimSpace(cond)
	for len(cond) >= 2 && cond[0] == '(' && cond[len(cond)-1] == ')' {
		cond = cond[1 : len(cond)-1]
		cond = strings.TrimSpace(cond)
	}
	return cond
}

func tsNormalizeQuotes(s string) string {
	return tsQuoteNormalizer.Replace(s)
}

func tsAssertionCondition(stmt, cond string) bool {
	s := tsNormalizeQuotes(compactJS(stmt))
	c := tsNormalizeQuotes(cond)
	return strings.Contains(s, "assert("+c+")") || strings.Contains(s, "invariant("+c+")")
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
	lineStart := strings.LastIndexAny(body[:pos], ";\n") + 1
	for lineStart > 0 {
		prevLine := strings.TrimSpace(body[:lineStart-1])
		currentPrefix := strings.TrimSpace(body[lineStart:pos])
		if !strings.HasSuffix(prevLine, "&&") && !strings.HasPrefix(currentPrefix, "?") && !strings.HasPrefix(currentPrefix, ":") {
			break
		}
		lineStart = strings.LastIndexByte(body[:lineStart-1], '\n') + 1
	}
	prefix := compactJS(body[lineStart:pos])
	lookup := compactJS(base) + "['" + key + "']"
	quoteLookup := strings.ReplaceAll(lookup, "'", `"`)
	if strings.Contains(prefix, lookup+"&&") || strings.Contains(prefix, quoteLookup+"&&") ||
		strings.Contains(prefix, lookup+"||") || strings.Contains(prefix, quoteLookup+"||") {
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
	if and := strings.LastIndex(prefix, "&&"); and >= 0 {
		left := prefix[:and]
		if at := strings.LastIndex(left, "if("); at >= 0 {
			left = left[at+3:]
		}
		if positive, _ := tsConditionGuard(left, base, key); positive {
			return true
		}
	}
	if or := strings.LastIndex(prefix, "||"); or >= 0 {
		left := prefix[:or]
		if at := strings.LastIndex(left, "if("); at >= 0 {
			left = left[at+3:]
		}
		if _, negative := tsConditionGuard(left, base, key); negative {
			return true
		}
	}
	// The right hand side of a true ternary arm is protected by its condition.
	if q := strings.LastIndex(prefix, "?"); q >= 0 {
		if strings.Contains(prefix[q+1:], ":") {
			return false
		}
		cond := strings.TrimRight(prefix[:q], "( ")
		if at := strings.LastIndex(cond, "return"); at >= 0 {
			cond = cond[at+len("return"):]
		}
		if at := strings.LastIndex(cond, "typeof"); at >= 0 {
			cond = cond[at:]
		}
		cond = strings.TrimLeft(cond, "{(<")
		if positive, _ := tsConditionGuard(cond, base, key); positive {
			return true
		}
	}
	return false
}

func tsGuardedByTernary(body string, pos int, base, key string) bool {
	q := strings.LastIndexByte(body[:pos], '?')
	if q < 0 {
		return false
	}
	colonRel := strings.IndexByte(body[q+1:], ':')
	if colonRel < 0 {
		return false
	}
	colon := q + 1 + colonRel
	condStart := strings.LastIndexAny(body[:q], "=;,\n") + 1
	if condStart < q && body[condStart] == '>' {
		condStart++ // the preceding '=' belongs to an arrow's '=>'
	}
	cond := strings.TrimSpace(body[condStart:q])
	if strings.HasPrefix(cond, "(") && !strings.HasSuffix(cond, ")") {
		cond = strings.TrimSpace(cond[1:])
	}
	positive, negative := tsConditionGuard(cond, base, key)
	if pos < colon {
		return positive
	}
	return negative
}

func compactJS(s string) string { return strings.Join(strings.Fields(s), "") }

func tsGuardPolarity(cond, base, key string) (bool, bool) {
	cond = tsNormalizeQuotes(compactJS(cond))
	b := compactJS(base)
	forms := []string{b + "['" + key + "']"}
	forms = append(forms, b+"."+key)
	for _, lookup := range forms {
		guard := cond
		if strings.HasPrefix(guard, lookup+"?.") || strings.HasPrefix(guard, lookup+"?[") {
			return true, false
		}
		if strings.HasPrefix(guard, "!") && strings.HasPrefix(strings.TrimPrefix(guard, "!"), lookup+"?.") {
			return false, true
		}
		if strings.HasPrefix(guard, "!(") && strings.HasSuffix(guard, ")") {
			inner := strings.TrimPrefix(strings.TrimSuffix(guard, ")"), "!(")
			if strings.HasPrefix(inner, lookup+"?.") {
				return false, true
			}
		}
		if positive, negative, ok := tsLookupGuardPolarity(guard, lookup); ok {
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
	if cond == lookup+"||=" || cond == lookup+"??=" {
		return true, false, true
	}
	typeofPrefix := "typeof" + lookup
	if rest, ok := strings.CutPrefix(cond, typeofPrefix); ok {
		for _, comparison := range []string{"===", "==", "!==", "!="} {
			if !strings.HasPrefix(rest, comparison) {
				continue
			}
			value := strings.TrimPrefix(rest, comparison)
			if len(value) < 2 || value[0] != '\'' || value[len(value)-1] != '\'' {
				break
			}
			isEqual := comparison == "===" || comparison == "=="
			if value == "'undefined'" {
				return !isEqual, isEqual, true
			}
			if value != "''" {
				return isEqual, !isEqual, true
			}
			break
		}
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
	protoHas := "Object.prototype.hasOwnProperty.call(" + base + ",'" + key + "')"
	if cond == objectHas || cond == keysHas || cond == legacyHas || cond == protoHas {
		return true, false
	}
	if strings.HasPrefix(cond, "!") && (cond[1:] == objectHas || cond[1:] == keysHas || cond[1:] == legacyHas || cond[1:] == protoHas) {
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
	start, paren, bracket, brace := 0, 0, 0, 0
	for i := 0; i < len(trimmed); i++ {
		switch trimmed[i] {
		case '(':
			paren++
		case ')':
			paren--
		case '[':
			bracket++
		case ']':
			bracket--
		case '{':
			brace++
		case '}':
			brace--
		case ';', '\n':
			if paren == 0 && bracket == 0 && brace == 0 {
				start = i + 1
			}
		}
	}
	last := strings.TrimSpace(trimmed[start:])
	for _, keyword := range []string{"return", "throw", "continue", "break"} {
		if strings.HasPrefix(last, keyword) && (len(last) == len(keyword) || !isJSIdent(last[len(keyword)])) {
			return true
		}
	}
	return false
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
		if beforeOK && afterOK && strings.Contains(after[i:], "{ ") {
			lineEnd := strings.IndexAny(after[i:], ";\n")
			if lineEnd < 0 {
				lineEnd = len(after) - i
			}
			if strings.Contains(after[i:i+lineEnd], "}=") || strings.Contains(after[i:i+lineEnd], "}= ") {
				return pos, true
			}
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
		positive, negative := tsAliasConditionGuard(cond, name)
		if positive && readPos >= thenStart && readPos < thenEnd {
			return true
		}
		if negative && readPos >= thenEnd && tsTerminates(body[thenStart:thenEnd]) {
			return true
		}
	}
	p := compactJS(prior)
	return strings.Contains(p, name+"&&") || strings.Contains(p, name+"?") || strings.Contains(p, name+"||") || strings.Contains(p, "!"+name)
}

func tsAliasConditionGuard(cond, name string) (bool, bool) {
	cond = compactJS(cond)
	if p, n, ok := tsLookupGuardPolarity(cond, name); ok {
		return p, n
	}
	for term := range strings.SplitSeq(cond, "&&") {
		if p, _, ok := tsLookupGuardPolarity(term, name); ok && p {
			return true, false
		}
	}
	for term := range strings.SplitSeq(cond, "||") {
		if _, n, ok := tsLookupGuardPolarity(term, name); ok && n {
			return false, true
		}
	}
	return false, false
}
