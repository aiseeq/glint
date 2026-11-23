package frontendrules

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

const (
	tsArrowTokenWidth        = 2
	tsCallScanLookback       = 180
	tsFunctionHeaderLookback = 256
	tsObjectHeaderLookback   = 96
	tsObjectKeyPattern       = "(?:^|[,])\\s*(?:['\"`]([^'\"`]+)['\"`]|([A-Za-z_$][\\w$]*|[0-9]+))\\s*(?::|\\(|[,}])"
)

var (
	tsObjectKey           = regexp.MustCompile(tsObjectKeyPattern)
	tsDestructuredPattern = regexp.MustCompile(`(?s)\b(?:const|let|var)\s+\{[^{}]*\}\s*=\s*$`)
	tsObjectShorthandKey  = regexp.MustCompile(`(?:^|[,])\s*([A-Za-z_$][\w$]*|[0-9]+)\s*$`)
	tsTypeBeforeObject    = regexp.MustCompile(`\b(?:type|interface)\s+[A-Za-z_$][\w$]*\s*(?:=\s*)?$`)
	tsControlHeader       = regexp.MustCompile(`^(?:else\s+)?(?:if|for|while|switch|catch|with)\b`)
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
	tsClassStart           = regexp.MustCompile(`\bclass\s+[A-Za-z_$][\w$]*[^\{]*\{`)
	tsTypeAliasStart       = regexp.MustCompile(`\btype\s+[A-Za-z_$][\w$]*\s*=\s*$`)
	tsParamRecord          = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\??\s*:\s*(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,`)
	tsParamIndex           = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\??\s*:\s*\{\s*\[\s*[A-Za-z_$][\w$]*\s*:\s*string\s*\]`)
	tsParamNamed           = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\??\s*:\s*([A-Za-z_$][\w$]*)`)
	tsTemplateNull         = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*null\b`)
	tsTypeBody             = regexp.MustCompile(`(?s)\b(?:interface|type)\s+([A-Za-z_$][\w$]*)\s*(?:=\s*)?\{([^}]*)\}`)
	tsRecordField          = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,`)
	tsInlineObject         = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*\{([^}]*)\}`)
	tsTypedDictDecl        = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,|:\s*([A-Za-z_$][\w$]*))\s*=`)
	tsAssertRecord         = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*\bas\s+(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,`)
	tsUseStateRecord       = regexp.MustCompile(`\b(?:const|let|var)\s*\[\s*([A-Za-z_$][\w$]*)\s*(?:,[^\]]*)?\]\s*=\s*useState\s*<\s*(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,`)
	tsDestructuredParam    = regexp.MustCompile(`\{\s*([A-Za-z_$][\w$]*)\s*\}\s*:\s*([A-Za-z_$][\w$]*)`)
	tsAnnotatedDecl        = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)\s*=`)
	tsFunctionRecordReturn = regexp.MustCompile(`(?:\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\))\s*:\s*(?:Readonly\s*<\s*)?Record\s*<\s*string\s*,`)
	tsCallDecl             = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\(`)
	tsInMention            = regexp.MustCompile(`(['"` + "`" + `])([^'"` + "`" + `]+)['"` + "`" + `]\s+in\s+([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\b`)
	tsPropertyMention      = regexp.MustCompile(`\b([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*(?:\?\.|\.)\s*([A-Za-z_$][\w$]*)\b`)
	tsKeysCall             = regexp.MustCompile(`(?:Object\s*\.\s*keys|keys)\s*\(\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\)`)
	tsReceiverOwn          = regexp.MustCompile(`([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\.\s*hasOwnProperty\s*$`)
	tsSimpleExitStatement  = regexp.MustCompile(`^(?:return\b|throw\b|continue\b|break\b)`)
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
	globalCode := tsTopLevelCode(f.Code)
	globalText := tsTopLevelText(f.Code, f.Text)
	literalKeys := tsObjectLiteralKeyIndex(f.Code, f.Text)
	dictTypes := tsDictionaryTypes(f.Code)
	globalNames := tsDictionaryNames(globalCode, ctx.VirtualJavaScript, dictTypes)
	tsAddCallReturnNames(f.Code, globalNames)
	analyzer := tsConstantReadAnalyzer{
		rule:           r,
		ctx:            ctx,
		file:           f,
		globalCode:     globalCode,
		globalText:     globalText,
		dictTypes:      dictTypes,
		globalNames:    globalNames,
		dictNames:      make(map[[2]int]map[string]bool),
		dictResults:    make(map[[2]int]map[string]bool),
		aliasReads:     make(map[[2]int]map[int][]int),
		aliasUses:      make(map[[2]int]map[string][]int),
		mentions:       make(map[[2]int]map[string]tsMentionSummary),
		mentionIndexed: make(map[[2]int]bool),
		apiMentions:    make(map[[2]int]map[string][]int),
		functionEnds:   make(map[int]int),
		literalKeys:    literalKeys,
		reads:          reads,
	}
	return analyzer.analyze()
}

type tsConstantReadAnalyzer struct {
	rule           *TSConstantKeyReadUncheckedRule
	ctx            *core.FileContext
	file           patternkit.JsFlat
	globalCode     string
	globalText     string
	dictTypes      map[string]bool
	globalNames    map[string]bool
	dictNames      map[[2]int]map[string]bool
	dictResults    map[[2]int]map[string]bool
	aliasReads     map[[2]int]map[int][]int
	aliasUses      map[[2]int]map[string][]int
	mentions       map[[2]int]map[string]tsMentionSummary
	mentionIndexed map[[2]int]bool
	apiMentions    map[[2]int]map[string][]int
	functionEnds   map[int]int
	literalKeys    map[string]bool
	reads          [][]int
}

type tsMentionSummary struct {
	nonDereferences [][2]int
	apiPositions    []int
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
	globalCode, globalText := a.globalCode, a.globalText
	if !ok || !a.isDictionary(scope, base) || a.keyMentioned(scope, globalCode, globalText, base, key, match) {
		return nil
	}
	if tsDerefAfter(a.file.Code, match[1]) {
		return a.report(match[0], "Dictionary key "+key+" may be absent, so this read is undefined and the property access or call fails")
	}
	if tsDestructuredRead(scope.body, scope.localStart) {
		after := tsSkipJSWhitespace(scope.body, scope.localEnd)
		if !strings.HasPrefix(scope.body[after:], "||") && !strings.HasPrefix(scope.body[after:], "??") {
			return a.report(match[0], "Dictionary key "+key+" may be absent, so destructuring reads an undefined value")
		}
	}
	return a.analyzeAliasRead(scope, base, key)
}

// keyMentioned suppresses a candidate whenever the same key is discussed
// alongside the dictionary anywhere in the function or its visible module.
// Direct dereferences are the only allowed dictionary references.
func (a *tsConstantReadAnalyzer) keyMentioned(scope tsReadScope, globalCode, globalText, base, key string, candidate []int) bool {
	if a.literalKeys[key] {
		return true
	}
	summary := a.mentionSummary(scope.cacheKey, scope.body, scope.text, scope.start, base, key)
	if a.hasOtherBeforeRead(summary, scope, candidate[0]) {
		return true
	}
	if scope.inFunction && a.enclosingMentions(scope.start, base, key) {
		return true
	}
	moduleKey := [2]int{0, len(globalCode)}
	if scope.inFunction && a.mentionSummary(moduleKey, globalCode, globalText, 0, base, key).hasOther(candidate[0], candidate[1]) {
		return true
	}
	return false
}

func (a *tsConstantReadAnalyzer) hasOtherBeforeRead(summary tsMentionSummary, scope tsReadScope, candidate int) bool {
	for _, span := range summary.nonDereferences {
		if span[0] >= candidate || span[1] >= 0 && span[0] == candidate {
			continue
		}
		if !tsConditionalMentionIsIneffective(scope.body, span[0]-scope.start, candidate-scope.start) {
			return true
		}
	}
	for _, pos := range summary.apiPositions {
		if pos < candidate && !tsConditionalMentionIsIneffective(scope.body, pos-scope.start, candidate-scope.start) {
			return true
		}
	}
	return false
}

func tsConditionalMentionIsIneffective(code string, mention, candidate int) bool {
	if mention < 0 || mention >= len(code) || candidate < 0 || candidate > len(code) {
		return false
	}
	searchStart := max(mention-512, 0)
	if !strings.Contains(code[searchStart:mention+1], "if") {
		return false
	}
	flat := patternkit.JsFlat{Code: code}
	for ifPos := strings.LastIndex(code[searchStart:mention+1], "if"); ifPos >= 0; {
		ifPos += searchStart
		condition, ok := tsIfConditionAt(code, ifPos, flat)
		if ok && mention >= condition.Start && mention < condition.End {
			thenBranch, next, balanced := tsReadConditionalBranch(code, condition.End+1, flat)
			if !balanced {
				return false
			}
			conditionText := code[condition.Start:condition.End]
			if candidate >= thenBranch.start && candidate < thenBranch.end {
				return false
			}
			elseBranch, hasElse := tsReadElseBranch(code, next, flat)
			if hasElse && candidate >= elseBranch.start && candidate < elseBranch.end {
				return !tsConditionMeansMissing(conditionText, mention-condition.Start)
			}
			if candidate >= thenBranch.end {
				missing := tsConditionMeansMissing(conditionText, mention-condition.Start)
				guardExits := missing && tsBodyAlwaysExits(code[thenBranch.start:thenBranch.end])
				guardExits = guardExits || hasElse && !missing && tsBodyAlwaysExits(code[elseBranch.start:elseBranch.end])
				thenBody := code[thenBranch.start:thenBranch.end]
				if strings.Contains(thenBody, "if") && !tsBodyAlwaysExits(thenBody) {
					return false
				}
				return !guardExits && (!tsBodyAlwaysExits(thenBody) || strings.Contains(conditionText, "?."))
			}
		}
		if ifPos <= searchStart {
			break
		}
		// Relative to searchStart, like the first position: the loop head
		// adds the window start back.
		ifPos = strings.LastIndex(code[searchStart:ifPos], "if")
	}
	return false
}

func tsIfConditionAt(code string, pos int, flat patternkit.JsFlat) (patternkit.JsSpanRange, bool) {
	if pos > 0 && isJSIdent(code[pos-1]) {
		return patternkit.JsSpanRange{}, false
	}
	if pos+2 < len(code) && isJSIdent(code[pos+2]) {
		return patternkit.JsSpanRange{}, false
	}
	open := tsSkipJSWhitespace(code, pos+2)
	if open >= len(code) || code[open] != '(' {
		return patternkit.JsSpanRange{}, false
	}
	end, ok := flat.Closing(open)
	if !ok {
		return patternkit.JsSpanRange{}, false
	}
	return patternkit.JsSpanRange{Start: open + 1, End: end}, true
}

type tsConditionalBranch struct{ start, end int }

func tsReadConditionalBranch(code string, afterCondition int, flat patternkit.JsFlat) (tsConditionalBranch, int, bool) {
	start := tsSkipJSWhitespace(code, afterCondition)
	if start >= len(code) {
		return tsConditionalBranch{}, start, false
	}
	if condition, ok := tsIfConditionAt(code, start, flat); ok {
		_, next, balanced := tsReadConditionalBranch(code, condition.End+1, flat)
		if !balanced {
			return tsConditionalBranch{}, next, false
		}
		end := next
		if elseBranch, hasElse := tsReadElseBranch(code, next, flat); hasElse {
			end = elseBranch.end
		}
		return tsConditionalBranch{start: start, end: end}, end, true
	}
	if code[start] == '{' {
		end, ok := flat.Closing(start)
		return tsConditionalBranch{start: start + 1, end: end}, end + 1, ok
	}
	end := start
	for end < len(code) && code[end] != ';' && code[end] != '\n' {
		end++
	}
	if end < len(code) && code[end] == ';' {
		end++
	}
	return tsConditionalBranch{start: start, end: end}, end, true
}

func tsReadElseBranch(code string, afterThen int, flat patternkit.JsFlat) (tsConditionalBranch, bool) {
	start := tsSkipJSWhitespace(code, afterThen)
	if !strings.HasPrefix(code[start:], "else") {
		return tsConditionalBranch{}, false
	}
	branch, _, ok := tsReadConditionalBranch(code, start+len("else"), flat)
	return branch, ok
}

func tsConditionMeansMissing(condition string, mention int) bool {
	if mention < 0 || mention > len(condition) {
		return false
	}
	leading := strings.TrimLeft(condition, " \t\n(")
	if strings.HasPrefix(leading, "!") {
		return true
	}
	before := strings.TrimSpace(condition[:mention])
	for strings.HasSuffix(before, "(") {
		before = strings.TrimSpace(strings.TrimSuffix(before, "("))
	}
	if strings.HasSuffix(before, "!") {
		return true
	}
	after := condition[mention:]
	if strings.Contains(after, "=== undefined") || strings.Contains(after, "== undefined") || strings.Contains(after, "=== null") || strings.Contains(after, "== null") || strings.Contains(condition, "undefined ===") || strings.Contains(condition, "null ==") || strings.Contains(condition, "null ===") {
		return true
	}
	return strings.Contains(condition, "typeof") && strings.Contains(condition, "!==")
}

func tsBodyAlwaysExits(body string) bool {
	body = strings.TrimSpace(body)
	if tsSimpleExitStatement.MatchString(body) {
		return true
	}
	body = strings.TrimRight(body, ";")
	last := strings.LastIndexAny(body, ";\n")
	if last >= 0 {
		body = strings.TrimSpace(body[last+1:])
	}
	return tsSimpleExitStatement.MatchString(body)
}

func (summary tsMentionSummary) hasOther(start, end int) bool {
	for _, span := range summary.nonDereferences {
		if span[0] < start && (span[1] < 0 || span[0] != start || span[1] != end) {
			return true
		}
	}
	for _, pos := range summary.apiPositions {
		if pos < start {
			return true
		}
	}
	return false
}

func (a *tsConstantReadAnalyzer) mentionSummary(cacheKey [2]int, code, body string, offset int, base, key string) tsMentionSummary {
	if a.mentions[cacheKey] == nil {
		a.mentions[cacheKey] = make(map[string]tsMentionSummary)
	}
	pair := tsCanonicalBase(base) + "\x00" + key
	if !a.mentionIndexed[cacheKey] {
		a.indexMentionScope(cacheKey, code, body, offset)
	}
	summary := a.mentions[cacheKey][pair]
	summary.apiPositions = a.apiMentions[cacheKey][tsMentionPair(base, key)]
	return summary
}

func (a *tsConstantReadAnalyzer) indexMentionScope(cacheKey [2]int, code, body string, offset int) {
	if offset > 0 {
		bodyEnd := offset + len(body)
		for _, m := range a.reads {
			if m[0] < offset {
				continue
			}
			if m[1] > bodyEnd {
				break
			}
			base, key := tsCanonicalBase(a.file.Code[m[2]:m[3]]), a.file.Text[m[6]:m[7]]
			if !tsDerefAfter(a.file.Code, m[1]) {
				pair := base + "\x00" + key
				summary := a.mentions[cacheKey][pair]
				summary.nonDereferences = append(summary.nonDereferences, [2]int{m[0], m[1]})
				a.mentions[cacheKey][pair] = summary
			}
		}
	} else {
		for _, m := range tsConstKeyRead.FindAllStringSubmatchIndex(body, -1) {
			base, key := tsCanonicalBase(body[m[2]:m[3]]), body[m[6]:m[7]]
			if !tsDerefAfter(code, m[1]) {
				pair := base + "\x00" + key
				summary := a.mentions[cacheKey][pair]
				summary.nonDereferences = append(summary.nonDereferences, [2]int{offset + m[0], offset + m[1]})
				a.mentions[cacheKey][pair] = summary
			}
		}
	}
	a.apiMentions[cacheKey] = tsIndexAPIMentions(code, body)
	for pair, positions := range a.apiMentions[cacheKey] {
		for i := range positions {
			positions[i] += offset
		}
		a.apiMentions[cacheKey][pair] = positions
	}
	markMention := func(base, key string, pos int) {
		pair := tsCanonicalBase(base) + "\x00" + key
		summary := a.mentions[cacheKey][pair]
		summary.nonDereferences = append(summary.nonDereferences, [2]int{pos, -1})
		a.mentions[cacheKey][pair] = summary
	}
	for _, match := range tsInMention.FindAllStringSubmatchIndex(body, -1) {
		markMention(body[match[6]:match[7]], body[match[4]:match[5]], offset+match[0])
	}
	for _, match := range tsPropertyMention.FindAllStringSubmatchIndex(code, -1) {
		markMention(code[match[2]:match[3]], code[match[4]:match[5]], offset+match[0])
	}
	a.mentionIndexed[cacheKey] = true
}

func (a *tsConstantReadAnalyzer) enclosingMentions(pos int, base, keyName string) bool {
	fn, ok := a.file.EnclosingFunction(pos)
	for ok {
		parent, parentOK := a.file.EnclosingFunction(fn.Start)
		if !parentOK || parent.Brace == fn.Brace {
			return false
		}
		end, balanced := a.closingFunction(parent)
		if !balanced {
			return false
		}
		start := parent.Brace + 1
		body := a.file.Text[start:end]
		cacheKey := [2]int{parent.Brace, end}
		code := a.file.Code[start:end]
		if a.mentionSummary(cacheKey, code, body, start, base, keyName).hasOther(pos, pos) {
			return true
		}
		fn, ok = parent, true
	}
	return false
}

func (a *tsConstantReadAnalyzer) closingFunction(fn patternkit.JsFunc) (int, bool) {
	if end, ok := a.functionEnds[fn.Brace]; ok {
		return end, true
	}
	end, ok := a.file.Closing(fn.Brace)
	if ok {
		a.functionEnds[fn.Brace] = end
	}
	return end, ok
}

func tsMentionPair(base, key string) string {
	return tsCanonicalBase(base) + "\x00" + key
}

func tsIndexAPIMentions(code, text string) map[string][]int {
	flat := patternkit.JsFlat{Code: code}
	pairs := make(map[string][]int)
	for open := strings.IndexByte(code, '('); open >= 0; {
		close, ok := flat.Closing(open)
		if ok {
			indexCallMentionPairs(code, text, open, close, flat, pairs)
		}
		next := strings.IndexByte(code[open+1:], '(')
		if next < 0 {
			return pairs
		}
		open += next + 1
	}
	return pairs
}

func indexCallMentionPairs(code, text string, open, close int, flat patternkit.JsFlat, pairs map[string][]int) {
	var bases, keys []string
	for _, arg := range flat.Items(open, close) {
		codeArg := strings.TrimSpace(code[arg.Start:arg.End])
		if tsIsSimpleIdentifierPath(codeArg) {
			bases = append(bases, tsCanonicalBase(codeArg))
		}
		if key, ok := tsQuotedKeyValue(strings.TrimSpace(text[arg.Start:arg.End])); ok {
			keys = append(keys, key)
		}
	}
	for _, base := range bases {
		for _, key := range keys {
			addMentionPosition(pairs, base, key, open)
		}
	}
	addKeyEnumerationMentions(code, open, keys, pairs)
}

func addMentionPosition(pairs map[string][]int, base, key string, pos int) {
	pair := tsMentionPair(base, key)
	pairs[pair] = append(pairs[pair], pos)
}

func addKeyEnumerationMentions(code string, open int, keys []string, pairs map[string][]int) {
	if len(keys) == 0 {
		return
	}
	start := max(open-tsCallScanLookback, 0)
	before := code[start:open]
	if strings.Contains(before, "keys") {
		if match := tsKeysCall.FindStringSubmatch(before); match != nil {
			addMentionKeys(pairs, match[1], keys, open)
		}
	}
	before = strings.TrimSpace(code[:open])
	if strings.Contains(before, "hasOwnProperty") {
		if match := tsReceiverOwn.FindStringSubmatch(before); match != nil {
			addMentionKeys(pairs, match[1], keys, open)
		}
	}
}

func addMentionKeys(pairs map[string][]int, base string, keys []string, pos int) {
	for _, key := range keys {
		addMentionPosition(pairs, base, key, pos)
	}
}

func tsQuotedKeyValue(value string) (string, bool) {
	if len(value) < 2 {
		return "", false
	}
	quote := value[0]
	if quote != '\'' && quote != '"' && quote != '`' || value[len(value)-1] != quote {
		return "", false
	}
	return value[1 : len(value)-1], true
}

func tsIsSimpleIdentifierPath(value string) bool {
	expectIdentifier := true
	foundIdentifier := false
	for i := 0; i < len(value); {
		if value[i] == ' ' || value[i] == '\t' || value[i] == '\n' {
			i++
			continue
		}
		if expectIdentifier {
			c := value[i]
			if !isJSIdent(c) || c >= '0' && c <= '9' {
				return false
			}
			for i < len(value) && isJSIdent(value[i]) {
				i++
			}
			foundIdentifier = true
			expectIdentifier = false
			continue
		}
		if value[i] != '.' {
			return false
		}
		i++
		expectIdentifier = true
	}
	return foundIdentifier && !expectIdentifier
}

func (a *tsConstantReadAnalyzer) analyzeAliasRead(scope tsReadScope, base, key string) []*core.Violation {
	aliasesByRead, ok := a.aliasReads[scope.cacheKey]
	if !ok {
		aliasesByRead = make(map[int][]int)
		for _, alias := range tsAliasRead.FindAllStringSubmatchIndex(scope.body, -1) {
			aliasesByRead[alias[4]] = alias
		}
		a.aliasReads[scope.cacheKey] = aliasesByRead
	}
	alias, exists := aliasesByRead[scope.localStart]
	if !exists || alias[1] < scope.localEnd ||
		tsCanonicalBase(scope.body[alias[4]:alias[5]]) != tsCanonicalBase(base) ||
		a.file.Text[scope.start+alias[8]:scope.start+alias[9]] != key {
		return nil
	}
	var out []*core.Violation
	name := scope.body[alias[2]:alias[3]]
	after := tsSkipJSWhitespace(scope.body, alias[1])
	if strings.HasPrefix(scope.body[after:], "||") || strings.HasPrefix(scope.body[after:], "??") {
		return nil
	}
	uses := a.aliasUseIndex(scope)
	if !tsAliasUsesOnlyDereference(scope.body, uses[name], alias[1], name) {
		return nil
	}
	out = append(out, a.reportAt(scope.start+alias[0], "Dictionary key "+key+" may be absent, leaving "+name+" undefined before it is dereferenced")...)
	return out
}

func (a *tsConstantReadAnalyzer) aliasUseIndex(scope tsReadScope) map[string][]int {
	uses, ok := a.aliasUses[scope.cacheKey]
	if ok {
		return uses
	}
	uses = make(map[string][]int)
	for i := 0; i < len(scope.body); {
		if c := scope.body[i]; !isJSIdent(c) || c >= '0' && c <= '9' {
			i++
			continue
		}
		start := i
		previous := start - 1
		for previous >= 0 && (scope.body[previous] == ' ' || scope.body[previous] == '\t' || scope.body[previous] == '\n') {
			previous--
		}
		for i < len(scope.body) && isJSIdent(scope.body[i]) {
			i++
		}
		name := scope.body[start:i]
		if previous < 0 || scope.body[previous] != '.' {
			uses[name] = append(uses[name], start)
		}
	}
	a.aliasUses[scope.cacheKey] = uses
	return uses
}

func tsAliasUsesOnlyDereference(body string, positions []int, after int, name string) bool {
	for _, pos := range positions {
		if pos < after {
			continue
		}
		return tsIdentifierDereference(body, pos, name)
	}
	return false
}

func tsIdentifierDereference(body string, start int, name string) bool {
	end := start + len(name)
	i := end
	for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\n') {
		i++
	}
	if i < len(body) && (body[i] == '.' || body[i] == '(' || body[i] == '[') {
		return true
	}
	declarationStart := strings.LastIndexAny(body[:start], ";\n") + 1
	return tsDestructuredPattern.MatchString(body[declarationStart:start])
}

func tsCanonicalBase(base string) string {
	return strings.TrimSuffix(strings.ReplaceAll(strings.Join(strings.Fields(base), ""), "?.", "."), ".")
}

func tsObjectLiteralKeyIndex(code, text string) map[string]bool {
	keys := make(map[string]bool)
	flat := patternkit.JsFlat{Code: code}
	for open := strings.IndexByte(code, '{'); open >= 0; {
		if tsObjectLiteralOpen(code, open) {
			if close, ok := flat.Closing(open); ok {
				body := text[open+1 : close]
				for _, match := range tsObjectKey.FindAllStringSubmatch(body, -1) {
					key := match[1]
					if key == "" {
						key = match[2]
					}
					keys[key] = true
				}
				for _, shorthand := range tsObjectShorthandKey.FindAllStringSubmatch(body, -1) {
					keys[shorthand[1]] = true
				}
			}
		}
		next := strings.IndexByte(code[open+1:], '{')
		if next < 0 {
			break
		}
		open += next + 1
	}
	return keys
}

func tsObjectLiteralOpen(code string, open int) bool {
	start := max(open-tsObjectHeaderLookback, 0)
	before := strings.TrimSpace(code[start:open])
	if tsTypeBeforeObject.MatchString(before) {
		return false
	}
	for _, suffix := range []string{"=", ":", "return", "(", "[", ",", "default"} {
		if strings.HasSuffix(before, suffix) {
			return true
		}
	}
	return false
}

func tsDestructuredRead(body string, pos int) bool {
	start := strings.LastIndexByte(body[:pos], ';') + 1
	return tsDestructuredPattern.MatchString(body[start:pos])
}

func tsTopLevelCode(source string) string {
	return tsTopLevelText(source, source)
}

func tsTopLevelText(codeSource, target string) string {
	text := []byte(target)
	flat := patternkit.JsFlat{Code: codeSource}
	for i := 0; i < len(codeSource); i++ {
		if codeSource[i] != '{' {
			continue
		}
		if !tsLikelyFunctionBrace(codeSource, i) {
			continue
		}
		if _, ok := flat.FunctionAtBrace(i); !ok {
			continue
		}
		end, ok := flat.Closing(i)
		if !ok {
			continue
		}
		fn, _ := flat.FunctionAtBrace(i)
		for j := fn.Start; j < end; j++ {
			if text[j] != '\n' {
				text[j] = ' '
			}
		}
		i = end
	}
	for arrow := strings.Index(codeSource, "=>"); arrow >= 0; {
		end := arrow + tsArrowTokenWidth
		for end < len(codeSource) && codeSource[end] != ';' && codeSource[end] != '\n' {
			end++
		}
		headStart := strings.LastIndexAny(codeSource[:arrow], "\n;") + 1
		for j := headStart; j < end; j++ {
			if text[j] != '\n' {
				text[j] = ' '
			}
		}
		next := strings.Index(codeSource[end:], "=>")
		if next < 0 {
			break
		}
		arrow = end + next
	}
	return string(text)
}

func tsLikelyFunctionBrace(code string, brace int) bool {
	start := max(brace-tsFunctionHeaderLookback, 0)
	header := strings.TrimSpace(code[start:brace])
	if strings.HasSuffix(header, "=>") {
		return true
	}
	start = strings.LastIndexAny(header, ";{}\n") + 1
	header = strings.TrimSpace(header[start:])
	if tsControlHeader.MatchString(header) {
		return false
	}
	closeParen := strings.LastIndexByte(header, ')')
	if closeParen < 0 {
		return false
	}
	return strings.TrimSpace(header[closeParen+1:]) == "" || strings.HasPrefix(strings.TrimSpace(header[closeParen+1:]), ":")
}

func tsTypeIndexedAccess(body string, pos int) bool {
	if pos < 0 || pos > len(body) {
		return false
	}
	start := max(strings.LastIndexByte(body[:pos], ';'), strings.LastIndexByte(body[:pos], '\n')) + 1
	return tsTypeAliasStart.MatchString(body[start:pos])
}

func (a *tsConstantReadAnalyzer) readScope(match []int) (tsReadScope, bool) {
	scope := tsReadScope{start: 0, end: len(a.file.Code), dictCode: a.file.Code, cacheKey: [2]int{0, len(a.file.Code)}}
	fn, inFunction := a.file.EnclosingFunction(match[0])
	if inFunction {
		fnEnd, balanced := a.closingFunction(fn)
		if !balanced || match[0] < fn.Brace || match[1] > fnEnd {
			return tsReadScope{}, false
		}
		scope.start, scope.end = fn.Brace+1, fnEnd
		scope.dictCode = a.file.Code[fn.Start:fnEnd]
		scope.cacheKey = [2]int{fn.Start, fnEnd}
		scope.inFunction = true
	}
	if !inFunction {
		if arrow := strings.LastIndex(a.file.Code[:match[0]], "=>"); arrow >= 0 {
			end := len(a.file.Code)
			if rel := strings.IndexAny(a.file.Code[arrow+tsArrowTokenWidth:], ";\n"); rel >= 0 {
				end = arrow + tsArrowTokenWidth + rel
			}
			// An arrow body that ended before the read leaves the read at
			// the top level.
			if match[1] <= end {
				start := arrow + tsArrowTokenWidth
				headStart := strings.LastIndexAny(a.file.Code[:arrow], "\n;") + 1
				scope.start, scope.end = start, end
				scope.localStart, scope.localEnd = match[0]-start, match[1]-start
				scope.body, scope.text = a.file.Code[start:end], a.file.Text[start:end]
				scope.dictCode = a.file.Code[headStart:end]
				scope.cacheKey, scope.inFunction = [2]int{headStart, end}, true
				return scope, true
			}
		}
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
	if a.dictResults[scope.cacheKey] == nil {
		a.dictResults[scope.cacheKey] = make(map[string]bool)
	}
	canonical := tsCanonicalBase(base)
	if result, ok := a.dictResults[scope.cacheKey][canonical]; ok {
		return result
	}
	result := a.isDictionaryUncached(scope, base)
	a.dictResults[scope.cacheKey][canonical] = result
	return result
}

func (a *tsConstantReadAnalyzer) isDictionaryUncached(scope tsReadScope, base string) bool {
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
			end, balanced := a.closingFunction(fn)
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

func tsDerefAfter(code string, end int) bool {
	end = tsSkipJSWhitespace(code, end)
	if end < len(code) && code[end] == '!' {
		end++
	}
	end = tsSkipTypeAssertion(code, tsSkipJSWhitespace(code, end))
	end = tsSkipJSWhitespace(code, end)
	if end < len(code) && code[end] == '[' {
		if close, ok := (patternkit.JsFlat{Code: code}).Closing(end); ok {
			next := tsSkipJSWhitespace(code, close+1)
			return next < len(code) && (code[next] == '[' || code[next] == '.' || code[next] == '(')
		}
	}
	return end < len(code) && (code[end] == '.' || code[end] == '(')
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

func isJSIdent(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
