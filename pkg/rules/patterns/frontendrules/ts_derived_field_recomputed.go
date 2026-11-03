package frontendrules

import (
	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func init() { rules.Register(NewTSDerivedFieldRecomputedRule()) }

// TSDerivedFieldRecomputedRule reports functions that recompute a group already
// supplied by an API type. Not flagged when the function reads the group field.
type TSDerivedFieldRecomputedRule struct {
	*rules.BaseRule
	types     map[string]map[string]string
	props     map[string]map[string]bool
	typeFiles map[string]map[string]string
}

// NewTSDerivedFieldRecomputedRule creates the rule.
func NewTSDerivedFieldRecomputedRule() *TSDerivedFieldRecomputedRule {
	return &TSDerivedFieldRecomputedRule{BaseRule: rules.NewBaseRule("ts-derived-field-recomputed", "patterns", "Detects frontend functions that recompute a field group already supplied by an API type", core.SeverityMedium)}
}

var (
	dType           = regexp.MustCompile(`(?s)\b(?:interface|type)\s+([A-Za-z_$][\w$]*)\s*(?:=\s*)?\{([^}]*)\}`)
	dProp           = regexp.MustCompile(`(?:^|[,;\n])\s*(?:readonly\s+)?([A-Za-z_$][\w$]*)\s*[?:]`)
	dAnn            = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*(?:\s*\[\])?)`)
	dCmp            = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\??\.\s*([A-Za-z_$][\w$]*)\s*(?:===|!==|==|!=)\s*(?:'([^']*)'|"([^"]*)")`)
	dSwitch         = regexp.MustCompile(`switch\s*\(\s*([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\)\s*\{([^}]*)\}`)
	dIncludes       = regexp.MustCompile(`\[([^\]]*)\]\s*\.includes\(\s*([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\)`)
	dLiteral        = regexp.MustCompile(`'([^']*)'|"([^"]*)"`)
	dBareCmp        = regexp.MustCompile(`\b([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:===|!==|==|!=)\s*'([^']*)'|\b([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:===|!==|==|!=)\s*"([^"]*)"`)
	dParam          = regexp.MustCompile(`^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\??\s*:\s*(?:\{\s*)?([A-Za-z_$][A-Za-z0-9_$]*)`)
	dCmpAtStart     = regexp.MustCompile(`^(?:` + dCmp.String() + `)`)
	dBareCmpAtStart = regexp.MustCompile(`^(?:` + dBareCmp.String() + `)`)
)

func dCmpParts(source string, m []int) (string, string, string) {
	value := m[6:8]
	if value[0] < 0 {
		value = m[8:10]
	}
	return source[m[2]:m[3]], source[m[4]:m[5]], source[value[0]:value[1]]
}

func dTypeSource(c *core.FileContext) bool {
	return (c.IsTypeScriptFile() || c.IsJavaScriptFile()) && !c.IsTestFile() && !strings.Contains(filepath.ToSlash(c.RelPath), "/node_modules/")
}

func dFindingSource(c *core.FileContext) bool {
	return dTypeSource(c) && !c.IsGenerated()
}

// UseProjectFiles indexes generated and handwritten API type declarations.
func (r *TSDerivedFieldRecomputedRule) UseProjectFiles(files []*core.FileContext) {
	r.types = map[string]map[string]string{}
	r.props = map[string]map[string]bool{}
	r.typeFiles = map[string]map[string]string{}
	for _, c := range files {
		if !dTypeSource(c) {
			continue
		}
		f := patternkit.NewJSFlat(c)
		for _, m := range dType.FindAllStringSubmatch(f.Code, -1) {
			r.indexType(m[1], m[2], c.RelPath)
		}
	}
}

func (r *TSDerivedFieldRecomputedRule) indexType(name, body, source string) {
	props := map[string]bool{}
	for _, p := range dProp.FindAllStringSubmatch(body, -1) {
		props[p[1]] = true
	}
	if r.props[name] == nil {
		r.props[name] = map[string]bool{}
	}
	for prop := range props {
		r.props[name][prop] = true
	}
	for field := range props {
		for _, suffix := range []string{"Group", "Category", "Bucket"} {
			if !props[field+suffix] {
				continue
			}
			if r.types[name] == nil {
				r.types[name] = map[string]string{}
			}
			r.types[name][field] = field + suffix
			if r.typeFiles[name] == nil {
				r.typeFiles[name] = map[string]string{}
			}
			r.typeFiles[name][field] = source
		}
	}
}

// ResetState clears the indexed API field declarations.
func (r *TSDerivedFieldRecomputedRule) ResetState() {
	r.types = nil
	r.props = nil
	r.typeFiles = nil
}

// AnalyzeFile reports functions that recompute a known derived field.
func (r *TSDerivedFieldRecomputedRule) AnalyzeFile(c *core.FileContext) []*core.Violation {
	if !dFindingSource(c) {
		return nil
	}
	f := patternkit.NewJSFlat(c)
	seen := map[int]bool{}
	summaries := map[int]*dFunctionSummary{}
	comparisons := dComparisonMatches{
		derived: dCmp.FindAllStringSubmatchIndex(f.Code, -1),
		bare:    dBareCmp.FindAllStringSubmatchIndex(f.Code, -1),
	}
	var out []*core.Violation
	out = r.analyzeDerivedComparisons(c, f, comparisons.derived, seen, summaries, comparisons, out)
	out = r.analyzeBareComparisons(c, f, comparisons.bare, seen, summaries, comparisons, out)
	out = r.analyzeDerivedCandidates(c, f, seen, summaries, comparisons, out)
	return out
}

func (r *TSDerivedFieldRecomputedRule) analyzeDerivedComparisons(c *core.FileContext, f patternkit.JsFlat, matches [][]int, seen map[int]bool, summaries map[int]*dFunctionSummary, comparisons dComparisonMatches, out []*core.Violation) []*core.Violation {
	for _, m := range matches {
		name, field, lit := dCmpParts(f.Code, m)
		fn, ok := f.EnclosingFunction(m[0])
		if !ok || seen[fn.Start] {
			continue
		}
		end, ok := f.Closing(fn.Brace)
		if !ok {
			continue
		}
		summary := r.functionSummary(f, fn, end, summaries, comparisons, c.RelPath)
		derived := summary.bindings[name+"."+field]
		if derived == "" || summary.readsDerived(name, derived) {
			continue
		}
		if !summary.hasMultipleFieldValues(name, field, lit) {
			continue
		}
		seen[fn.Start] = true
		out = patternkit.JsReport(out, r.BaseRule, c, f.Line(m[0]), "Function recomputes "+derived+" from raw "+field+" values", "Read "+name+"."+derived+" supplied by the API")
	}
	return out
}

func (r *TSDerivedFieldRecomputedRule) analyzeBareComparisons(c *core.FileContext, f patternkit.JsFlat, matches [][]int, seen map[int]bool, summaries map[int]*dFunctionSummary, comparisons dComparisonMatches, out []*core.Violation) []*core.Violation {
	for _, m := range matches {
		name, value := dBareParts(f.Code, m)
		if strings.HasSuffix(f.Code[:m[0]], ".") {
			continue
		}
		fn, ok := f.EnclosingFunction(m[0])
		if !ok || seen[fn.Start] {
			continue
		}
		end, ok := f.Closing(fn.Brace)
		if !ok {
			continue
		}
		summary := r.functionSummary(f, fn, end, summaries, comparisons, c.RelPath)
		derived := summary.bindings[name]
		if derived == "" || summary.readsDerived(name, derived) || !summary.hasMultipleBareValues(name, value) {
			continue
		}
		seen[fn.Start] = true
		out = patternkit.JsReport(out, r.BaseRule, c, f.Line(m[0]), "Function recomputes "+derived+" from raw "+name+" values", "Read the API supplied group field")
	}
	return out
}

func (r *TSDerivedFieldRecomputedRule) analyzeDerivedCandidates(c *core.FileContext, f patternkit.JsFlat, seen map[int]bool, summaries map[int]*dFunctionSummary, comparisons dComparisonMatches, out []*core.Violation) []*core.Violation {
	for _, candidate := range dCandidates(f.Code) {
		fn, ok := f.EnclosingFunction(candidate.pos)
		if !ok || seen[fn.Start] {
			continue
		}
		end, ok := f.Closing(fn.Brace)
		if !ok {
			continue
		}
		summary := r.functionSummary(f, fn, end, summaries, comparisons, c.RelPath)
		derived := summary.bindings[candidate.name+"."+candidate.field]
		if derived == "" {
			derived = summary.bindings[candidate.name]
		}
		if derived == "" || summary.readsDerived(candidate.name, derived) || len(candidate.values) < 2 {
			continue
		}
		seen[fn.Start] = true
		out = patternkit.JsReport(out, r.BaseRule, c, f.Line(candidate.pos), "Function recomputes "+derived+" from raw "+candidate.field+" values", "Read "+candidate.name+"."+derived+" supplied by the API")
	}
	return out
}

type dFieldKey struct {
	name  string
	field string
}

type dFunctionSummary struct {
	body        string
	bindings    map[string]string
	bareValues  map[string]map[string]bool
	fieldValues map[dFieldKey]map[string]bool
	derivedRead map[dFieldKey]bool
}

type dComparisonMatches struct {
	derived [][]int
	bare    [][]int
}

func (r *TSDerivedFieldRecomputedRule) functionSummary(f patternkit.JsFlat, fn patternkit.JsFunc, end int, summaries map[int]*dFunctionSummary, comparisons dComparisonMatches, currentPath string) *dFunctionSummary {
	// Keyed by the body's brace: two functions can share a header start when
	// one header runs back over the other (a ')' in JSX text).
	if summary := summaries[fn.Brace]; summary != nil {
		return summary
	}
	body := f.Code[fn.Start : end+1]
	summary := &dFunctionSummary{
		body:        body,
		bindings:    dFunctionBindings(f, fn, body, r, currentPath),
		bareValues:  map[string]map[string]bool{},
		fieldValues: map[dFieldKey]map[string]bool{},
		derivedRead: map[dFieldKey]bool{},
	}
	for _, m := range comparisonMatchesInRange(comparisons.derived, fn.Start, end) {
		name, field, value := dCmpParts(f.Code, m)
		addDerivedValue(summary.fieldValues, dFieldKey{name: name, field: field}, value)
	}
	for _, m := range comparisonMatchesInRange(comparisons.bare, fn.Start, end) {
		name, value := dBareParts(f.Code, m)
		if m[0] > fn.Start && f.Code[m[0]-1] == '.' {
			continue
		}
		addBareValue(summary.bareValues, name, value)
	}
	if fn.Start > 0 && fn.Start < len(f.Code) && patternkit.IsWordChar(f.Code[fn.Start-1]) && patternkit.IsWordChar(f.Code[fn.Start]) {
		if m := dCmpAtStart.FindStringSubmatchIndex(body); m != nil && m[0] == 0 {
			name, field, value := dCmpParts(body, m)
			addDerivedValue(summary.fieldValues, dFieldKey{name: name, field: field}, value)
		}
		if m := dBareCmpAtStart.FindStringSubmatchIndex(body); m != nil && m[0] == 0 {
			name, value := dBareParts(body, m)
			addBareValue(summary.bareValues, name, value)
		}
	}
	summaries[fn.Brace] = summary
	return summary
}

func comparisonMatchesInRange(matches [][]int, start, end int) [][]int {
	first := sort.Search(len(matches), func(i int) bool { return matches[i][0] >= start })
	var inRange [][]int
	for i := first; i < len(matches) && matches[i][0] <= end; i++ {
		if matches[i][1] <= end+1 {
			inRange = append(inRange, matches[i])
		}
	}
	return inRange
}

func (s *dFunctionSummary) hasMultipleFieldValues(name, field, initial string) bool {
	values := map[string]bool{initial: true}
	for value := range s.fieldValues[dFieldKey{name: name, field: field}] {
		values[value] = true
	}
	for value := range s.bareValues[name] {
		values[value] = true
	}
	return len(values) >= 2
}

func (s *dFunctionSummary) hasMultipleBareValues(name, initial string) bool {
	values := s.bareValues[name]
	return len(values) >= 2 || len(values) == 1 && !values[initial]
}

func (s *dFunctionSummary) readsDerived(name, derived string) bool {
	key := dFieldKey{name: name, field: derived}
	if read, ok := s.derivedRead[key]; ok {
		return read
	}
	read := strings.Contains(s.body, name+"."+derived)
	s.derivedRead[key] = read
	return read
}

func addDerivedValue(values map[dFieldKey]map[string]bool, key dFieldKey, value string) {
	if values[key] == nil {
		values[key] = map[string]bool{}
	}
	values[key][value] = true
}

func addBareValue(values map[string]map[string]bool, name, value string) {
	if values[name] == nil {
		values[name] = map[string]bool{}
	}
	values[name][value] = true
}

func dFunctionBindings(f patternkit.JsFlat, fn patternkit.JsFunc, body string, r *TSDerivedFieldRecomputedRule, currentPath string) map[string]string {
	bindings := map[string]string{}
	for _, a := range dAnn.FindAllStringSubmatch(body, -1) {
		typ := strings.TrimSuffix(strings.TrimSpace(a[2]), "[]")
		for field, derived := range r.types[typ] {
			if r.typeFiles[typ][field] != "" && r.typeFiles[typ][field] != currentPath {
				bindings[a[1]+"."+field] = derived
			}
		}
	}
	head, _ := f.Header(fn.Brace)
	open := strings.IndexByte(head, '(')
	if open < 0 {
		return bindings
	}
	close := dMatchingClose(head, open)
	if close < 0 {
		return bindings
	}
	params := dSplitParams(head[open+1 : close])
	type paramInfo struct{ name, typ, object string }
	infos := make([]paramInfo, 0, len(params))
	for _, param := range params {
		m := dParam.FindStringSubmatch(param)
		if m == nil {
			continue
		}
		info := paramInfo{name: m[1], typ: m[2]}
		if brace := strings.IndexByte(param, '{'); brace >= 0 {
			if end := dMatchingClose(param, brace); end > brace {
				info.object = param[brace+1 : end]
			}
		}
		infos = append(infos, info)
		for field, derived := range r.types[info.typ] {
			if r.typeFiles[info.typ][field] != currentPath {
				bindings[info.name+"."+field] = derived
			}
		}
	}
	for _, info := range infos {
		if info.object == "" {
			continue
		}
		props := dPropNames(info.object)
		for typ := range r.types {
			matches := 0
			for field := range r.props[typ] {
				if props[field] {
					matches++
				}
			}
			if matches < 2 {
				continue
			}
			for field, derived := range r.types[typ] {
				if props[field] && r.typeFiles[typ][field] != currentPath {
					bindings[info.name+"."+field] = derived
				}
			}
		}
	}
	for typ, fields := range r.types {
		matched := 0
		for _, info := range infos {
			if r.props[typ][info.name] {
				matched++
			}
		}
		if matched < 2 {
			continue
		}
		for _, info := range infos {
			if derived := fields[info.name]; derived != "" && r.typeFiles[typ][info.name] != currentPath {
				bindings[info.name] = derived
			}
		}

	}
	return bindings
}

func dBareParts(source string, m []int) (string, string) {
	if m[2] >= 0 {
		return source[m[2]:m[3]], source[m[4]:m[5]]
	}
	return source[m[6]:m[7]], source[m[8]:m[9]]
}

func dPropNames(body string) map[string]bool {
	props := map[string]bool{}
	for _, p := range dProp.FindAllStringSubmatch(body, -1) {
		props[p[1]] = true
	}
	return props
}

func dMatchingClose(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func dSplitParams(s string) []string {
	var result []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
			depth--
		case ',':
			if depth == 0 {
				result = append(result, s[start:i])
				start = i + 1
			}
		}
	}
	if strings.TrimSpace(s[start:]) != "" {
		result = append(result, s[start:])
	}
	return result
}

type dCandidate struct {
	name, field string
	values      map[string]bool
	pos         int
}

func dCandidates(source string) []dCandidate {
	var candidates []dCandidate
	for _, m := range dSwitch.FindAllStringSubmatchIndex(source, -1) {
		candidate := dCandidate{name: source[m[2]:m[3]], field: source[m[4]:m[5]], values: map[string]bool{}, pos: m[0]}
		for _, literal := range dLiteral.FindAllStringSubmatchIndex(source[m[6]:m[7]], -1) {
			candidate.values[dLiteralValue(source[m[6]:m[7]], literal)] = true
		}
		candidates = append(candidates, candidate)
	}
	for _, m := range dIncludes.FindAllStringSubmatchIndex(source, -1) {
		candidate := dCandidate{name: source[m[4]:m[5]], field: source[m[6]:m[7]], values: map[string]bool{}, pos: m[0]}
		array := source[m[2]:m[3]]
		for _, literal := range dLiteral.FindAllStringSubmatchIndex(array, -1) {
			candidate.values[dLiteralValue(array, literal)] = true
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func dLiteralValue(source string, m []int) string {
	if m[2] >= 0 {
		return source[m[2]:m[3]]
	}
	return source[m[4]:m[5]]
}
