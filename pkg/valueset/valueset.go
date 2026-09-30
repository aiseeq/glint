// Package valueset collects the sets of string values a project spells out
// by hand — the constants of a Go string type, a TypeScript union or enum,
// the members of a list literal, the keys of a map or object literal, the
// labels of a switch — so that rules can find two copies of one set that
// drifted apart.
package valueset

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// Kind tells a declared set from one spelled out in the code.
type Kind int

const (
	// Enum is a declared set: the string constants of a Go type, a TS union
	// of string literals, a TS enum.
	Enum Kind = iota
	// List is a set spelled out as such: a list literal, the keys of a
	// membership map (map[string]bool).
	List
	// Keyed is a set of values each given its own behaviour: the keys or
	// values of an object literal, the labels of a switch. A project keeps
	// one per value set on purpose (a label, a colour, a handler for each).
	Keyed
)

// Set is a set of string values written in one place.
type Set struct {
	Path string // relative to the project root
	Line int
	// Name is the declared type or the variable the set is assigned to;
	// empty for a switch or an unnamed literal.
	Name string
	Kind Kind
	Go   bool
	// Switch is a switch's labels: a switch handles some values of a set
	// and leaves the rest to its default on purpose.
	Switch  bool
	Members []string // sorted, unique
}

// MinMembers is the least number of members a set needs to be collected: two
// values match by chance too often.
const MinMembers = 3

// member is a value that names something (a status, a network, a currency):
// a word, not a sentence, a path or a format.
var member = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,39}$`)

func newSet(path string, line int, name string, kind Kind, isGo bool, values []string) (Set, bool) {
	for _, v := range values {
		if !member.MatchString(v) {
			return Set{}, false
		}
	}
	values = slices.Clone(values)
	slices.Sort(values)
	values = slices.Compact(values)
	if len(values) < MinMembers {
		return Set{}, false
	}
	return Set{Path: path, Line: line, Name: name, Kind: kind, Go: isGo, Members: values}, true
}

// Extract returns the sets written in a Go or TS/JS file.
func Extract(ctx *core.FileContext) []Set {
	switch {
	case ctx.IsGoFile() && ctx.GoAST != nil:
		return extractGo(ctx)
	case ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile():
		return extractJS(ctx)
	}
	return nil
}

func extractGo(ctx *core.FileContext) []Set {
	g := &goSets{ctx: ctx, names: make(map[*ast.CompositeLit]string), nested: make(map[*ast.CompositeLit]bool)}
	g.enums()
	ast.Inspect(ctx.GoAST, g.visit)
	return g.sets
}

// goSets gathers the sets of a Go file.
type goSets struct {
	ctx    *core.FileContext
	sets   []Set
	names  map[*ast.CompositeLit]string // the variable a literal is assigned to
	nested map[*ast.CompositeLit]bool   // a literal inside another: a row of a table
}

func (g *goSets) add(node ast.Node, name string, kind Kind, values []string) *Set {
	set, ok := newSet(g.ctx.RelPath, g.ctx.LineFor(node), name, kind, true, values)
	if !ok {
		return nil
	}
	g.sets = append(g.sets, set)
	return &g.sets[len(g.sets)-1]
}

// enums adds the constants of each type, gathered over the file's
// declarations. A typed constant belongs to its type; an untyped one to the
// group its name starts with in its declaration: WithdrawalStatusPending to
// WithdrawalStatus.
func (g *goSets) enums() {
	values := make(map[string][]string)
	at := make(map[string]ast.Node)
	var order []string
	for _, decl := range g.ctx.GoAST.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != len(vs.Values) {
				continue
			}
			for i, value := range vs.Values {
				s, ok := goString(value)
				key := constGroup(gen, vs, i)
				if !ok || key == "" {
					continue
				}
				if _, seen := at[key]; !seen {
					at[key] = vs
					order = append(order, key)
				}
				values[key] = append(values[key], s)
			}
		}
	}
	for _, key := range order {
		name, _, _ := strings.Cut(key, "\x00")
		g.add(at[key], name, Enum, values[key])
	}
}

// constGroup is the set the i-th constant of a spec belongs to: its type, or
// the prefix of its name within its declaration.
func constGroup(gen *ast.GenDecl, vs *ast.ValueSpec, i int) string {
	if vs.Type != nil {
		return goTypeName(vs.Type)
	}
	prefix := namePrefix(vs.Names[i].Name)
	if prefix == "" {
		return ""
	}
	return fmt.Sprintf("%s\x00%d", prefix, gen.Pos())
}

func (g *goSets) visit(n ast.Node) bool {
	switch n := n.(type) {
	case *ast.AssignStmt:
		if len(n.Lhs) == len(n.Rhs) {
			for i, rhs := range n.Rhs {
				if lit, ok := ast.Unparen(rhs).(*ast.CompositeLit); ok {
					g.names[lit] = goExprName(n.Lhs[i])
				}
			}
		}
	case *ast.ValueSpec:
		if len(n.Names) == len(n.Values) {
			for i, rhs := range n.Values {
				if lit, ok := ast.Unparen(rhs).(*ast.CompositeLit); ok {
					g.names[lit] = n.Names[i].Name
				}
			}
		}
	case *ast.CompositeLit:
		g.literal(n)
	case *ast.SwitchStmt:
		var labels []string
		for _, stmt := range n.Body.List {
			clause, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expr := range clause.List {
				if s, ok := goString(expr); ok {
					labels = append(labels, s)
				}
			}
		}
		if set := g.add(n, "", Keyed, labels); set != nil {
			set.Switch = true
		}
	}
	return true
}

// literal adds a list literal of strings, or the keys of a membership map
// (map[string]bool, map[string]struct{}); the keys of any other map are as
// often a record's fields. A literal inside another is a row of a data table
// and is not a set.
func (g *goSets) literal(n *ast.CompositeLit) {
	for _, elt := range n.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			elt = kv.Value
		}
		if inner, ok := ast.Unparen(elt).(*ast.CompositeLit); ok {
			g.nested[inner] = true
		}
	}
	if g.nested[n] {
		return
	}
	mapType, isMap := n.Type.(*ast.MapType)
	if isMap && !membershipValue(mapType.Value) {
		return
	}
	var members []string
	for _, elt := range n.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok && isMap {
			elt = kv.Key
		}
		s, ok := goString(elt)
		if !ok {
			return
		}
		members = append(members, s)
	}
	g.add(n, g.names[n], List, members)
}

// namePrefix is a constant's name without its last word:
// WithdrawalStatusPending gives WithdrawalStatus; a name of one word gives "".
func namePrefix(name string) string {
	for i := len(name) - 1; i > 0; i-- {
		if name[i] >= 'A' && name[i] <= 'Z' {
			return name[:i]
		}
	}
	return ""
}

func membershipValue(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "bool"
	case *ast.StructType:
		return len(e.Fields.List) == 0
	}
	return false
}

func goString(expr ast.Expr) (string, bool) {
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

func goTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		if e.Name == "string" {
			return ""
		}
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

func goExprName(expr ast.Expr) string {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

var (
	jsString    = `(?:'[^'\n\\]*'|"[^"\n\\]*")`
	jsUnion     = regexp.MustCompile(`\btype\s+([A-Za-z_$][\w$]*)\s*=\s*\|?\s*(` + jsString + `(?:\s*\|\s*` + jsString + `)+)\s*(?:;|\n|$)`)
	jsEnum      = regexp.MustCompile(`\benum\s+([A-Za-z_$][\w$]*)\s*\{([^{}]*)\}`)
	jsEnumValue = regexp.MustCompile(`=\s*(` + jsString + `)`)
	jsArray     = regexp.MustCompile(`\[\s*(` + jsString + `(?:\s*,\s*` + jsString + `)+)\s*,?\s*\]`)
	jsStrings   = regexp.MustCompile(jsString)
	jsAssigned  = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*(?::[^=;\n]*)?=\s*$`)
	jsObject    = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]*)?=\s*\{`)
	jsEntry     = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*|` + jsString + `|\d+)\s*:\s*([\s\S]*?)\s*$`)
	jsSwitch    = regexp.MustCompile(`\bswitch\s*\(`)
	typedRecord = regexp.MustCompile(`:\s*(?:Partial\s*<\s*)?Record\s*<\s*(?:[A-Z][\w$]*|[\w$]+\[)`)
	jsNumber    = regexp.MustCompile(`^\d+$`)
	jsScalar    = regexp.MustCompile(`^(?:-?\d[\d_.]*|true|false|null)$`)
	jsCase      = regexp.MustCompile(`\bcase\s+(` + jsString + `)\s*:`)
)

func extractJS(ctx *core.FileContext) []Set {
	text := strings.Join(helpers.FileJSText(ctx), "\n")
	code := strings.Join(helpers.FileJSCode(ctx), "\n")
	lineAt := lineIndex(text)
	var sets []Set
	add := func(offset int, name string, kind Kind, values []string) {
		if set, ok := newSet(ctx.RelPath, lineAt(offset), name, kind, false, values); ok {
			sets = append(sets, set)
		}
	}
	unions, enums := strings.Contains(code, "type "), strings.Contains(code, "enum ")
	for _, m := range jsMatches(jsUnion, text, unions) {
		add(m[0], text[m[2]:m[3]], Enum, unquoteAll(jsStrings.FindAllString(text[m[4]:m[5]], -1)))
	}
	for _, m := range jsMatches(jsEnum, text, enums) {
		var values []string
		for _, v := range jsEnumValue.FindAllStringSubmatch(text[m[4]:m[5]], -1) {
			values = append(values, unquote(v[1]))
		}
		add(m[0], text[m[2]:m[3]], Enum, values)
	}
	for _, m := range jsArray.FindAllStringSubmatchIndex(text, -1) {
		name := ""
		// The name is right before the list: look back a line's length, not
		// over the whole file for every list.
		if a := jsAssigned.FindStringSubmatch(text[max(0, m[0]-maxDeclaration):m[0]]); a != nil {
			name = a[1]
		}
		add(m[0], name, List, unquoteAll(jsStrings.FindAllString(text[m[2]:m[3]], -1)))
	}
	for _, m := range jsObject.FindAllStringSubmatchIndex(code, -1) {
		open := m[1] - 1
		end := matchingBrace(code, open)
		if end < 0 {
			continue
		}
		keys, values, ok := objectEntries(code[open+1:end], text[open+1:end])
		if !ok {
			continue
		}
		if typedRecord.MatchString(code[m[0]:m[1]]) {
			continue // Record<Union, V>: the compiler keeps its keys to the union
		}
		name := code[m[2]:m[3]]
		add(m[0], name, Keyed, keys)
		add(m[0], name, Keyed, values)
	}
	for _, m := range jsSwitch.FindAllStringIndex(code, -1) {
		open := strings.IndexByte(code[m[1]:], '{')
		if open < 0 {
			continue
		}
		open += m[1]
		end := matchingBrace(code, open)
		if end < 0 {
			continue
		}
		var labels []string
		for _, c := range jsCase.FindAllStringSubmatchIndex(text[open:end], -1) {
			if braceDepth(code[open:open+c[0]]) == 1 {
				labels = append(labels, unquote(text[open+c[2]:open+c[3]]))
			}
		}
		if set, ok := newSet(ctx.RelPath, lineAt(m[0]), "", Keyed, false, labels); ok {
			set.Switch = true
			sets = append(sets, set)
		}
	}
	return sets
}

// maxDeclaration is how far back from a list its declaration is looked for:
// const NAME: Type = [
const maxDeclaration = 200

func jsMatches(re *regexp.Regexp, text string, present bool) [][]int {
	if !present {
		return nil
	}
	return re.FindAllStringSubmatchIndex(text, -1)
}

// objectEntries returns the keys and, when every value is a string literal,
// the values of an object literal's body; false when an entry is anything
// but key: value (a spread, a method, a shorthand) or a value is not a
// literal - such an object is a record, and its keys are fields.
func objectEntries(code, text string) ([]string, []string, bool) {
	var keys, values []string
	valuesOK := true
	depth, start := 0, 0
	split := func(end int) bool {
		entryCode, entryText := code[start:end], text[start:end]
		start = end + 1
		if strings.TrimSpace(entryCode) == "" {
			return true
		}
		m := jsEntry.FindStringSubmatchIndex(entryCode)
		if m == nil {
			return false
		}
		if key := unquote(entryText[m[2]:m[3]]); !jsNumber.MatchString(key) {
			keys = append(keys, key)
		}
		value := strings.TrimSpace(entryText[m[4]:m[5]])
		switch {
		case value != "" && jsStrings.FindString(value) == value:
			values = append(values, unquote(value))
		case jsScalar.MatchString(value):
			valuesOK = false
		default:
			return false
		}
		return true
	}
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '{', '(', '[':
			depth++
		case '}', ')', ']':
			depth--
		case ',':
			if depth == 0 && !split(i) {
				return nil, nil, false
			}
		}
	}
	if !split(len(code)) {
		return nil, nil, false
	}
	if !valuesOK {
		values = nil
	}
	return keys, values, true
}

func matchingBrace(code string, open int) int {
	depth := 0
	for i := open; i < len(code); i++ {
		switch code[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func braceDepth(code string) int {
	return strings.Count(code, "{") - strings.Count(code, "}")
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') {
		return s[1 : len(s)-1]
	}
	return s
}

func unquoteAll(list []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, unquote(s))
	}
	return out
}

func lineIndex(text string) func(int) int {
	var starts []int
	starts = append(starts, 0)
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return func(offset int) int {
		i, found := slices.BinarySearch(starts, offset)
		if found {
			return i + 1
		}
		return i
	}
}

// Index is every set of a project, with the sets each value is a member of.
type Index struct {
	Sets     []Set
	byMember map[string][]int
}

// NewIndex indexes the sets.
func NewIndex(sets []Set) *Index {
	slices.SortFunc(sets, func(a, b Set) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Line, b.Line))
	})
	idx := &Index{Sets: sets, byMember: make(map[string][]int)}
	for i, set := range sets {
		for _, m := range set.Members {
			idx.byMember[m] = append(idx.byMember[m], i)
		}
	}
	return idx
}

// Overlapping returns the other sets sharing at least min members with set,
// with the number shared.
func (idx *Index) Overlapping(set Set, minShared int) map[int]int {
	shared := make(map[int]int)
	for _, m := range set.Members {
		for _, i := range idx.byMember[m] {
			other := idx.Sets[i]
			if other.Path == set.Path && other.Line == set.Line && slices.Equal(other.Members, set.Members) {
				continue
			}
			shared[i]++
		}
	}
	for i, n := range shared {
		if n < minShared {
			delete(shared, i)
		}
	}
	return shared
}

type setsKey struct{}

// FileSets is Extract of a file, done once per file for every rule that asks.
// The result must not be modified.
func FileSets(ctx *core.FileContext) []Set {
	return core.FileShared(ctx, setsKey{}, func() []Set { return Extract(ctx) })
}

// IndexFiles indexes the sets of a project's files. Test files and browser
// tests are left out: they spell out the values they expect, and a copy
// there is not one anyone keeps in step.
func IndexFiles(files []*core.FileContext) *Index {
	var kept []*core.FileContext
	for _, file := range files {
		if !file.IsTestFile() && !strings.Contains("/"+filepath.ToSlash(file.RelPath), "/e2e/") {
			kept = append(kept, file)
		}
	}
	perFile := make([][]Set, len(kept))
	var wg sync.WaitGroup
	next := make(chan int)
	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				perFile[i] = FileSets(kept[i])
			}
		}()
	}
	for i := range kept {
		next <- i
	}
	close(next)
	wg.Wait()
	var sets []Set
	for _, fileSets := range perFile {
		sets = append(sets, fileSets...)
	}
	return NewIndex(sets)
}
