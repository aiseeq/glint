package patternkit

import (
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// jsFunctionsAgree compares JsFunctions with FunctionAtBrace on every '{'.
func jsFunctionsAgree(t *testing.T, code string) {
	t.Helper()
	f := JsFlat{Code: code}
	index := f.Functions()
	for i := 0; i < len(code); i++ {
		if code[i] != '{' {
			continue
		}
		want, wantOK := f.FunctionAtBrace(i)
		got, gotOK := index.AtBrace(i)
		if want != got || wantOK != gotOK {
			head, _ := f.Header(i)
			t.Fatalf("brace %d of %q (header %q): FunctionAtBrace %+v %v, Functions %+v %v", i, code, head, want, wantOK, got, gotOK)
		}
	}
}

func TestJsFunctionsHeaders(t *testing.T) {
	for _, code := range []string{
		"function pair(o: O): [number, number] {",
		"function f(o): (number | null)[] {",
		"class C { [Symbol.iterator]() { return 1 } }",
		"const g = function* () {",
		"function load(o){return __awaiter(this,void 0,void 0,function*(){const v=1})}",
		"const f = (o) =>\f{",
		"const f = (o) =>\u00a0{",
		"async function f(o): Promise<[number, number]> {",
		"class C { 'calc-total'(o) {",
		"function café(o) {",
		"function f(o): Promise<(number | null)> {",
		"if (a) { } else if (b) { } else { } for (;;) { } while (x) { } switch (y) { } try { } catch (e) { } finally { } do { } with (o) {",
		"const a = (b = (c = () => {}) => {}) => {",
		"x: (e) => {",
		"const total: Fn = async (a, b): Promise<number> => {",
		"a: b: c => {",
		"const f = async x => {",
		"const f = async$x => {",
		"let f = async => {",
		"static async get<T extends Item>(id: string): Promise<T> {",
		"get value() {",
		"export default function () {",
		"function\nfunctionfoo(x){",
		"f(a) ) {",
		"[ ( ] {",
		"x = { a: (o) => { return 1 } }",
		"`${(a) => {}}`",
	} {
		jsFunctionsAgree(t, code)
	}
}

var jsFunctionsTokens = []string{
	"function", "function*", "function ", "async", "async ", "const ", "let ", "var ", "export ", "default ",
	"get ", "set ", "static ", "readonly ", "public ", "override ",
	"if", "if ", "else", "else ", "try", "do", "for", "while ", "catch", "with", "switch", "finally", "format",
	"=>", "=", "==", ":", ": ", "(", ")", "[", "]", "{", "}", "<", ">", ";", ",", ".", "*", "?", "'", "\"", "`", "/",
	"\n", " ", " ", "  ", "\t", "\f", "\v", "\r", "\u00a0", "\u2028", "\u0085", "\xc2", "\xa0", "\xff", "é",
	"$", "_", "a", "b", "x", "o", "0", "1", "x1", "T", "Promise",
}

// jsHeaderTokens lean toward the pieces of method and arrow binding headers.
var jsHeaderTokens = []string{
	"const ", "let ", "export ", "static ", "async ", "get ", "readonly ", "async", "a", "b", "x$", "async$",
	" ", " ", "\t", "\n", ":", ":", " = ", "=", "=>", " => ", "(", ")", "(a)", "(a, b)", "()", "<T>", "<", ">",
	"{", "}", ";", ",", "[", "]", "?", "\u00a0", "\f", "function ", "*",
}

// jsBindingSlots build arrow binding and method headers slot by slot, each
// slot picked from its choices, the first of which is often empty.
var jsBindingSlots = [][]string{
	{"", "", "(", "x;", "a, ", "{", "a: 1, "},
	{"", "", "export ", "const ", "export const ", "static readonly ", "let let ", "async ", "get ", "static async "},
	{"a", "x$", "const", "async", "get", "_b1", "$"},
	{"", "", " ", "<T>", " <T, U>", "<(T)>"},
	{"", "", " ", ": T", ": (a) => b ", ":", ": a: b ", ": {a: b}", ": a<b> "},
	{"=", ":", " = ", " : ", "=="},
	{"", "", " ", "async ", "async", "async$", "\n"},
	{"(a)", "()", "(a, b: T)", "a", "b$", "(a) => (b)", "(", ")", "(a: T): U", "x :"},
	{"", "", " ", ": T ", ":", ": (a)", " = 1", "(b)", ")"},
	{"=>", " =>", "=> ", "=>\f", ")", "", "=>\u00a0"},
	{"{", " {", "{}", "{ a }"},
}

func randomJsCode(rng *rand.Rand, size int) string {
	if rng.Intn(3) == 0 {
		var b strings.Builder
		for range 1 + rng.Intn(3) {
			for _, slot := range jsBindingSlots {
				b.WriteString(slot[rng.Intn(len(slot))])
			}
			if rng.Intn(2) == 0 {
				b.WriteString(jsHeaderTokens[rng.Intn(len(jsHeaderTokens))])
			}
		}
		return b.String()
	}
	tokens := jsFunctionsTokens
	if rng.Intn(2) == 0 {
		tokens = jsHeaderTokens
	}
	var b strings.Builder
	for range size {
		b.WriteString(tokens[rng.Intn(len(tokens))])
	}
	return b.String()
}

func TestJsFunctionsMatchesFunctionAtBrace(t *testing.T) {
	cases := 20000
	if n, err := strconv.Atoi(os.Getenv("GLINT_JS_FUNCTIONS_CASES")); err == nil {
		cases = n
	}
	seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(seed))
	t.Logf("seed %d", seed)
	for range cases {
		jsFunctionsAgree(t, randomJsCode(rng, 1+rng.Intn(40)))
	}
}

// The work per brace does not grow with the header: each brace of a nested
// group has the whole group in its header.
func TestJsFunctionsNestedHeadersStayLinear(t *testing.T) {
	for _, unit := range []string{" f(x){})", " formatX{})", " x = (y) => {})", " a: (y) => {})", " function g(y){})"} {
		code := ""
		for range 20000 {
			code = "(" + code
		}
		code += strings.Repeat(unit, 20000)
		start := time.Now()
		index := JsFlat{Code: code}.Functions()
		for i := 0; i < len(code); i++ {
			if code[i] == '{' {
				index.AtBrace(i)
			}
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("%q nested 20000 deep took %s", unit, elapsed)
		}
	}
}
