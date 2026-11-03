package patternkit

import (
	"math/rand"
	"testing"
)

// JsBrackets.Closing agrees with JsFlat.Closing on every opener, balanced or
// not.
func TestJsBracketsClosingMatchesFlat(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("([{}]),;a ")
	for range 2000 {
		code := make([]byte, rng.Intn(40))
		for i := range code {
			code[i] = alphabet[rng.Intn(len(alphabet))]
		}
		f := JsFlat{Code: string(code)}
		b := NewJsBrackets(f.Code)
		for i, c := range code {
			if c != '(' && c != '[' && c != '{' {
				continue
			}
			want, wantOK := f.Closing(i)
			got, gotOK := b.Closing(i)
			if want != got || wantOK != gotOK {
				t.Fatalf("Closing(%d) of %q: JsFlat %d %v, JsBrackets %d %v", i, code, want, wantOK, got, gotOK)
			}
		}
	}
}

func TestJsBracketsOpeningMatchesClosing(t *testing.T) {
	code := "f((a), [b], {c})"
	b := NewJsBrackets(code)
	for open, c := range []byte(code) {
		if c != '(' && c != '[' && c != '{' {
			continue
		}
		close, ok := b.Closing(open)
		if !ok {
			continue
		}
		got, gotOK := b.Opening(close)
		if !gotOK || got != open {
			t.Errorf("Opening(%d) = %d, %v; want %d", close, got, gotOK, open)
		}
	}
}

func TestJsBracketsFirstItemEnd(t *testing.T) {
	for _, tc := range []struct {
		code string
		open int
		want string
	}{
		{"f(a, b)", 1, "a"},
		{"f(g(a, b), c)", 1, "g(a, b)"},
		{"f(ok ? () => { go(); } : m)", 1, "ok ? () => { go(); } : m"},
		{"f(a; b", 1, "a; b"},
		{"f()", 1, ""},
	} {
		if got := tc.code[tc.open+1 : NewJsBrackets(tc.code).FirstItemEnd(tc.open)]; got != tc.want {
			t.Errorf("first item of %q = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestJsBracketsEnclosingParen(t *testing.T) {
	for _, tc := range []struct {
		code string
		want int // offset of the '(' around the last '{', -1 for none
	}{
		{"f({ a })", 1},
		{"f({ a }, { b })", 1},
		{"f(() => { g() }, { b })", 1},
		{"f([{ a }, { b }], { c })", 1},
		{"f(a, [{ b }])", 1},
		{"x = { a: { b } }", -1},
		{"{ f(a); { b } }", -1},
		{"for (a; b; { c })", -1},
		{"{ b }", -1},
	} {
		last := -1
		for i := range tc.code {
			if tc.code[i] == '{' {
				last = i
			}
		}
		got, ok := NewJsBrackets(tc.code).EnclosingParen(last)
		if !ok {
			got = -1
		}
		if got != tc.want {
			t.Errorf("EnclosingParen of the last '{' in %q = %d, want %d", tc.code, got, tc.want)
		}
	}
}
