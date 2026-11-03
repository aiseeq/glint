package patternkit

import "sort"

// JsBrackets pairs the brackets of a code view in one pass from left to
// right, so a rule that asks about every call or object of a minified file
// does not walk the same nested code again for each of them. '(', '[' and '{'
// nest together, as in JsFlat.Closing.
type JsBrackets struct {
	opens       []jsOpen // in the order of their offsets
	openByClose map[int]int
	closed      []jsClosed
}

// JsBrace is an opening brace in source order.
type JsBrace struct{ Open int }

type jsOpen struct {
	pos   int
	kind  byte // '(', '[' or '{'
	close int  // offset of the closer, -1 when the code ends first
	// firstEnd is where the first item ends: the first comma of the
	// bracket's own level, else the closer, else the end of the code.
	firstEnd int
	// semicolon is the first ';' of the bracket's own level, -1 for none.
	semicolon int
	// outer is the index of the nearest enclosing '(' or '{', passing over
	// enclosing '[', -1 at the top level.
	outer int
}

type jsClosed struct{ close, open int }

// NewJsBrackets indexes the brackets of code.
func NewJsBrackets(code string) *JsBrackets {
	b := &JsBrackets{}
	var stack []int
	for i := 0; i < len(code); i++ {
		switch c := code[i]; c {
		case '(', '[', '{':
			outer := -1
			if len(stack) > 0 {
				outer = stack[len(stack)-1]
				if b.opens[outer].kind == '[' {
					outer = b.opens[outer].outer
				}
			}
			stack = append(stack, len(b.opens))
			b.opens = append(b.opens, jsOpen{pos: i, kind: c, close: -1, firstEnd: -1, semicolon: -1, outer: outer})
		case ')', ']', '}':
			if len(stack) == 0 {
				continue
			}
			o := &b.opens[stack[len(stack)-1]]
			stack = stack[:len(stack)-1]
			o.close = i
			if o.kind == '(' {
				b.closed = append(b.closed, jsClosed{close: i, open: o.pos})
			}
			if b.openByClose == nil {
				b.openByClose = make(map[int]int)
			}
			b.openByClose[i] = o.pos
			if o.firstEnd < 0 {
				o.firstEnd = i
			}
		case ',', ';':
			if len(stack) == 0 {
				continue
			}
			o := &b.opens[stack[len(stack)-1]]
			if c == ',' && o.firstEnd < 0 {
				o.firstEnd = i
			}
			if c == ';' && o.semicolon < 0 {
				o.semicolon = i
			}
		}
	}
	for _, i := range stack {
		if b.opens[i].firstEnd < 0 {
			b.opens[i].firstEnd = len(code)
		}
	}
	return b
}

// Opening returns the offset of the bracket paired with close.
func (b *JsBrackets) Opening(close int) (int, bool) {
	open, ok := b.openByClose[close]
	return open, ok
}

// OpeningBefore returns the opening parenthesis paired with the last ')'
// before pos.
func (b *JsBrackets) OpeningBefore(pos int) (int, bool) {
	i := sort.Search(len(b.closed), func(i int) bool { return b.closed[i].close >= pos }) - 1
	if i < 0 {
		return 0, false
	}
	return b.closed[i].open, true
}

// Braces returns the brace pairs indexed by NewJsBrackets, in source order.
func (b *JsBrackets) Braces() []JsBrace {
	out := make([]JsBrace, 0)
	for _, o := range b.opens {
		if o.kind == '{' {
			out = append(out, JsBrace{Open: o.pos})
		}
	}
	return out
}

// index returns the index of the opener at pos.
func (b *JsBrackets) index(pos int) (int, bool) {
	i := sort.Search(len(b.opens), func(i int) bool { return b.opens[i].pos >= pos })
	return i, i < len(b.opens) && b.opens[i].pos == pos
}

// Closing returns the offset of the bracket that closes the one at open, as
// JsFlat.Closing does.
func (b *JsBrackets) Closing(open int) (int, bool) {
	i, ok := b.index(open)
	if !ok || b.opens[i].close < 0 {
		return 0, false
	}
	return b.opens[i].close, true
}

// FirstItemEnd returns where the first item inside the bracket at open ends:
// the first comma of its own level, its closer, or the end of the code when
// it is not closed. It is the end of a call's first argument.
func (b *JsBrackets) FirstItemEnd(open int) int {
	i, ok := b.index(open)
	if !ok {
		return open
	}
	return b.opens[i].firstEnd
}

// EnclosingParen returns the '(' whose arguments hold the bracket at open,
// passing over enclosing array brackets and over whole bracketed arguments
// before it: the call of f({ a }, [{ b }]) holds both objects. A '{' around
// the bracket, or a ';' of the parenthesis's own level before it, means the
// bracket is in no argument list.
func (b *JsBrackets) EnclosingParen(open int) (int, bool) {
	i, ok := b.index(open)
	if !ok || b.opens[i].outer < 0 {
		return 0, false
	}
	o := b.opens[b.opens[i].outer]
	if o.kind != '(' || o.semicolon >= 0 && o.semicolon < open {
		return 0, false
	}
	return o.pos, true
}
