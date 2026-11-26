package shellrules

import (
	"iter"
	"math"
	"slices"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// trapWords are the words of a trap command that sets or resets signals, as
// trap gets them; other commands have none. action is nil where the signals are reset by a command without
// an action. unbound marks a command with a word of braces past the bounds of
// trapReader.words, which may hold any signal.
type trapWords struct {
	action  *syntax.Word
	signals []*syntax.Word
	unbound bool
}

// readTrap reads the words of a trap command; trap is false for another command.
// Every rule reads them here. The signals are words, so a trap continued over a line
// break or with an action of several lines counts, and an EXIT or a 0 inside the
// action does not. A word counts by its value, quoted or not ("EXIT", E"XIT"). As
// in bash: the words are those bash makes of braces; trap may be called as
// builtin trap or command trap; a first operand of a dash and more is options,
// and trap with options prints or fails and sets nothing; a single operand, or a
// first operand that is the number of a signal, starts the signals to reset,
// otherwise the first operand is the action. A word bash expands at run time
// ("$sig") is not known. The operands are read only where they may name one of
// the signals of names, which the rule gives in lower case, or all without
// names.
func (r trapReader) readTrap(call *syntax.CallExpr, names ...string) (words trapWords, trap bool) {
	operands, trap := r.trapOperands(call, names)
	if len(operands) == 0 {
		return trapWords{}, trap
	}
	switch first := wordLit(operands[0]); {
	case first == "--":
		operands = operands[1:]
	case len(first) > 1 && first[0] == '-':
		return trapWords{}, true
	}
	if len(operands) == 0 {
		return trapWords{}, true
	}
	words = trapWords{signals: operands, unbound: slices.ContainsFunc(operands, unboundWord)}
	if n, number := signalNumber(wordLit(operands[0])); len(operands) > 1 && (!number || n > lastSignal) {
		words.action, words.signals = operands[0], operands[1:]
	}
	return words, true
}

// trapOperands returns the words after the name of a trap command, none where
// they cannot name one of names; ok is false for another command, whose words
// are built only up to its name and only where they may name trap.
func (r trapReader) trapOperands(call *syntax.CallExpr, names []string) (operands []*syntax.Word, ok bool) {
	args, _ := unprefixed(call.Args)
	if len(args) > 0 && braceText(args[0]) == 0 {
		if wordLit(args[0]) != "trap" {
			return nil, false
		}
		if len(names) > 0 && !mayName(args[1:], names) {
			return nil, true
		}
		return slices.Collect(r.words(args[1:])), true
	}
	if !mayName(call.Args, []string{"trap"}) {
		return nil, false
	}
	for w := range r.words(call.Args) {
		if ok {
			operands = append(operands, w)
			continue
		}
		switch wordLit(w) {
		case "trap":
			ok = true
		case "builtin", "command":
		default:
			return nil, false
		}
	}
	return operands, ok
}

// mayName reports whether the words may make one of the names, in any case.
// Brace expansion only puts pieces of their text together, and a word with
// another part, as a parameter, has no known value: a name with a letter their
// text lacks is none of their words. A range ({1..20}) and ANSI-C quoting
// ($'\x45') may make any letter.
func mayName(words []*syntax.Word, names []string) bool {
	var text [256]bool
	for _, w := range words {
		for _, part := range w.Parts {
			if !markText(&text, part) {
				return true
			}
		}
	}
	for _, name := range names {
		if !strings.ContainsFunc(name, func(c rune) bool { return !text[c] }) {
			return true
		}
	}
	return false
}

// markText marks the letters of a part in lower case; it is false for a part
// that may make letters it does not hold: a range, ANSI-C quoting.
func markText(text *[256]bool, part syntax.WordPart) bool {
	value := ""
	switch x := part.(type) {
	case *syntax.Lit:
		if strings.Contains(x.Value, "..") {
			return false
		}
		value = x.Value
	case *syntax.SglQuoted:
		if x.Dollar {
			return false
		}
		value = x.Value
	case *syntax.DblQuoted:
		for _, inner := range x.Parts {
			markText(text, inner)
		}
	}
	for i := range len(value) {
		c := value[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		text[c] = true
	}
	return true
}

// lastSignal is the number of the last signal, RTMAX.
const lastSignal = 64

// signalNumber reads a signal given by its number, as trap 0 or trap 00.
func signalNumber(s string) (uint64, bool) {
	n, err := strconv.ParseUint(s, 10, 0)
	return n, err == nil
}

// trapReader reads the words of trap commands of one script. braces is false in
// a script that turns brace expansion off; built, if set, sees each word the
// expander builds.
type trapReader struct {
	braces bool
	built  func(*syntax.Word)
}

// newTrapReader reads the words of the script. A script that turns brace
// expansion off anywhere gets its braces as text everywhere: bash takes them so
// from the moment it runs set +B, which is an order of running and not of text
// (a function, a loop, a sourced file), and a script that has its braces taken
// as text somewhere has them so read where bash may take them so.
func newTrapReader(file *syntax.File) trapReader {
	braces := true
	syntax.Walk(file, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok && setsBracesOff(call.Args) {
			braces = false
		}
		return braces
	})
	return trapReader{braces: braces}
}

// setsBracesOff reports whether the command is set +B or set +o braceexpand,
// alone or among other options.
func setsBracesOff(args []*syntax.Word) bool {
	args, _ = unprefixed(args)
	if len(args) == 0 || wordLit(args[0]) != "set" {
		return false
	}
	for i := 1; i < len(args); i++ {
		option := wordLit(args[i])
		switch {
		case option == "+o" || option == "-o":
			if i+1 < len(args) && option == "+o" && wordLit(args[i+1]) == "braceexpand" {
				return true
			}
			i++
		case option == "" || option == "-" || option == "--" || option[0] != '+' && option[0] != '-':
			return false
		case option[0] == '+' && strings.Contains(option, "B"):
			return true
		}
	}
	return false
}

// The bounds of what the braces of one command build. Bash has 65 signal
// numbers (0 to 64) and 66 names, 625 bytes as a list of the names with SIG, and
// a list of signals is one brace or a few of words of a few parts: what passes a
// bound is no list of signals. The braces and the text bound what SplitBraces
// reads, the words and their parts what the expander builds, and those are known
// before it runs.
const (
	maxBraces     = 8
	maxBraceText  = 1024
	maxBraceWords = 128
	maxBraceParts = 512
)

// words yields the words bash makes of the words of a command by brace
// expansion, which it does before any other: {EXIT,INT} is two words, and an
// unquoted empty element is none. A word whose braces pass the bounds is one
// word of unknown value, and the words are built as they are read.
func (r trapReader) words(words []*syntax.Word) iter.Seq[*syntax.Word] {
	return func(yield func(*syntax.Word) bool) {
		left := braceBudget{maxBraces, maxBraceText, maxBraceWords, maxBraceParts}
		for _, w := range words {
			for e := range r.wordsOf(w, &left) {
				if !yield(e) {
					return
				}
			}
		}
	}
}

// braceBudget is what is left of the bounds for the words of one command.
type braceBudget struct {
	braces, text, words, parts int
}

// wordsOf returns the words of one word within the budget: the word itself where
// it has no braces, one word of unknown value where they pass the bounds.
func (r trapReader) wordsOf(w *syntax.Word, left *braceBudget) iter.Seq[*syntax.Word] {
	text := braceText(w)
	if !r.braces || text == 0 {
		return single(w)
	}
	left.text -= text
	if left.text < 0 {
		return single(newUnboundWord())
	}
	split := &syntax.Word{Parts: w.Parts}
	if !syntax.SplitBraces(split) || !slices.ContainsFunc(split.Parts, isBraceExp) {
		return single(w)
	}
	left.braces -= countBraces(split)
	n, parts := braceSpan(split)
	if left.braces < 0 || n > left.words || parts > left.parts {
		return single(newUnboundWord())
	}
	left.words -= n
	left.parts -= parts
	return r.expandBraces(split, n)
}

func single(w *syntax.Word) iter.Seq[*syntax.Word] {
	return func(yield func(*syntax.Word) bool) {
		yield(w)
	}
}

// expandBraces yields the n words of a split word. As bash, a range stops at
// its end where the expander would overflow and go on, so the words stop at n.
// The expander errs past 16Ki words, which the bounds stop before; were it to
// err, the words would be past the bounds.
func (r trapReader) expandBraces(split *syntax.Word, n int) iter.Seq[*syntax.Word] {
	return func(yield func(*syntax.Word) bool) {
		for e, err := range expand.BracesSeq(nil, split) {
			if n == 0 {
				return
			}
			n--
			word := newUnboundWord()
			if err == nil {
				if r.built != nil {
					r.built(e)
				}
				word = &syntax.Word{Parts: slices.DeleteFunc(slices.Clone(e.Parts), emptyLit)}
			}
			if len(word.Parts) > 0 && !yield(word) {
				return
			}
		}
	}
}

func isBraceExp(part syntax.WordPart) bool {
	_, ok := part.(*syntax.BraceExp)
	return ok
}

// countBraces returns the number of braces in a split word, nested ones too.
func countBraces(w *syntax.Word) int {
	n := 0
	for _, part := range w.Parts {
		if br, ok := part.(*syntax.BraceExp); ok {
			n++
			for _, elem := range br.Elems {
				n += countBraces(elem)
			}
		}
	}
	return n
}

// braceText returns the size of what SplitBraces reads of a word with a brace
// in its unquoted text, an escaped one too: its parts and the bytes of that
// text; 0 for a word without.
func braceText(w *syntax.Word) int {
	size, braces := len(w.Parts), false
	for _, part := range w.Parts {
		if lit, ok := part.(*syntax.Lit); ok {
			size += len(lit.Value)
			braces = braces || strings.Contains(lit.Value, "{")
		}
	}
	if !braces {
		return 0
	}
	return size
}

// spanCap is past every bound: a span counts up to it.
const spanCap = 1 << 20

// braceSpan returns the number of words the expander builds of a split word and
// the number of their parts together, each up to spanCap.
func braceSpan(w *syntax.Word) (words, parts int) {
	words = 1
	for _, part := range w.Parts {
		n, p := 1, 1
		if br, ok := part.(*syntax.BraceExp); ok {
			n, p = elemsSpan(br)
		}
		words, parts = min(words*n, spanCap), min(parts*n+p*words, spanCap)
	}
	return words, parts
}

// elemsSpan returns the words and parts a brace adds: the words of its
// elements, or a word of one part for each number or letter of a range.
func elemsSpan(br *syntax.BraceExp) (words, parts int) {
	if br.Sequence {
		n := rangeLen(br)
		return n, n
	}
	for _, elem := range br.Elems {
		n, p := braceSpan(elem)
		words, parts = min(words+n, spanCap), min(parts+p, spanCap)
	}
	return words, parts
}

// rangeLen returns the number of words of a range as the expander reads it, up
// to spanCap: of numbers, or else of letters, and of a step that is a number,
// as SplitBraces keeps only those; a step of 0 is 1, and its sign does not
// count. As bash, a range does not go past its end where a number would
// overflow, and a step bash cannot negate leaves no range, which the expander
// would run on.
func rangeLen(br *syntax.BraceExp) int {
	fromLit, toLit := br.Elems[0].Lit(), br.Elems[1].Lit()
	from, err1 := strconv.ParseInt(fromLit, 10, 64)
	to, err2 := strconv.ParseInt(toLit, 10, 64)
	if err1 != nil || err2 != nil {
		from, to = int64(fromLit[0]), int64(toLit[0])
	}
	distance := uint64(to) - uint64(from)
	if from > to {
		distance = uint64(from) - uint64(to)
	}
	step := uint64(1)
	if len(br.Elems) > 2 {
		step = 0
		if n, err := strconv.ParseInt(br.Elems[2].Lit(), 10, 64); err == nil && n != math.MinInt64 {
			step = uint64(max(n, -n, 1))
		}
	}
	if step == 0 {
		return spanCap
	}
	return int(min(distance/step+1, spanCap))
}

// newUnboundWord is the word for braces past the bounds: a brace expansion left
// in place, which no word of a parsed script holds.
func newUnboundWord() *syntax.Word {
	return &syntax.Word{Parts: []syntax.WordPart{&syntax.BraceExp{}}}
}

// unboundWord reports whether the word is one bracedWords did not build: it stands
// for any words.
func unboundWord(w *syntax.Word) bool {
	return slices.ContainsFunc(w.Parts, func(part syntax.WordPart) bool {
		_, ok := part.(*syntax.BraceExp)
		return ok
	})
}

// emptyLit reports whether the part is unquoted empty text, as the expander
// leaves beside a brace.
func emptyLit(part syntax.WordPart) bool {
	lit, ok := part.(*syntax.Lit)
	return ok && lit.Value == ""
}
