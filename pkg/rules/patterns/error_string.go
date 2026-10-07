package patterns

import (
	"go/ast"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewErrorStringRule())
}

// ErrorStringRule detects error strings that don't follow Go conventions.
//
// Go Code Review Comments allow a proper noun at the start ("Bridgo quote %s:
// %w"). A capitalised first word is taken for one when the package spells it
// as the lead word of a package-level type, variable or constant name
// (BridgoQuote, bridgoClient), capitalised in the middle of a comment sentence
// ("quotes come from Bridgo"), or when the proper_nouns setting lists it.
// Common error openers (Failed, Invalid, Unable…) never count as proper nouns.
type ErrorStringRule struct {
	*rules.BaseRule
	properNouns map[string]bool
	// packageNouns holds the proper nouns of each package of the analyzed
	// root, keyed by errorStringPackageKey.
	packageNouns map[string]map[string]bool
}

// NewErrorStringRule creates the rule
func NewErrorStringRule() *ErrorStringRule {
	return &ErrorStringRule{
		BaseRule: rules.NewBaseRule(
			"error-string",
			"patterns",
			"Error strings should not be capitalized or end with punctuation (Go convention)",
			core.SeverityLow,
		),
	}
}

// Configure reads the proper_nouns list.
func (r *ErrorStringRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	nouns, _, err := rules.NameSetSetting(settings, r.Name(), "proper_nouns")
	if err != nil {
		return err
	}
	r.properNouns = nouns
	return nil
}

// ResetState drops the proper nouns of the previous root.
func (r *ErrorStringRule) ResetState() { r.packageNouns = nil }

// UseProjectFiles collects the proper nouns every package of the root spells.
func (r *ErrorStringRule) UseProjectFiles(files []*core.FileContext) {
	nouns := map[string]map[string]bool{}
	for _, ctx := range files {
		if !ctx.IsGoFile() || !ctx.HasGoAST() {
			continue
		}
		key := errorStringPackageKey(ctx)
		if nouns[key] == nil {
			nouns[key] = map[string]bool{}
		}
		collectProperNouns(ctx.GoAST, nouns[key])
	}
	r.packageNouns = nouns
}

func errorStringPackageKey(ctx *core.FileContext) string {
	return filepath.Dir(ctx.Path) + "\x00" + ctx.GoAST.Name.Name
}

// errorOpeners are the capitalised words error strings start with that are
// plain English, whatever identifiers the package declares with them.
var errorOpeners = map[string]bool{
	"A": true, "An": true, "The": true, "This": true, "That": true, "It": true, "No": true, "Not": true,
	"Failed": true, "Fail": true, "Failure": true, "Invalid": true, "Unable": true, "Cannot": true, "Can": true,
	"Could": true, "Error": true, "Missing": true, "Unknown": true, "Unexpected": true, "Unsupported": true,
	"Empty": true, "Bad": true, "Wrong": true, "Expected": true, "Must": true, "Required": true, "Duplicate": true,
	"Already": true, "Malformed": true, "Incorrect": true, "Insufficient": true, "Illegal": true, "Too": true,
	"Timeout": true, "Timed": true, "Unauthorized": true, "Forbidden": true, "Denied": true, "Something": true,
	"Nothing": true, "Undefined": true, "Exceeded": true, "Cancelled": true, "Canceled": true,
}

// midSentenceCapital matches a capitalised word after a lower-case word of a
// sentence: "quotes come from Bridgo".
var midSentenceCapital = regexp.MustCompile(`[a-z,] +([A-Z][a-z]+)\b`)

// collectProperNouns adds to nouns the lead words of the file's package-level
// type, variable and constant names and the words its comments capitalise in
// the middle of a sentence.
func collectProperNouns(file *ast.File, nouns map[string]bool) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			switch spec := spec.(type) {
			case *ast.TypeSpec:
				addLeadWord(spec.Name.Name, nouns)
			case *ast.ValueSpec:
				for _, name := range spec.Names {
					addLeadWord(name.Name, nouns)
				}
			}
		}
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			for _, match := range midSentenceCapital.FindAllStringSubmatch(comment.Text, -1) {
				nouns[match[1]] = true
			}
		}
	}
}

// addLeadWord records the first camelCase word of a name, capitalised:
// bridgoClient and BridgoQuote both give Bridgo.
func addLeadWord(name string, nouns map[string]bool) {
	words := helpers.IdentifierWords(name)
	if len(words) == 0 || len(words[0]) < 2 {
		return
	}
	first, size := utf8.DecodeRuneInString(words[0])
	nouns[string(unicode.ToUpper(first))+words[0][size:]] = true
}

var errorFuncs = map[string]bool{
	"errors.New": true,
	"fmt.Errorf": true,
}

// AnalyzeFile checks error string formatting
func (r *ErrorStringRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	nouns := r.packageNouns[errorStringPackageKey(ctx)]
	if nouns == nil {
		nouns = map[string]bool{}
		collectProperNouns(ctx.GoAST, nouns)
	}

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if vs := r.checkCall(ctx, n, nouns); len(vs) > 0 {
			violations = append(violations, vs...)
		}
		return true
	})

	return violations
}

func (r *ErrorStringRule) checkCall(ctx *core.FileContext, n ast.Node, nouns map[string]bool) []*core.Violation {
	call, ok := n.(*ast.CallExpr)
	if !ok || !r.isErrorCreation(call) || len(call.Args) == 0 {
		return nil
	}

	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return nil
	}

	val := strings.Trim(lit.Value, "`\"")
	if val == "" {
		return nil
	}

	return r.checkErrorString(ctx, lit, val, nouns)
}

func (r *ErrorStringRule) checkErrorString(ctx *core.FileContext, lit *ast.BasicLit, val string, nouns map[string]bool) []*core.Violation {
	var violations []*core.Violation
	pos := ctx.PositionFor(lit)

	if r.startsWithCapital(val) && !r.startsWithProperNoun(val, nouns) {
		v := r.CreateViolation(ctx.RelPath, pos.Line, "Error strings should not be capitalized")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Use lowercase for error strings (Go convention)")
		violations = append(violations, v)
	}

	if r.endsWithPunctuation(val) {
		v := r.CreateViolation(ctx.RelPath, pos.Line, "Error strings should not end with punctuation")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Remove trailing punctuation from error string")
		violations = append(violations, v)
	}

	return violations
}

func (r *ErrorStringRule) isErrorCreation(call *ast.CallExpr) bool {
	// Check for errors.New or fmt.Errorf
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}

	funcName := ident.Name + "." + sel.Sel.Name
	return errorFuncs[funcName]
}

// startsWithCapital reports whether the error string starts with a capitalized
// word. A word with another capital or a digit after its first letter is an
// initialism (HTTP, TLS1.2, ID) or an identifier (GetUser, AppConfig) and
// keeps its spelling; a capitalized English word (Failed, Invalid, Canceled)
// is reported.
func (r *ErrorStringRule) startsWithCapital(s string) bool {
	if len(s) == 0 {
		return false
	}

	// Check for format verbs at start (like %s, %v)
	if s[0] == '%' {
		return false
	}

	first, size := utf8.DecodeRuneInString(s)

	// Only check Latin letters for capitalization
	// Non-Latin scripts (Cyrillic, etc.) have different conventions
	// and error messages in these languages are valid
	if !unicode.Is(unicode.Latin, first) || !unicode.IsUpper(first) {
		return false
	}

	rest := s[size:]
	if end := strings.IndexByte(rest, ' '); end >= 0 {
		rest = rest[:end]
	}
	for _, c := range rest {
		if unicode.IsUpper(c) || unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

// startsWithProperNoun reports a first word the configuration or the package
// names as a proper noun.
func (r *ErrorStringRule) startsWithProperNoun(s string, nouns map[string]bool) bool {
	word, _, _ := strings.Cut(s, " ")
	word = strings.TrimRightFunc(word, func(c rune) bool { return !unicode.IsLetter(c) })
	if r.properNouns[word] {
		return true
	}
	return !errorOpeners[word] && nouns[word]
}

func (r *ErrorStringRule) endsWithPunctuation(s string) bool {
	if len(s) == 0 {
		return false
	}

	// Check for format verbs at end
	if len(s) >= 2 && s[len(s)-2] == '%' {
		return false
	}

	lastRune := rune(s[len(s)-1])
	// . ! ? are problematic, but : is often used in structured errors
	return lastRune == '.' || lastRune == '!' || lastRune == '?'
}
