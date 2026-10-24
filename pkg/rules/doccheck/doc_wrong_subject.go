package doccheck

import (
	"errors"
	"fmt"
	"go/ast"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewDocWrongSubjectRule())
}

// DocWrongSubjectRule detects a doc comment left above the wrong function:
//
//	// pickAnchor returns the first anchor that fits, measured over 200 runs.
//	func newTimer() int { … }        // pickAnchor is declared further down
//
// It happens when new code is pasted between a comment and the function it
// described. Nothing complains — the comment still compiles as a comment — and
// from then on the reasoning belongs to a function that never had it, while the
// function it was written for stands undocumented.
//
// Only the first word counts, and only when it names another function of the
// same package: a comment that merely mentions a neighbour later in the
// sentence is normal prose, and so is one that names both functions — unless
// the own name opens a later line, which is the doc of the function with the
// comment of another glued above it.
//
// A deleted function leaves its comment the same way:
//
//	// heatSpot — a hot spot of a hidden unit, measured over 40 runs.
//	// hiddenNearBase — hidden foes next to our bases.
//	func hiddenNearBase() int { … }   // heatSpot is gone
//
// So a first word written as an unexported name of several words (heatSpot)
// that the code of the package never mentions is reported too; an exported
// one (PostgreSQL could be a brand) only when the own name opens a later line.
type DocWrongSubjectRule struct {
	*rules.BaseRule
}

// NewDocWrongSubjectRule creates the rule
func NewDocWrongSubjectRule() *DocWrongSubjectRule {
	return &DocWrongSubjectRule{
		BaseRule: rules.NewBaseRule(
			"doc-wrong-subject",
			"documentation",
			"Detects a doc comment whose first word names another function of the package, or a name the package no longer has — the comment was left above the wrong declaration",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op: the function a comment describes may be declared in
// another file of the package.
func (r *DocWrongSubjectRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DocWrongSubjectRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks the doc comments package by package.
func (r *DocWrongSubjectRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("doc wrong subject: nil Go project context")
	}

	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			return nil, errors.New("doc wrong subject: package has no syntax")
		}

		names := packageNames{funcs: make(map[string]bool), used: make(map[string]bool)}
		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil {
				continue
			}
			for _, decl := range fileCtx.GoAST.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok {
					names.funcs[fn.Name.Name] = true
				}
			}
			ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok {
					names.used[id.Name] = true
				}
				return true
			})
		}

		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			violations = append(violations, r.analyzeFile(fileCtx, names)...)
		}
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

// packageNames is what the code of a package names: its functions and every
// identifier it spells, declared or used.
type packageNames struct {
	funcs map[string]bool
	used  map[string]bool
}

func (r *DocWrongSubjectRule) analyzeFile(fileCtx *core.FileContext, names packageNames) []*core.Violation {
	var violations []*core.Violation

	for _, decl := range fileCtx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Doc == nil {
			continue
		}
		doc := fn.Doc.Text()
		subject, ok := docSubject(doc)
		if !ok || subject == fn.Name.Name {
			continue
		}
		// A doc that names its own function too explains a pair; it did not
		// lose its declaration — unless the own name opens a later line.
		glued := opensLaterLine(doc, fn.Name.Name)
		if !glued && mentionsWord(doc, fn.Name.Name) {
			continue
		}
		switch {
		case names.funcs[subject]:
			violations = append(violations, r.report(fileCtx, fn, subject, false))
		case !names.used[subject] && namedLikeCode(subject, glued):
			violations = append(violations, r.report(fileCtx, fn, subject, true))
		}
	}

	return violations
}

func (r *DocWrongSubjectRule) report(fileCtx *core.FileContext, fn *ast.FuncDecl, subject string, gone bool) *core.Violation {
	line := fileCtx.LineFor(fn.Name)
	message := fmt.Sprintf("Doc comment above %s describes %s — the comment was left behind when the code between them was inserted", fn.Name.Name, subject)
	suggestion := fmt.Sprintf("Move the comment back above %s, or rewrite it for %s", subject, fn.Name.Name)
	if gone {
		message = fmt.Sprintf("Doc comment above %s starts with %s, which the package no longer names — the doc of a removed, moved or renamed declaration stayed above %s", fn.Name.Name, subject, fn.Name.Name)
		suggestion = fmt.Sprintf("Move the comment of %s with its code or delete it, and keep a doc that describes %s", subject, fn.Name.Name)
	}
	v := r.CreateViolation(fileCtx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
	v.WithSuggestion(suggestion)
	v.WithContext("pattern", "doc_wrong_subject")
	v.WithContext("subject", subject)
	return v
}

// docSubject returns the identifier the comment starts with, if it starts with
// one: Go doc comments open with the name of what they describe.
func docSubject(doc string) (string, bool) {
	fields := strings.Fields(doc)
	if len(fields) < 2 {
		return "", false // a one-word comment names nothing it could confuse
	}
	word := strings.TrimRight(fields[0], ".,:;—-")
	if word == "" || !isGoIdentifier(word) {
		return "", false
	}
	return word, true
}

// opensLaterLine reports whether a line after the first one starts with the
// name as its own word: the doc of the function begins there.
func opensLaterLine(doc, name string) bool {
	lines := strings.Split(doc, "\n")
	for _, line := range lines[1:] {
		if first, ok := docSubject(line); ok && first == name {
			return true
		}
	}
	return false
}

// namedLikeCode reports a word spelled as an identifier of several words: an
// unexported one (heatSpot) is a name, not prose; an exported one may be a
// brand (PostgreSQL), so it counts only when the doc shows it was glued.
func namedLikeCode(word string, glued bool) bool {
	if len(helpers.IdentifierWords(word)) < 2 {
		return false
	}
	first, _ := utf8.DecodeRuneInString(word)
	return glued || unicode.IsLower(first)
}

func isGoIdentifier(word string) bool {
	for i, symbol := range word {
		if symbol == '_' {
			continue
		}
		if unicode.IsLetter(symbol) {
			continue
		}
		if i > 0 && unicode.IsDigit(symbol) {
			continue
		}
		return false
	}
	return true
}

// mentionsWord reports whether the text contains the name as a whole word.
func mentionsWord(text, name string) bool {
	for field := range strings.FieldsSeq(text) {
		if strings.Trim(field, "().,:;\"`'—-") == name {
			return true
		}
	}
	return false
}
