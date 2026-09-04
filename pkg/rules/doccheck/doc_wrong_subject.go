package doccheck

import (
	"errors"
	"fmt"
	"go/ast"
	"sort"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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
// sentence is normal prose, and so is one that names both functions.
type DocWrongSubjectRule struct {
	*rules.BaseRule
}

// NewDocWrongSubjectRule creates the rule
func NewDocWrongSubjectRule() *DocWrongSubjectRule {
	return &DocWrongSubjectRule{
		BaseRule: rules.NewBaseRule(
			"doc-wrong-subject",
			"documentation",
			"Detects a doc comment whose first word names another function of the package — the comment was left above the wrong declaration",
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

		declared := make(map[string]bool)
		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil {
				continue
			}
			for _, decl := range fileCtx.GoAST.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok {
					declared[fn.Name.Name] = true
				}
			}
		}

		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			violations = append(violations, r.analyzeFile(fileCtx, declared)...)
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

func (r *DocWrongSubjectRule) analyzeFile(fileCtx *core.FileContext, declared map[string]bool) []*core.Violation {
	var violations []*core.Violation

	for _, decl := range fileCtx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Doc == nil {
			continue
		}
		doc := fn.Doc.Text()
		subject, ok := docSubject(doc)
		if !ok || subject == fn.Name.Name || !declared[subject] {
			continue
		}
		// A doc that names its own function too explains a pair; it did not
		// lose its declaration.
		if mentionsWord(doc, fn.Name.Name) {
			continue
		}
		violations = append(violations, r.report(fileCtx, fn, subject))
	}

	return violations
}

func (r *DocWrongSubjectRule) report(fileCtx *core.FileContext, fn *ast.FuncDecl, subject string) *core.Violation {
	line := fileCtx.LineFor(fn.Name)
	v := r.CreateViolation(fileCtx.RelPath, line,
		fmt.Sprintf("Doc comment above %s describes %s — the comment was left behind when the code between them was inserted", fn.Name.Name, subject))
	v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Move the comment back above %s, or rewrite it for %s", subject, fn.Name.Name))
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
	for _, field := range strings.Fields(text) {
		if strings.Trim(field, "().,:;\"`'—-") == name {
			return true
		}
	}
	return false
}
