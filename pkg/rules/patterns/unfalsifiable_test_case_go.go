package patterns

import (
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// UseProjectFiles collects the text every page of the project carries: the
// layout templates and the stylesheets, read from disk - the analysis does
// not list them.
func (r *UnfalsifiableTestCaseRule) UseProjectFiles(files []*core.FileContext) {
	r.sharedPageText = make(map[string]string)
	r.sharedPageErr = nil
	texts := make(map[string][]string)
	roots := make(map[string]bool)
	for _, file := range files {
		if file.ProjectRoot != "" && file.IsGoFile() && file.IsTestFile() {
			roots[file.ProjectRoot] = true
		}
	}
	for root := range roots {
		paths, err := filesWithExt(root, ".css", ".html", ".tmpl", ".gohtml")
		if err != nil {
			r.sharedPageErr = fmt.Errorf("list layouts under %s: %w", root, err)
			return
		}
		for _, path := range paths {
			if !sharedPageFile(path) {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				r.sharedPageErr = fmt.Errorf("read layout: %w", err)
				return
			}
			dir := filepath.Dir(filepath.Dir(path))
			texts[dir] = append(texts[dir], string(data))
		}
	}
	for dir, parts := range texts {
		r.sharedPageText[dir] = strings.Join(parts, "\n")
	}
}

// ResetState drops the shared text of the previous root.
func (r *UnfalsifiableTestCaseRule) ResetState() { r.sharedPageText, r.sharedPageErr = nil, nil }

// sharedPageFile reports a layout template or a stylesheet.
func sharedPageFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch filepath.Ext(base) {
	case ".css":
		return true
	case ".html", ".tmpl", ".gohtml":
		return strings.Contains(base, "layout") || strings.HasPrefix(base, "base.")
	}
	return false
}

// pageMarker is a lone CSS class or word a body check looks for.
var pageMarker = regexp.MustCompile(`^[A-Za-z][\w-]*$`)

// analyzeGoBodyMarkers reports a Go test check that a response body holds a
// marker the shared layout or stylesheet carries on every page:
//
//	if !strings.Contains(body, "callout-error") { t.Fatal(...) } // in the CSS of every page
//
// The check holds whether the code under test rendered anything.
func (r *UnfalsifiableTestCaseRule) analyzeGoBodyMarkers(ctx *core.FileContext) []*core.Violation {
	if r.sharedPageErr != nil {
		v := r.CreateViolation(ctx.RelPath, 1, "The project's layouts could not be read, so body checks were not compared with them: "+r.sharedPageErr.Error())
		v.Severity = core.SeverityCritical
		return []*core.Violation{v}
	}
	shared := r.sharedTextAbove(ctx.Path)
	if shared == "" {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var arg ast.Expr
		switch name := core.ExtractFullFunctionName(call); {
		case name == "strings.Contains" && len(call.Args) == 2:
			arg = call.Args[1]
		case strings.HasSuffix(name, ".Contains") && len(call.Args) >= 3:
			arg = call.Args[2] // assert.Contains(t, body, marker)
		default:
			return true
		}
		lit, ok := arg.(*ast.BasicLit)
		if !ok {
			return true
		}
		marker, err := strconv.Unquote(lit.Value)
		if err != nil || !pageMarker.MatchString(marker) || !regexp.MustCompile(`(?:^|[^\w-])`+regexp.QuoteMeta(marker)+`(?:[^\w-]|$)`).MatchString(shared) {
			return true
		}
		line := ctx.LineFor(call)
		v := r.CreateViolation(ctx.RelPath, line,
			"The test looks for \""+marker+"\" in the body, and the shared layout or stylesheet carries it on every page — the check passes whether the page rendered it or not")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Assert the markup only this response renders (the element with its text), not a class name or a word of the layout")
		violations = append(violations, v)
		return true
	})
	return violations
}

// sharedTextAbove returns the shared page text of the test's directory tree.
func (r *UnfalsifiableTestCaseRule) sharedTextAbove(path string) string {
	dirs := make([]string, 0, len(r.sharedPageText))
	for dir := range r.sharedPageText {
		if strings.HasPrefix(path, dir+string(filepath.Separator)) {
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	parts := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		parts = append(parts, r.sharedPageText[dir])
	}
	return strings.Join(parts, "\n")
}
