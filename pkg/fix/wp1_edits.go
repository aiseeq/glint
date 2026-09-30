package fix

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
)

// edit is a fix resolved to a byte span of the file it applies to.
type edit struct {
	fix        *Fix
	start, end int
}

// applyEdits applies the fixes of one file to its content. Fixes that overlap
// an earlier fix are deferred, never applied halfway. A fix whose span no
// longer holds its OldText means the file changed since it was analyzed: then
// nothing is applied. A Go file must still parse afterwards; it gets the
// imports its fixes need and is gofmt-formatted, and if any of that fails
// nothing is applied either.
func applyEdits(file string, content []byte, fixes []*Fix) (fixed []byte, applied, deferred []*Fix, err error) {
	edits, err := resolveEdits(content, fixes)
	if err != nil {
		return nil, nil, nil, err
	}
	accepted, deferred := disjointEdits(edits)
	if len(accepted) == 0 {
		return content, nil, deferred, nil
	}

	var out bytes.Buffer
	pos := 0
	for _, e := range accepted {
		out.Write(content[pos:e.start])
		out.WriteString(e.fix.NewText)
		pos = e.end
	}
	out.Write(content[pos:])

	applied = make([]*Fix, 0, len(accepted))
	for _, e := range accepted {
		applied = append(applied, e.fix)
	}

	fixed = out.Bytes()
	if filepath.Ext(file) == ".go" {
		fixed, err = finishGoFile(file, content, fixed, applied)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return fixed, applied, deferred, nil
}

// resolveEdits turns every fix into a byte span and checks that the span still
// holds the text the fix replaces.
func resolveEdits(content []byte, fixes []*Fix) ([]edit, error) {
	lineStarts := []int{0}
	for i, b := range content {
		if b == '\n' {
			lineStarts = append(lineStarts, i+1)
		}
	}
	lineEnd := func(line int) int {
		if line < len(lineStarts) {
			return lineStarts[line] - 1
		}
		return len(content)
	}

	edits := make([]edit, 0, len(fixes))
	var stale []string
	for _, fix := range fixes {
		start, end, ok := fixSpan(fix, lineStarts, lineEnd)
		if !ok || string(content[start:end]) != fix.OldText {
			stale = append(stale, fmt.Sprintf("%s (line %d)", fix.RuleName, fix.StartLine))
			continue
		}
		edits = append(edits, edit{fix: fix, start: start, end: end})
	}
	if len(stale) > 0 {
		return nil, fmt.Errorf("%d fix(es) no longer match the file, so none were applied: %s",
			len(stale), strings.Join(stale, ", "))
	}
	return edits, nil
}

// fixSpan converts the line and column position of a fix into byte offsets.
func fixSpan(fix *Fix, lineStarts []int, lineEnd func(int) int) (start, end int, ok bool) {
	endLine := max(fix.EndLine, fix.StartLine)
	if fix.StartLine < 1 || endLine > len(lineStarts) {
		return 0, 0, false
	}
	start = lineStarts[fix.StartLine-1]
	if fix.StartCol > 0 {
		start += fix.StartCol - 1
	}
	end = lineEnd(endLine)
	if fix.EndCol > 0 {
		end = lineStarts[endLine-1] + fix.EndCol - 1
	}
	if start > end || start > lineEnd(fix.StartLine) || end > lineEnd(endLine) {
		return 0, 0, false
	}
	return start, end, true
}

// disjointEdits picks, in file order, the edits that do not overlap an edit
// already picked, and returns the others as deferred. Two insertions at one
// point overlap too: which goes first would be a guess.
func disjointEdits(edits []edit) (accepted []edit, deferred []*Fix) {
	sort.SliceStable(edits, func(i, j int) bool {
		if edits[i].start != edits[j].start {
			return edits[i].start < edits[j].start
		}
		return edits[i].end < edits[j].end
	})

	coveredUntil := -1
	insertions := make(map[int]bool)
	for _, e := range edits {
		insertion := e.start == e.end
		if e.start < coveredUntil || (insertion && insertions[e.start]) {
			deferred = append(deferred, e.fix)
			continue
		}
		accepted = append(accepted, e)
		coveredUntil = max(coveredUntil, e.end)
		if insertion {
			insertions[e.start] = true
		}
	}
	return accepted, deferred
}

// finishGoFile adds the imports the applied fixes need, removes the ones they
// made unused, and formats the result. The fixed source must parse and format,
// otherwise the fix is reported instead of written.
func finishGoFile(file string, original, fixed []byte, applied []*Fix) ([]byte, error) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, fixed, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("fixed source does not parse, file left unchanged: %w", err)
	}

	var needed, dropped []string
	for _, fix := range applied {
		needed = append(needed, fix.Imports...)
		dropped = append(dropped, fix.DropImports...)
	}
	slices.Sort(needed)
	needed = slices.Compact(needed)
	slices.Sort(dropped)
	dropped = slices.Compact(dropped)

	changed := false
	for _, importPath := range needed {
		if astutil.AddImport(fset, parsed, importPath) {
			changed = true
		}
	}
	for _, importPath := range dropped {
		if dropUnusedImport(fset, parsed, importPath) {
			changed = true
		}
	}

	if changed {
		var buf bytes.Buffer
		if err := format.Node(&buf, fset, parsed); err != nil {
			return nil, fmt.Errorf("print fixed source, file left unchanged: %w", err)
		}
		fixed = buf.Bytes()
	}

	formatted, err := format.Source(fixed)
	if err != nil {
		return nil, fmt.Errorf("fixed source does not format, file left unchanged: %w", err)
	}
	if usesCRLF(original) {
		formatted = bytes.ReplaceAll(formatted, []byte("\n"), []byte("\r\n"))
	}
	return formatted, nil
}

// dropUnusedImport removes the imports of importPath that no selector of the
// file refers to any more. Blank and dot imports are kept: whether they are
// needed cannot be seen from the file.
func dropUnusedImport(fset *token.FileSet, file *ast.File, importPath string) bool {
	removed := false
	for _, spec := range slices.Clone(file.Imports) {
		specPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || specPath != importPath {
			continue
		}
		name := path.Base(importPath)
		specName := ""
		if spec.Name != nil {
			specName = spec.Name.Name
			name = specName
		}
		if name == "_" || name == "." || refersToPackageName(file, name) {
			continue
		}
		if astutil.DeleteNamedImport(fset, file, specName, importPath) {
			removed = true
		}
	}
	return removed
}

// refersToPackageName reports whether a selector of the file starts with the
// name as an unresolved identifier, the way a package reference does.
func refersToPackageName(file *ast.File, name string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		selector, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == name && ident.Obj == nil {
			found = true
			return false
		}
		return true
	})
	return found
}

// usesCRLF reports whether every line of the content ends with CRLF.
func usesCRLF(content []byte) bool {
	lf := bytes.Count(content, []byte("\n"))
	return lf > 0 && lf == bytes.Count(content, []byte("\r\n"))
}
