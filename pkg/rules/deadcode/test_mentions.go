package deadcode

import (
	"go/ast"
	"path"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// testMentions answers "does a Go file outside the typed load in this
// package's directory mention this name". Test packages are not part of the
// typed load (packages.Load runs with Tests:false), so a white-box test
// reading an internal field or symbol is invisible to typed analysis; this
// scan keeps such members from being reported as dead.
// Parsed files contribute identifiers from their syntax trees, so strings and
// comments cannot keep dead code alive. Files without an AST use a coarse word
// scan: an extra mention only hides a finding, while a missed mention reports
// live code as dead.
type testMentions struct {
	// identifiers mentioned in the scanned files, keyed by directory and
	// package name. Counts let test-function declarations exclude themselves.
	names    map[mentionPackage]map[string]int
	fallback map[mentionPackage]map[string]bool
	// names written where a field goes: x.Name outside a package selector,
	// and Name: in a composite literal
	fieldNames map[mentionPackage]map[string]bool
	seen       map[string]bool
}

type mentionPackage struct {
	dir         string
	packageName string
}

type mentionsKey struct{}

// projectMentions is the name scan of every Go file outside the typed load —
// tests, build-excluded files, and package files the configuration excluded
// from analysis — built once per project and shared by the dead-code rules.
func projectMentions(ctx *core.GoProjectContext) (*testMentions, error) {
	return core.Shared(ctx, mentionsKey{}, func() (*testMentions, error) {
		mentions := newUntypedMentions(ctx)
		for _, pkg := range ctx.Packages {
			if pkg == nil || pkg.Package == nil {
				continue
			}
			if err := mentions.addUnloadedPackageFiles(pkg); err != nil {
				return nil, err
			}
		}
		return mentions, nil
	})
}

// newUntypedMentions scans every Go file the typed load leaves out: test
// files, and files the build excludes on this platform (foo_windows.go, a
// build tag). Such a file can still use a package's symbols; the scan reads
// the text, so a file that does not even parse (a template behind
// //go:build ignore) costs nothing but a few spurious words.
func newUntypedMentions(ctx *core.GoProjectContext) *testMentions {
	typed := make(map[*core.FileContext]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil {
			continue
		}
		for _, fileCtx := range pkg.Files {
			typed[fileCtx] = true
		}
	}
	mentions := &testMentions{
		names:      make(map[mentionPackage]map[string]int),
		fallback:   make(map[mentionPackage]map[string]bool),
		fieldNames: make(map[mentionPackage]map[string]bool),
		seen:       make(map[string]bool),
	}
	packagesByDir := make(map[string]map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || len(pkg.Package.GoFiles) == 0 {
			continue
		}
		dir := filepath.Dir(pkg.Package.GoFiles[0])
		if packagesByDir[dir] == nil {
			packagesByDir[dir] = make(map[string]bool)
		}
		packagesByDir[dir][pkg.Package.Name] = true
	}
	for _, fileCtx := range ctx.Files {
		if fileCtx == nil || !fileCtx.IsGoFile() || (typed[fileCtx] && !fileCtx.IsTestFile()) {
			continue
		}
		if fileCtx.GoAST == nil && fileCtx.GoPackage == "" {
			if packageNames := packagesByDir[filepath.Dir(fileCtx.Path)]; len(packageNames) > 0 {
				for packageName := range packageNames {
					mentions.add(fileCtx, packageName)
				}
				continue
			}
		}
		mentions.add(fileCtx, fileCtx.GoPackage)
	}
	return mentions
}

// add records identifiers from the AST, or words when parsing failed.
func (m *testMentions) add(fileCtx *core.FileContext, packageName string) {
	if fileCtx.GoAST != nil {
		packageName = fileCtx.GoAST.Name.Name
	}
	key := mentionPackage{dir: filepath.Dir(fileCtx.Path), packageName: packageName}
	m.seen[fileCtx.Path] = true
	set := m.names[key]
	if set == nil {
		set = make(map[string]int)
		m.names[key] = set
	}
	if fileCtx.GoAST == nil {
		fallback := m.fallback[key]
		if fallback == nil {
			fallback = make(map[string]bool)
			m.fallback[key] = fallback
		}
		collectIdentifierWords(string(fileCtx.Content), fallback)
		return
	}
	fields := m.fieldNames[key]
	if fields == nil {
		fields = make(map[string]bool)
		m.fieldNames[key] = fields
	}
	imports := importNames(fileCtx.GoAST)
	ast.Inspect(fileCtx.GoAST, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.Ident:
			set[node.Name]++
		case *ast.SelectorExpr:
			if x, ok := node.X.(*ast.Ident); !ok || !imports[x.Name] {
				fields[node.Sel.Name] = true
			}
		case *ast.KeyValueExpr:
			if key, ok := node.Key.(*ast.Ident); ok {
				fields[key.Name] = true
			}
		}
		return true
	})
}

// importNames are the names a file refers to its imported packages by.
func importNames(file *ast.File) map[string]bool {
	names := make(map[string]bool, len(file.Imports))
	for _, spec := range file.Imports {
		if spec.Name != nil {
			names[spec.Name.Name] = true
			continue
		}
		names[path.Base(strings.Trim(spec.Path.Value, "`\""))] = true
	}
	return names
}

// mentionedAsField reports whether a scanned file in the declaration's
// directory writes the name where a field goes. An embedded field is named
// after its type, and a test that only names the type (a fake, an interface
// assertion) does not reach the field. A file without an AST counts any
// mention, as mentioned does.
func (m *testMentions) mentionedAsField(declCtx *core.FileContext, name string) bool {
	dir := filepath.Dir(declCtx.Path)
	for key, set := range m.fieldNames {
		if key.dir == dir && set[name] {
			return true
		}
	}
	for key, set := range m.fallback {
		if key.dir == dir && set[name] {
			return true
		}
	}
	return false
}

// mentioned reports whether a scanned file in the declaration's directory
// uses the identifier. Fields and ordinary package members can be read by an
// external test package in that directory, so their mentions are not split by
// package name. Test helper functions use functionUsed, which must stay within
// their own package.
func (m *testMentions) mentioned(declCtx *core.FileContext, name string) bool {
	dir := filepath.Dir(declCtx.Path)
	for key, set := range m.names {
		if key.dir == dir && set[name] > 0 {
			return true
		}
	}
	for key, set := range m.fallback {
		if key.dir == dir && set[name] {
			return true
		}
	}
	return false
}

// functionUsed reports whether another identifier in this package mentions
// the test helper. Its own declaration is the one identifier excluded.
func (m *testMentions) functionUsed(fileCtx *core.FileContext, name string) bool {
	key := packageKey(fileCtx)
	return m.names[key][name] > 1 || m.fallback[key][name]
}

func packageKey(fileCtx *core.FileContext) mentionPackage {
	packageName := fileCtx.GoPackage
	if fileCtx.GoAST != nil {
		packageName = fileCtx.GoAST.Name.Name
	}
	return mentionPackage{dir: filepath.Dir(fileCtx.Path), packageName: packageName}
}

// mentionedAnywhere reports whether any scanned file of the project uses the
// identifier: an exported member is reachable from tests of other packages
// (a test helper's counter asserted by the package it fakes for).
func (m *testMentions) mentionedAnywhere(name string) bool {
	for _, set := range m.names {
		if set[name] > 0 {
			return true
		}
	}
	for _, set := range m.fallback {
		if set[name] {
			return true
		}
	}
	return false
}

// collectIdentifierWords splits source text into identifier-shaped words for
// files without an AST. These conservative fallback matches can over-match;
// strings and comments in parsed files are intentionally ignored because
// neither is a code reference.
func collectIdentifierWords(content string, into map[string]bool) {
	start := -1
	for i := 0; i <= len(content); i++ {
		isWord := i < len(content) && helpers.IsIdentifierChar(content[i])
		switch {
		case isWord && start < 0:
			start = i
		case !isWord && start >= 0:
			into[content[start:i]] = true
			start = -1
		}
	}
}
