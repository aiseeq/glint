package doccheck

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeStaleReference(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	violations, err := NewDocStaleReferenceRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations
}

var staleModule = map[string]string{
	"planner/ctx.go": `package planner

// Ctx is the request context.
type Ctx struct{}

func helper() {}
`,
	"build/order.go": `package build

// Order is one build order.
type Order struct{}
`,
}

func withFile(path, src string) map[string]string {
	files := map[string]string{path: src}
	for k, v := range staleModule {
		files[k] = v
	}
	return files
}

// Repro from a real project: a type moved from one package to another, and
// the comments that pointed at it kept the old package. An agent following
// the comment searches the old package and finds nothing.
func TestDocStaleReferenceReportsMovedType(t *testing.T) {
	violations := analyzeStaleReference(t, withFile("catalog/a.go", `package catalog

import "example.com/rulestest/planner"

// run hands the request to planner.Order before the reply.
func run(*planner.Ctx) {}
`))

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Contains(t, violations[0].Message, "planner.Order")
}

// Names that exist resolve, exported or not, in an imported package, in a
// package of the module the file does not import, and in the file's own package.
func TestDocStaleReferenceAcceptsLiveNames(t *testing.T) {
	violations := analyzeStaleReference(t, withFile("catalog/a.go", `package catalog

import "example.com/rulestest/planner"

// run takes planner.Ctx (built by planner.helper) and queues a build.Order;
// catalog.run is the entry.
func run(*planner.Ctx) {}
`))

	assert.Empty(t, violations)
}

// A method or a field is named through its package as often as through its
// type: planner.Run for (*Ctx).Run, planner.Frame for Ctx.Frame. A test of the
// package, internal or external, is a name of it too.
func TestDocStaleReferenceAcceptsMethodsFieldsAndTests(t *testing.T) {
	files := withFile("catalog/a.go", `package catalog

// run calls planner.Run, reads planner.Frame and is checked by planner.TestRun
// and planner.TestFrame.
func run() {}
`)
	files["planner/run.go"] = `package planner

// Run serves the request.
func (c *Ctx) Run() {}

// Step holds the request.
type Step struct{ Frame int }
`
	files["planner/run_test.go"] = `package planner

import "testing"

func TestRun(t *testing.T) {}
`
	files["planner/frame_test.go"] = `package planner_test

import "testing"

func TestFrame(t *testing.T) {}
`

	assert.Empty(t, analyzeStaleReference(t, files))
}

// A lower-case name after a package name is as often a quote of another
// language (self.planner.execute in a Python source) or a file of an archive
// (planner.details) as a Go name. It is reported only when the module declares
// it elsewhere — the name moved; a name the module has nowhere is left alone.
func TestDocStaleReferenceLowerCaseOnlyWhenMoved(t *testing.T) {
	files := withFile("catalog/a.go", `package catalog

// run is what the source calls planner.execute, and planner.details is read first;
// the order goes through planner.queue.
func run() {}
`)
	files["build/queue.go"] = `package build

func queue() {}
`

	violations := analyzeStaleReference(t, files)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "planner.queue")
}

// Packages outside the module, file names and paths are not references to
// check: fmt.Sprintf, planner.go, catalog/planner.Order.
func TestDocStaleReferenceIgnoresOutsideNames(t *testing.T) {
	violations := analyzeStaleReference(t, withFile("catalog/a.go", `package catalog

// run formats with fmt.Sprintf; the context lives in planner.go and
// the path catalog/planner.Order is a directory, not a reference.
func run() {}
`))

	assert.Empty(t, violations)
}

// Two module packages share a name: only the import of the file says which
// one a comment means; without it the reference is left alone. A name the
// imported package lacks but its namesake declares is left alone too: the
// comment may mean the other one.
func TestDocStaleReferenceResolvesAmbiguousNameByImport(t *testing.T) {
	files := withFile("catalog/a.go", `package catalog

import "example.com/rulestest/one/util"

// run calls util.Missing and util.Other.
func run() { util.Do() }
`)
	files["one/util/u.go"] = "package util\n\nfunc Do() {}\n"
	files["two/util/u.go"] = "package util\n\nfunc Other() {}\n"
	files["catalog/b.go"] = `package catalog

// other mentions util.Anything without importing a util.
func other() {}
`

	violations := analyzeStaleReference(t, files)

	require.Len(t, violations, 1)
	assert.Equal(t, "catalog/a.go", violations[0].File)
	assert.Contains(t, violations[0].Message, "util.Missing")
}

// Go names are Unicode: a test named in another script is one identifier.
func TestDocStaleReferenceReadsUnicodeNames(t *testing.T) {
	files := withFile("catalog/a.go", `package catalog

// run is checked by planner.TestRunПолный.
func run() {}
`)
	files["planner/run_test.go"] = "package planner\n\nimport \"testing\"\n\nfunc TestRunПолный(t *testing.T) {}\n"

	assert.Empty(t, analyzeStaleReference(t, files))
}

// A lower-case chain is a file or an attribute path (planner.queue.events), not
// a Go reference, even when the module declares queue elsewhere.
func TestDocStaleReferenceIgnoresLowerCaseChains(t *testing.T) {
	files := withFile("catalog/a.go", `package catalog

// run reads planner.queue.events of the archive.
func run() {}
`)
	files["build/queue.go"] = "package build\n\nfunc queue() {}\n"

	assert.Empty(t, analyzeStaleReference(t, files))
}

// A main package is never imported: main.Name in a comment is prose, not a
// reference to follow.
func TestDocStaleReferenceIgnoresMainPackage(t *testing.T) {
	files := withFile("catalog/a.go", `package catalog

// run: main is never imported, so its names are never read as main.Name.
func run() {}
`)
	files["cmd/tool/main.go"] = "package main\n\n// main runs the tool; see main.Name above.\nfunc main() {}\n"

	assert.Empty(t, analyzeStaleReference(t, files))
}

// Test files keep fixtures and quotes of old output; they are not checked.
func TestDocStaleReferenceSkipsTestFiles(t *testing.T) {
	violations := analyzeStaleReference(t, withFile("catalog/a_test.go", `package catalog

// the old planner.Order fixture.
func fixture() {}
`))

	assert.Empty(t, violations)
}

// A check of one directory loads only its files, yet a comment there names a
// test of another package of the module: the test counts all the same.
func TestDocStaleReferenceSeesTestsOutsideCheckedFiles(t *testing.T) {
	files := withFile("catalog/a.go", `package catalog

import "example.com/rulestest/planner"

// run is held by planner.TestRun.
func run(*planner.Ctx) {}
`)
	files["planner/run_test.go"] = "package planner\n\nimport \"testing\"\n\nfunc TestRun(t *testing.T) {}\n"
	root, contexts := rulestest.Module(t, files)
	var checked []*core.FileContext
	for _, fileCtx := range contexts {
		if strings.HasPrefix(fileCtx.RelPath, "catalog/") || fileCtx.RelPath == "go.mod" {
			checked = append(checked, fileCtx)
		}
	}
	project, err := core.LoadGoProject(root, checked, core.GoProjectOptions{})
	require.NoError(t, err)

	violations, err := NewDocStaleReferenceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

// Repro from a real project: a comment names a family of constants by its
// prefix, pkg.Prefix*. The reference is live while the package declares a
// name with the prefix, and stale once none is left.
func TestDocStaleReferenceAcceptsPrefixFamily(t *testing.T) {
	files := withFile("catalog/a.go", `package catalog

// run maps the reply onto one of planner.Status* and never onto planner.Phase*.
func run() {}
`)
	files["planner/status.go"] = "package planner\n\nconst (\n\tStatusPending = \"pending\"\n\tStatusDone = \"done\"\n)\n"
	violations := analyzeStaleReference(t, files)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "planner.Phase*")
}

// A module package shares its name with a standard library package the
// project imports: a package http that imports net/http means net/http by
// http.Cookie, and a comment elsewhere naming sql.ErrNoRows may mean
// database/sql. A local package whose name nothing outside the module has is
// still checked.
func TestDocStaleReferenceLeavesNamesOfImportedOutsidePackages(t *testing.T) {
	files := withFile("shared/http/jwt.go", `package http

import nethttp "net/http"

// Read takes the token from the request's http.Cookie.
func Read(r *nethttp.Request) {}
`)
	files["shared/errors/types.go"] = `package errors

import "errors"

// Is wraps errors.Is.
func Is(err, target error) bool { return errors.Is(err, target) }
`
	files["shared/sql/db.go"] = "package sql\n\nfunc Open() {}\n"
	files["service/users.go"] = `package service

import "database/sql"

var _ = sql.ErrNoRows
`
	files["service/orders.go"] = `package service

// find answers sql.ErrNoRows for a missing order; the order lives in build.Gone.
func find() {}
`

	violations := analyzeStaleReference(t, files)

	require.Len(t, violations, 1, "%v", violations)
	assert.Contains(t, violations[0].Message, "build.Gone")
}

// Repro from a real project: a comment quoted frontend code in backticks,
// `planner.queue?.id` and `planner.queue["id"]`, while a Go package planner
// existed and another package declared queue. Code in backticks is a quote:
// it refers to a Go name only as pkg.Exported. A missing exported name in
// backticks is still reported.
func TestDocStaleReferenceQuotedCodeNeedsExportedName(t *testing.T) {
	files := withFile("catalog/a.go", "package catalog\n\n"+
		"// run warns on `planner.queue?.id` and `planner.queue[\"id\"]` in the frontend,\n"+
		"// and hands the result to `planner.Order`.\n"+
		"func run() {}\n")
	files["build/queue.go"] = "package build\n\nfunc queue() {}\n"

	violations := analyzeStaleReference(t, files)

	require.Len(t, violations, 1)
	assert.Equal(t, 4, violations[0].Line)
	assert.Contains(t, violations[0].Message, "planner.Order")
}
