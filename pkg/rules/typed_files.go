package rules

import (
	"fmt"
	"go/types"
	"sort"

	"github.com/aiseeq/glint/pkg/core"
)

// AnalyzeTypedFiles walks the analyzed files of every loaded package and
// returns their violations in file and line order. It is the entry point every
// typed rule shares: the traversal, the demand for typed syntax and the sort
// are the same for all of them, only the per-file check differs.
//
// ruleName prefixes the errors, so a project that failed to load says which
// rule was asking.
func AnalyzeTypedFiles(
	ctx *core.GoProjectContext,
	ruleName string,
	analyze func(fileCtx *core.FileContext, info *types.Info) []*core.Violation,
) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", ruleName)
	}

	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, fmt.Errorf("%s: package has no typed syntax", ruleName)
		}
		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			violations = append(violations, analyze(fileCtx, pkg.Package.TypesInfo)...)
		}
	}

	sortViolations(violations)
	return violations, nil
}

// AnalyzeGoFiles walks every Go file of the project: the files of type-checked
// packages with their package's types.Info, every other file - test files
// (the typed load leaves tests out), files of packages that failed to
// type-check under --tolerant, files outside any module - with a nil
// types.Info. Violations come back in file and line order.
//
// A rule that gets a nil types.Info sees one file only, and a declaration it
// does not find there is unknown, not absent: the rule must stay silent about
// such a name rather than guess its type from how it is spelled.
func AnalyzeGoFiles(
	ctx *core.GoProjectContext,
	ruleName string,
	analyze func(fileCtx *core.FileContext, info *types.Info) []*core.Violation,
) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", ruleName)
	}

	var violations []*core.Violation
	typed := make(map[*core.FileContext]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, fmt.Errorf("%s: package has no typed syntax", ruleName)
		}
		for _, fileCtx := range pkg.Files {
			if typed[fileCtx] {
				continue
			}
			typed[fileCtx] = true
			if fileCtx.GoAST == nil {
				continue
			}
			violations = append(violations, analyze(fileCtx, pkg.Package.TypesInfo)...)
		}
	}
	for _, fileCtx := range ctx.Files {
		if fileCtx == nil || fileCtx.GoAST == nil || typed[fileCtx] {
			continue
		}
		violations = append(violations, analyze(fileCtx, nil)...)
	}

	sortViolations(violations)
	return violations, nil
}

func sortViolations(violations []*core.Violation) {
	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
}
