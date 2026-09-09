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

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}
