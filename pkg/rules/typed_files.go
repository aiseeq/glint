package rules

import (
	"fmt"
	"go/types"
	"path/filepath"
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
	return analyzeTypedFiles(ctx, ruleName, nil, analyze)
}

// AnalyzeTypedRunFiles analyzes only files selected for the current run. Use
// it when each file's findings are independent; project-wide indexes should
// be built before calling it.
func AnalyzeTypedRunFiles(
	ctx *core.GoProjectContext,
	ruleName string,
	analyze func(fileCtx *core.FileContext, info *types.Info) []*core.Violation,
) ([]*core.Violation, error) {
	if ctx == nil || !ctx.HasReportScope() {
		return AnalyzeTypedFiles(ctx, ruleName, analyze)
	}
	return analyzeTypedFiles(ctx, ruleName, ctx.IsReportFile, analyze)
}

func analyzeTypedFiles(
	ctx *core.GoProjectContext,
	ruleName string,
	inScope func(*core.FileContext) bool,
	analyze func(fileCtx *core.FileContext, info *types.Info) []*core.Violation,
) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", ruleName)
	}

	var violations []*core.Violation
	if inScope != nil {
		for _, fileCtx := range ctx.ReportFiles() {
			if fileCtx == nil || fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			info, loaded := ctx.ReportTypesInfo(fileCtx)
			if !loaded {
				continue
			}
			if info == nil {
				return nil, fmt.Errorf("%s: package has no typed syntax", ruleName)
			}
			found := analyze(fileCtx, info)
			if err := validateRunFindings(inScope, fileCtx, ruleName, found); err != nil {
				return nil, err
			}
			violations = append(violations, found...)
		}
		sortViolations(violations)
		return violations, nil
	}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, fmt.Errorf("%s: package has no typed syntax", ruleName)
		}
		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() || inScope != nil && !inScope(fileCtx) {
				continue
			}
			found := analyze(fileCtx, pkg.Package.TypesInfo)
			if inScope != nil {
				for _, violation := range found {
					if violation == nil || !sameFilePath(fileCtx, violation.File) {
						return nil, fmt.Errorf("%s: report callback for %q returned a finding for %q", ruleName, fileCtx.RelPath, violationPath(violation))
					}
				}
			}
			violations = append(violations, found...)
		}
	}

	sortViolations(violations)
	return violations, nil
}

func violationPath(violation *core.Violation) string {
	if violation == nil {
		return "<nil>"
	}
	return violation.File
}

func sameFilePath(file *core.FileContext, path string) bool {
	if filepath.IsAbs(path) {
		return filepath.Clean(file.Path) == filepath.Clean(path)
	}
	return filepath.Clean(path) == filepath.Clean(file.RelPath)
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
	return analyzeGoFiles(ctx, ruleName, nil, analyze)
}

// AnalyzeGoRunFiles analyzes only files selected for the current run. Use it
// when the callback reports findings from its file and keeps no cross-file
// state.
func AnalyzeGoRunFiles(
	ctx *core.GoProjectContext,
	ruleName string,
	analyze func(fileCtx *core.FileContext, info *types.Info) []*core.Violation,
) ([]*core.Violation, error) {
	if ctx == nil || !ctx.HasReportScope() {
		return AnalyzeGoFiles(ctx, ruleName, analyze)
	}
	return analyzeGoFiles(ctx, ruleName, ctx.IsReportFile, analyze)
}

func analyzeGoFiles(
	ctx *core.GoProjectContext,
	ruleName string,
	inScope func(*core.FileContext) bool,
	analyze func(fileCtx *core.FileContext, info *types.Info) []*core.Violation,
) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", ruleName)
	}

	var violations []*core.Violation
	if inScope != nil {
		for _, fileCtx := range ctx.ReportFiles() {
			if fileCtx == nil || fileCtx.GoAST == nil {
				continue
			}
			info, loaded := ctx.ReportTypesInfo(fileCtx)
			if loaded && info == nil {
				return nil, fmt.Errorf("%s: package has no typed syntax", ruleName)
			}
			var fileInfo *types.Info
			if loaded {
				fileInfo = info
			}
			found := analyze(fileCtx, fileInfo)
			if err := validateRunFindings(inScope, fileCtx, ruleName, found); err != nil {
				return nil, err
			}
			violations = append(violations, found...)
		}
		sortViolations(violations)
		return violations, nil
	}
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
			if fileCtx.GoAST == nil || inScope != nil && !inScope(fileCtx) {
				continue
			}
			found := analyze(fileCtx, pkg.Package.TypesInfo)
			if err := validateRunFindings(inScope, fileCtx, ruleName, found); err != nil {
				return nil, err
			}
			violations = append(violations, found...)
		}
	}
	for _, fileCtx := range ctx.Files {
		if fileCtx == nil || fileCtx.GoAST == nil || typed[fileCtx] || inScope != nil && !inScope(fileCtx) {
			continue
		}
		found := analyze(fileCtx, nil)
		if err := validateRunFindings(inScope, fileCtx, ruleName, found); err != nil {
			return nil, err
		}
		violations = append(violations, found...)
	}

	sortViolations(violations)
	return violations, nil
}

func validateRunFindings(inScope func(*core.FileContext) bool, file *core.FileContext, ruleName string, found []*core.Violation) error {
	if inScope == nil {
		return nil
	}
	for _, violation := range found {
		if violation == nil || !sameFilePath(file, violation.File) {
			return fmt.Errorf("%s: report callback for %q returned a finding for %q", ruleName, file.RelPath, violationPath(violation))
		}
	}
	return nil
}

func sortViolations(violations []*core.Violation) {
	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
}
