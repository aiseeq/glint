package doccheck

import (
	"fmt"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewPackageDocNameRule())
}

// PackageDocNameRule detects a package doc comment that names another package:
//
//	// Package registry keeps the list of entries.
//	package catalog
//
// It is what a rename leaves behind: the package clause changes, the doc keeps
// the old name, and a reader who looks the package up by its doc finds nothing.
// Only a doc that opens with the word "Package" names a package; a command's
// doc ("Command x …") and prose are left alone.
type PackageDocNameRule struct {
	*rules.BaseRule
}

// NewPackageDocNameRule creates the rule
func NewPackageDocNameRule() *PackageDocNameRule {
	return &PackageDocNameRule{
		BaseRule: rules.NewBaseRule(
			"package-doc-name",
			"documentation",
			"Detects a package doc comment `// Package X` whose X is not the name of the package — the doc kept an old name",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile compares the package doc of one file with its package clause.
func (r *PackageDocNameRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil || ctx.GoAST.Doc == nil {
		return nil
	}
	fields := strings.Fields(ctx.GoAST.Doc.Text())
	if len(fields) < 2 || fields[0] != "Package" {
		return nil
	}
	named := strings.TrimRight(fields[1], ".,:;—-")
	actual := ctx.GoAST.Name.Name
	if named == actual {
		return nil
	}
	line := ctx.LineFor(ctx.GoAST.Doc)
	v := r.CreateViolation(ctx.RelPath, line,
		fmt.Sprintf("Package doc names package %s, but the package is %s", named, actual))
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Start the doc with \"Package %s\"", actual))
	v.WithContext("pattern", "package_doc_name")
	return []*core.Violation{v}
}
