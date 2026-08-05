package architecture

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewImportDirectionRule())
}

// ImportDirectionRule checks that imports respect layered architecture direction
// Handler → Service → Repository (imports should flow downward)
type ImportDirectionRule struct {
	*rules.BaseRule
}

// NewImportDirectionRule creates the rule
func NewImportDirectionRule() *ImportDirectionRule {
	return &ImportDirectionRule{
		BaseRule: rules.NewBaseRule(
			"import-direction",
			"architecture",
			"Detects imports that violate layered architecture direction (Service→Handler, Repo→Service)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks for import direction violations
func (r *ImportDirectionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	currentLayer := determineLayerFromPath(ctx.RelPath)
	if currentLayer == UnknownLayer {
		return nil
	}

	var violations []*core.Violation

	for _, imp := range ctx.GoAST.Imports {
		if imp.Path == nil {
			continue
		}

		importPath := strings.Trim(imp.Path.Value, `"`)
		importLayer := r.determineLayerFromImport(importPath)

		if importLayer == UnknownLayer {
			continue
		}

		// Check for wrong direction imports
		if v := r.checkImportDirection(ctx, imp, currentLayer, importLayer, importPath); v != nil {
			violations = append(violations, v)
		}
	}

	return violations
}

func (r *ImportDirectionRule) determineLayerFromImport(importPath string) LayerType {
	lowerPath := strings.ToLower(importPath)

	if strings.Contains(lowerPath, "/handlers") || strings.Contains(lowerPath, "/handler/") ||
		strings.Contains(lowerPath, "/routing/") {
		return HandlerLayer
	}
	if strings.Contains(lowerPath, "/services") || strings.Contains(lowerPath, "/service/") {
		return ServiceLayer
	}
	if strings.Contains(lowerPath, "/repository") || strings.Contains(lowerPath, "/repo/") ||
		strings.Contains(lowerPath, "/repositories") {
		return RepositoryLayer
	}

	return UnknownLayer
}

func (r *ImportDirectionRule) checkImportDirection(
	ctx *core.FileContext,
	imp *ast.ImportSpec,
	currentLayer, importLayer LayerType,
	importPath string,
) *core.Violation {
	// Service importing from Handler (wrong direction)
	if currentLayer == ServiceLayer && importLayer == HandlerLayer {
		return r.createViolation(ctx, imp, "Service", "Handler", importPath)
	}

	// Repository importing from Service (wrong direction)
	if currentLayer == RepositoryLayer && importLayer == ServiceLayer {
		return r.createViolation(ctx, imp, "Repository", "Service", importPath)
	}

	// Repository importing from Handler (wrong direction - skipping a layer)
	if currentLayer == RepositoryLayer && importLayer == HandlerLayer {
		return r.createViolation(ctx, imp, "Repository", "Handler", importPath)
	}

	return nil
}

func (r *ImportDirectionRule) createViolation(
	ctx *core.FileContext,
	imp *ast.ImportSpec,
	currentLayerName, importLayerName, importPath string,
) *core.Violation {
	pos := ctx.PositionFor(imp)

	v := r.CreateViolation(ctx.RelPath, pos.Line,
		currentLayerName+" imports from "+importLayerName+" (violates Handler→Service→Repository direction)")
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Imports should flow downward: Handler→Service→Repository. " +
		"Consider restructuring to maintain proper dependency direction.")
	v.WithContext("current_layer", currentLayerName)
	v.WithContext("import_layer", importLayerName)
	v.WithContext("import_path", importPath)

	return v
}
