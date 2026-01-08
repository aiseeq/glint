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

	currentLayer := r.determineLayer(ctx.RelPath)
	if currentLayer == unknownImportLayer {
		return nil
	}

	var violations []*core.Violation

	for _, imp := range ctx.GoAST.Imports {
		if imp.Path == nil {
			continue
		}

		importPath := strings.Trim(imp.Path.Value, `"`)
		importLayer := r.determineLayerFromImport(importPath)

		if importLayer == unknownImportLayer {
			continue
		}

		// Check for wrong direction imports
		if v := r.checkImportDirection(ctx, imp, currentLayer, importLayer, importPath); v != nil {
			violations = append(violations, v)
		}
	}

	return violations
}

type importLayerType int

const (
	unknownImportLayer importLayerType = iota
	handlerImportLayer
	serviceImportLayer
	repositoryImportLayer
)

func (r *ImportDirectionRule) determineLayer(path string) importLayerType {
	lowerPath := strings.ToLower(path)

	if strings.Contains(lowerPath, "handler") || strings.Contains(lowerPath, "/routing/") {
		return handlerImportLayer
	}
	if strings.Contains(lowerPath, "service") {
		return serviceImportLayer
	}
	if strings.Contains(lowerPath, "repository") || strings.Contains(lowerPath, "repo") {
		return repositoryImportLayer
	}

	return unknownImportLayer
}

func (r *ImportDirectionRule) determineLayerFromImport(importPath string) importLayerType {
	lowerPath := strings.ToLower(importPath)

	if strings.Contains(lowerPath, "/handlers") || strings.Contains(lowerPath, "/handler/") ||
		strings.Contains(lowerPath, "/routing/") {
		return handlerImportLayer
	}
	if strings.Contains(lowerPath, "/services") || strings.Contains(lowerPath, "/service/") {
		return serviceImportLayer
	}
	if strings.Contains(lowerPath, "/repository") || strings.Contains(lowerPath, "/repo/") ||
		strings.Contains(lowerPath, "/repositories") {
		return repositoryImportLayer
	}

	return unknownImportLayer
}

func (r *ImportDirectionRule) checkImportDirection(
	ctx *core.FileContext,
	imp *ast.ImportSpec,
	currentLayer, importLayer importLayerType,
	importPath string,
) *core.Violation {
	// Service importing from Handler (wrong direction)
	if currentLayer == serviceImportLayer && importLayer == handlerImportLayer {
		return r.createViolation(ctx, imp, "Service", "Handler", importPath)
	}

	// Repository importing from Service (wrong direction)
	if currentLayer == repositoryImportLayer && importLayer == serviceImportLayer {
		return r.createViolation(ctx, imp, "Repository", "Service", importPath)
	}

	// Repository importing from Handler (wrong direction - skipping a layer)
	if currentLayer == repositoryImportLayer && importLayer == handlerImportLayer {
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
