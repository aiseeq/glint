package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewShadowVariableRule())
}

// ShadowVariableRule detects variable shadowing
type ShadowVariableRule struct {
	*rules.BaseRule
	// Common Go variable names that are safe to shadow
	safeToShadow map[string]bool
}

// NewShadowVariableRule creates the rule
func NewShadowVariableRule() *ShadowVariableRule {
	return &ShadowVariableRule{
		BaseRule: rules.NewBaseRule(
			"shadow-variable",
			"patterns",
			"Detects variable shadowing (same name in nested scope)",
			core.SeverityMedium,
		),
		safeToShadow: map[string]bool{
			"err": true, // Very common in Go error handling
			"ok":  true, // Common in map/type assertion checks
			"i":   true, // Loop counter
			"j":   true, // Nested loop counter
			"k":   true, // Third loop counter
			"v":   true, // Common value placeholder
			"n":   true, // Common count variable
		},
	}
}

// AnalyzeFile checks for variable shadowing
func (r *ShadowVariableRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		if fn.Body == nil {
			return true
		}

		// Collect parameter and receiver names
		outerScope := make(map[string]int) // name -> line

		// Add receiver if present
		if fn.Recv != nil {
			for _, field := range fn.Recv.List {
				for _, name := range field.Names {
					if name.Name != "_" {
						outerScope[name.Name] = r.getLineFromNode(ctx, name)
					}
				}
			}
		}

		// Add parameters
		if fn.Type.Params != nil {
			for _, field := range fn.Type.Params.List {
				for _, name := range field.Names {
					if name.Name != "_" {
						outerScope[name.Name] = r.getLineFromNode(ctx, name)
					}
				}
			}
		}

		// Check function body for shadowing
		r.checkBlock(ctx, fn.Body, outerScope, &violations)

		return true
	})

	return violations
}

func (r *ShadowVariableRule) checkBlock(ctx *core.FileContext, block *ast.BlockStmt, outerScope map[string]int, violations *[]*core.Violation) {
	if block == nil {
		return
	}

	// Create new scope for this block
	currentScope := make(map[string]int)
	for k, v := range outerScope {
		currentScope[k] = v
	}

	for _, stmt := range block.List {
		r.checkStmt(ctx, stmt, currentScope, outerScope, violations)
	}
}

func (r *ShadowVariableRule) checkStmt(ctx *core.FileContext, stmt ast.Stmt, currentScope, outerScope map[string]int, violations *[]*core.Violation) {
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		if s.Tok.String() == ":=" {
			for _, lhs := range s.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
					if origLine, exists := outerScope[ident.Name]; exists && !r.safeToShadow[ident.Name] {
						line := r.getLineFromNode(ctx, ident)
						v := r.CreateViolation(ctx.RelPath, line, "Variable '"+ident.Name+"' shadows declaration from line "+r.itoa(origLine))
						v.WithCode(ctx.GetLine(line))
						v.WithSuggestion("Use a different variable name to avoid confusion")
						v.WithContext("pattern", "shadow_variable")
						v.WithContext("shadowed_name", ident.Name)
						*violations = append(*violations, v)
					}
					currentScope[ident.Name] = r.getLineFromNode(ctx, ident)
				}
			}
		}

	case *ast.DeclStmt:
		if genDecl, ok := s.Decl.(*ast.GenDecl); ok {
			for _, spec := range genDecl.Specs {
				if valueSpec, ok := spec.(*ast.ValueSpec); ok {
					for _, name := range valueSpec.Names {
						if name.Name != "_" {
							if origLine, exists := outerScope[name.Name]; exists && !r.safeToShadow[name.Name] {
								line := r.getLineFromNode(ctx, name)
								v := r.CreateViolation(ctx.RelPath, line, "Variable '"+name.Name+"' shadows declaration from line "+r.itoa(origLine))
								v.WithCode(ctx.GetLine(line))
								v.WithSuggestion("Use a different variable name to avoid confusion")
								v.WithContext("pattern", "shadow_variable")
								v.WithContext("shadowed_name", name.Name)
								*violations = append(*violations, v)
							}
							currentScope[name.Name] = r.getLineFromNode(ctx, name)
						}
					}
				}
			}
		}

	case *ast.IfStmt:
		// Check init statement
		if s.Init != nil {
			r.checkStmt(ctx, s.Init, currentScope, outerScope, violations)
		}
		// Check body with merged scopes
		mergedScope := make(map[string]int)
		for k, v := range currentScope {
			mergedScope[k] = v
		}
		r.checkBlock(ctx, s.Body, mergedScope, violations)
		if s.Else != nil {
			if elseBlock, ok := s.Else.(*ast.BlockStmt); ok {
				r.checkBlock(ctx, elseBlock, mergedScope, violations)
			} else if elseIf, ok := s.Else.(*ast.IfStmt); ok {
				r.checkStmt(ctx, elseIf, mergedScope, outerScope, violations)
			}
		}

	case *ast.ForStmt:
		mergedScope := make(map[string]int)
		for k, v := range currentScope {
			mergedScope[k] = v
		}
		if s.Init != nil {
			r.checkStmt(ctx, s.Init, mergedScope, outerScope, violations)
		}
		r.checkBlock(ctx, s.Body, mergedScope, violations)

	case *ast.RangeStmt:
		mergedScope := make(map[string]int)
		for k, v := range currentScope {
			mergedScope[k] = v
		}
		// Check range variables
		if s.Tok.String() == ":=" {
			if key, ok := s.Key.(*ast.Ident); ok && key.Name != "_" {
				if origLine, exists := outerScope[key.Name]; exists && !r.safeToShadow[key.Name] {
					line := r.getLineFromNode(ctx, key)
					v := r.CreateViolation(ctx.RelPath, line, "Variable '"+key.Name+"' shadows declaration from line "+r.itoa(origLine))
					v.WithCode(ctx.GetLine(line))
					v.WithSuggestion("Use a different variable name to avoid confusion")
					v.WithContext("pattern", "shadow_variable")
					*violations = append(*violations, v)
				}
				mergedScope[key.Name] = r.getLineFromNode(ctx, key)
			}
			if s.Value != nil {
				if value, ok := s.Value.(*ast.Ident); ok && value.Name != "_" {
					if origLine, exists := outerScope[value.Name]; exists && !r.safeToShadow[value.Name] {
						line := r.getLineFromNode(ctx, value)
						v := r.CreateViolation(ctx.RelPath, line, "Variable '"+value.Name+"' shadows declaration from line "+r.itoa(origLine))
						v.WithCode(ctx.GetLine(line))
						v.WithSuggestion("Use a different variable name to avoid confusion")
						v.WithContext("pattern", "shadow_variable")
						*violations = append(*violations, v)
					}
					mergedScope[value.Name] = r.getLineFromNode(ctx, value)
				}
			}
		}
		r.checkBlock(ctx, s.Body, mergedScope, violations)

	case *ast.BlockStmt:
		r.checkBlock(ctx, s, currentScope, violations)
	}
}

func (r *ShadowVariableRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
	if node == nil {
		return 1
	}

	pos := node.Pos()
	if pos == 0 {
		return 1
	}

	offset := int(pos) - 1
	if offset < 0 || offset >= len(ctx.Content) {
		return 1
	}

	line := 1
	for i := 0; i < offset && i < len(ctx.Content); i++ {
		if ctx.Content[i] == '\n' {
			line++
		}
	}
	return line
}

func (r *ShadowVariableRule) itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
