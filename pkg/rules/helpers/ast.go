// Package helpers provides shared utilities for rule implementations.
package helpers

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
)

// FuncBodyChecker is called for each function body to check for violations.
// It receives the file context and function body, and appends violations to the provided slice.
type FuncBodyChecker func(ctx *core.FileContext, body *ast.BlockStmt, violations *[]*core.Violation)

// FuncDeclChecker is called for each function declaration.
// It receives the file context, function declaration, and returns violations.
type FuncDeclChecker func(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation

// AnalyzeFuncBodies is a helper for rules that analyze function bodies.
// It handles the common boilerplate of:
// - Checking if AST exists
// - Iterating over function declarations
// - Filtering out functions without bodies
//
// Usage:
//
//	func (r *MyRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
//	    if !ctx.IsGoFile() || ctx.IsTestFile() {
//	        return nil
//	    }
//	    return helpers.AnalyzeFuncBodies(ctx, r.checkFunction)
//	}
func AnalyzeFuncBodies(ctx *core.FileContext, checker FuncBodyChecker) []*core.Violation {
	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		checker(ctx, fn.Body, &violations)
		return true
	})

	return violations
}

// AnalyzeFuncDecls is a helper for rules that need full function declarations.
// Use this when you need function name, receiver, etc. in addition to body.
func AnalyzeFuncDecls(ctx *core.FileContext, checker FuncDeclChecker) []*core.Violation {
	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		if vs := checker(ctx, fn); len(vs) > 0 {
			violations = append(violations, vs...)
		}
		return true
	})

	return violations
}

// PackageAliases returns the identifiers a file uses for an imported package.
// path is the quoted import path as written in source (`"regexp"`); defaultName
// is the package's own name, used when the import has no alias. Blank and dot
// imports give no identifier.
func PackageAliases(file *ast.File, path, defaultName string) map[string]bool {
	aliases := make(map[string]bool)
	for _, spec := range file.Imports {
		if spec.Path == nil || spec.Path.Value != path {
			continue
		}
		name := defaultName
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name != "_" && name != "." {
			aliases[name] = true
		}
	}
	return aliases
}
