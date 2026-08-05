package patterns

import (
	"go/ast"
	"go/token"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewRedundantCompatibilityRule())
}

// RedundantCompatibilityRule detects false backward compatibility patterns
// This implements CLAUDE.md principles:
// - "Delete cleanly, git remembers" - no fake compatibility
// - SRP - one way to do one thing
// Catches:
// - Multiple context key fallbacks (GetAdminIDFromContext checking 3 different keys)
// - False "backward compatibility" comments without external API consumers
// - Duplicate key definitions (AdminIDKey vs AdminIDKeyAlt)
type RedundantCompatibilityRule struct {
	*rules.BaseRule
	compatibilityCommentPatterns []*regexp.Regexp
}

// NewRedundantCompatibilityRule creates the rule
func NewRedundantCompatibilityRule() *RedundantCompatibilityRule {
	r := &RedundantCompatibilityRule{
		BaseRule: rules.NewBaseRule(
			"redundant-compatibility",
			"patterns",
			"Detects false backward compatibility patterns that violate SRP",
			core.SeverityMedium,
		),
	}
	r.compatibilityCommentPatterns = r.initCompatibilityCommentPatterns()
	return r
}

// initCompatibilityCommentPatterns initializes patterns for detecting false compatibility comments
func (r *RedundantCompatibilityRule) initCompatibilityCommentPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// Russian compatibility mentions
		regexp.MustCompile(`(?i)обратн\w*\s*совместим`),
		regexp.MustCompile(`(?i)для\s+совместимости`),
		regexp.MustCompile(`(?i)legacy\s*support`),
		regexp.MustCompile(`(?i)backward\s*compat`),
		regexp.MustCompile(`(?i)backwards\s*compat`),
		regexp.MustCompile(`(?i)for\s+compatibility`),
		// Fallback key patterns
		regexp.MustCompile(`(?i)fallback:?\s*(?:check|проверяем|key)`),
		regexp.MustCompile(`(?i)alt(?:ernative)?\s*key`),
	}
}

// AnalyzeFile checks for redundant compatibility patterns
func (r *RedundantCompatibilityRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if r.shouldSkipFile(ctx) {
		return nil
	}

	var violations []*core.Violation

	if ctx.IsGoFile() {
		violations = append(violations, r.analyzeGoFile(ctx)...)
	}

	return violations
}

// shouldSkipFile checks if file should be excluded
func (r *RedundantCompatibilityRule) shouldSkipFile(ctx *core.FileContext) bool {
	return ctx.IsTestFile() || isVendoredOrGeneratedPath(ctx.RelPath)
}

// analyzeGoFile analyzes Go file for redundant compatibility patterns
func (r *RedundantCompatibilityRule) analyzeGoFile(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	// Check for false compatibility comments
	violations = append(violations, r.detectFalseCompatibilityComments(ctx)...)

	// AST-based: detect multiple context key fallbacks
	if ctx.HasGoAST() {
		violations = append(violations, r.detectMultipleContextKeyFallbacks(ctx)...)
		violations = append(violations, r.detectDuplicateKeyDefinitions(ctx)...)
	}

	return violations
}

// detectFalseCompatibilityComments finds comments claiming backward compatibility
func (r *RedundantCompatibilityRule) detectFalseCompatibilityComments(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		// Only check comments
		if !strings.Contains(line, "//") {
			continue
		}

		commentIdx := strings.Index(line, "//")
		comment := line[commentIdx:]

		for _, pattern := range r.compatibilityCommentPatterns {
			if pattern.MatchString(comment) {
				// Skip if this is in an actual API compatibility layer
				if r.isLegitimateCompatibilityContext(ctx, lineNum) {
					continue
				}

				v := r.CreateViolation(ctx.RelPath, lineNum+1, "False backward compatibility claim - no external API consumers exist")
				v.WithCode(strings.TrimSpace(line))
				v.WithSuggestion("Remove compatibility comment and consolidate to single implementation. Git remembers history.")
				v.WithContext("pattern", "false-compatibility-comment")
				violations = append(violations, v)
				break
			}
		}
	}

	return violations
}

// detectMultipleContextKeyFallbacks finds functions where the results of
// ctx.Value calls with different keys merge into a single destination — the
// evidence of a fallback chain. A function that reads userID and requestID
// into separate variables reads two different values and is left alone.
func (r *RedundantCompatibilityRule) detectMultipleContextKeyFallbacks(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		fallbackKeys := r.fallbackKeys(fn.Body)
		if len(fallbackKeys) >= 2 {
			// Results of ctx.Value with distinct keys merge into one destination
			v := r.CreateViolation(ctx.RelPath, ctx.PositionFor(fn).Line,
				"Multiple context key fallbacks detected - SRP violation")
			v.WithCode("func " + fn.Name.Name + " checks " + strings.Join(fallbackKeys, ", "))
			v.WithSuggestion("Unify context keys. One value should be set/retrieved with one key only.")
			v.WithContext("pattern", "multiple-context-keys")
			v.WithContext("keys_count", len(fallbackKeys))
			violations = append(violations, v)
		}

		return true
	})

	return violations
}

// fallbackKeys returns the distinct ctx.Value keys whose results flow into the
// same destination: assignments to one variable name or the function's return
// path. Only such merging proves a fallback chain.
func (r *RedundantCompatibilityRule) fallbackKeys(body *ast.BlockStmt) []string {
	sinkKeys := make(map[string][]string)
	seen := make(map[string]map[string]bool)
	var sinkOrder []string

	record := func(sink, key string) {
		if seen[sink] == nil {
			seen[sink] = make(map[string]bool)
			sinkOrder = append(sinkOrder, sink)
		}
		if !seen[sink][key] {
			seen[sink][key] = true
			sinkKeys[sink] = append(sinkKeys[sink], key)
		}
	}

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, rhs := range node.Rhs {
				key := r.ctxValueKey(rhs)
				if key == "" {
					continue
				}
				if ident, ok := node.Lhs[i].(*ast.Ident); ok {
					record("var "+ident.Name, key)
				}
			}
		case *ast.ReturnStmt:
			for _, result := range node.Results {
				if key := r.ctxValueKey(result); key != "" {
					record("return", key)
				}
			}
		}
		return true
	})

	var keys []string
	added := make(map[string]bool)
	for _, sink := range sinkOrder {
		if len(sinkKeys[sink]) < 2 {
			continue
		}
		for _, key := range sinkKeys[sink] {
			if !added[key] {
				added[key] = true
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// ctxValueKey extracts the key name from a ctx.Value(key) call (possibly
// wrapped in a type assertion), or "" when expr is not such a call.
func (r *RedundantCompatibilityRule) ctxValueKey(expr ast.Expr) string {
	if assertion, ok := expr.(*ast.TypeAssertExpr); ok {
		expr = assertion.X
	}

	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}

	// Check for ctx.Value(key) or context.Value(key) pattern
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Value" {
		return ""
	}

	// Check if receiver looks like context (ctx, c, context, etc.)
	receiverName := ""
	if ident, ok := sel.X.(*ast.Ident); ok {
		receiverName = strings.ToLower(ident.Name)
	}
	if !strings.Contains(receiverName, "ctx") && receiverName != "c" && receiverName != "context" {
		return ""
	}

	if len(call.Args) != 1 {
		return ""
	}
	return r.extractKeyName(call.Args[0])
}

// extractKeyName extracts the key name from ctx.Value argument
func (r *RedundantCompatibilityRule) extractKeyName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		// constants.UserIDKey -> UserIDKey
		return e.Sel.Name
	}
	return ""
}

// detectDuplicateKeyDefinitions finds duplicate key definitions (AdminIDKey + AdminIDKeyAlt)
func (r *RedundantCompatibilityRule) detectDuplicateKeyDefinitions(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	// Collect all context key definitions
	keyDefs := make(map[string][]keyDefinition)

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		// Check for const or var declarations
		genDecl, ok := n.(*ast.GenDecl)
		if !ok {
			return true
		}

		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for _, name := range valueSpec.Names {
				nameLower := strings.ToLower(name.Name)
				// Look for *Key, *KeyAlt patterns
				if strings.HasSuffix(nameLower, "key") || strings.HasSuffix(nameLower, "keyalt") {
					// Extract base name (remove Alt, _alt, etc.)
					baseName := r.getBaseKeyName(name.Name)
					keyDefs[baseName] = append(keyDefs[baseName], keyDefinition{
						name: name.Name,
						pos:  ctx.PositionFor(name),
					})
				}
			}
		}

		return true
	})

	// Report duplicates
	for _, baseName := range slices.Sorted(maps.Keys(keyDefs)) {
		defs := keyDefs[baseName]
		if len(defs) >= 2 {
			names := make([]string, len(defs))
			for i, d := range defs {
				names[i] = d.name
			}

			v := r.CreateViolation(ctx.RelPath, defs[0].pos.Line,
				"Duplicate context key definitions for same purpose")
			v.WithCode("Keys: " + strings.Join(names, ", ") + " (base: " + baseName + ")")
			v.WithSuggestion("Consolidate to single key. Multiple keys for same value violates SRP.")
			v.WithContext("pattern", "duplicate-key-definitions")
			violations = append(violations, v)
		}
	}

	return violations
}

type keyDefinition struct {
	name string
	pos  token.Position
}

// getBaseKeyName extracts base name from key (AdminIDKeyAlt -> AdminIDKey)
func (r *RedundantCompatibilityRule) getBaseKeyName(name string) string {
	nameLower := strings.ToLower(name)

	// Remove common alt suffixes
	suffixes := []string{"alt", "_alt", "alternative", "fallback", "backup", "2", "v2"}
	for _, suffix := range suffixes {
		if strings.HasSuffix(nameLower, suffix) {
			// Remove suffix preserving case
			return name[:len(name)-len(suffix)]
		}
	}

	return name
}

// isLegitimateCompatibilityContext checks if this is a real API compatibility layer
func (r *RedundantCompatibilityRule) isLegitimateCompatibilityContext(ctx *core.FileContext, lineNum int) bool {
	path := ctx.RelPath

	// API versioning layers are legitimate
	if strings.Contains(path, "/v1/") || strings.Contains(path, "/v2/") ||
		strings.Contains(path, "api_compat") || strings.Contains(path, "migration") {
		return true
	}

	// Check if file is an actual compatibility/adapter layer
	if strings.Contains(path, "adapter") || strings.Contains(path, "compat") {
		return true
	}

	// Check surrounding code for external API indicators
	start := lineNum - 10
	if start < 0 {
		start = 0
	}
	end := lineNum + 5
	if end >= len(ctx.Lines) {
		end = len(ctx.Lines) - 1
	}

	for i := start; i <= end; i++ {
		line := strings.ToLower(ctx.Lines[i])
		// External API compatibility is legitimate
		if strings.Contains(line, "external api") || strings.Contains(line, "public api") ||
			strings.Contains(line, "external client") || strings.Contains(line, "third party") {
			return true
		}
	}

	return false
}
