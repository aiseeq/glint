package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSilentConfigErrorRule())
}

// SilentConfigErrorRule detects silent error ignoring in config/bootstrap code.
// CLAUDE.md: "Fail explicitly, never degrade silently" — absolute rule; in
// config/env-loading paths it is critical because misconfiguration stays
// invisible until a much later failure.
//
// Unlike the generic `ignored-error` rule, this one intentionally does NOT
// honor `//nolint:errcheck` — policy forbids the pattern regardless of the
// linter suppression.
//
// Detects in files whose path contains `/config/` OR matches
// `**/bootstrap_environment_loader.go` / `**/unified_config*.go`:
//   - `_ = X()` where X is an env/config-loading call (ReadEnv, Load,
//     loadEnvFileDirectly, godotenv.Load, cleanenv.ReadConfig, etc.)
//   - Bare call `X()` whose error return is dropped entirely (no assignment)
//     for the same set of env/config functions.
//
// Skips:
//   - Test files / test utility files
//   - Generated files
type SilentConfigErrorRule struct {
	*rules.BaseRule
}

// NewSilentConfigErrorRule creates the rule
func NewSilentConfigErrorRule() *SilentConfigErrorRule {
	return &SilentConfigErrorRule{
		BaseRule: rules.NewBaseRule(
			"silent-config-error",
			"patterns",
			"Detects silently-ignored env/config load errors in config/bootstrap paths (CLAUDE.md: Fail explicitly, never degrade silently)",
			core.SeverityCritical,
		),
	}
}

// configLoadFuncNames — function-name fragments that indicate an env/config
// load call. Matched against the fully-qualified callee name (e.g.
// `cleanenv.ReadEnv`, `godotenv.Load`, `c.loadEnvFileDirectly`).
var configLoadFuncNames = []string{
	"cleanenv.readenv",
	"cleanenv.readconfig",
	"godotenv.load",
	"godotenv.overload",
	"loadenvfile",      // *.loadEnvFile / *.loadEnvFileDirectly
	"loadenvironment",  // *.loadEnvironment / *.loadEnvironmentFile
	"readenvironment",  // *.readEnvironment
	"applyenvironment", // applyEnvironmentFixes / applyEnvironment
	"parseenv",         // parseEnv / parseEnvironment
	"viper.readinconfig",
	"viper.mergeconfig",
}

// AnalyzeFile checks for silent config errors
func (r *SilentConfigErrorRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() {
		return nil
	}

	path := strings.ToLower(ctx.RelPath)

	// Skip generated + _test.go (real unit tests may legitimately use
	// `err == nil` patterns; test helpers under /tests/common/ are still
	// scanned because the callee-gated check is narrow).
	if strings.HasSuffix(path, ".gen.go") || strings.HasSuffix(path, "_gen.go") ||
		strings.Contains(path, "/generated/") || strings.Contains(path, "vendor/") ||
		strings.HasSuffix(path, "_test.go") {
		return nil
	}

	var violations []*core.Violation

	// Path-gated checks: noisy, only run inside config/bootstrap paths and
	// skip everything that looks like a test file/helper.
	if r.isConfigPath(path) && !ctx.IsTestFile() {
		ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				if v := r.checkBlankAssignment(ctx, node); v != nil {
					violations = append(violations, v)
				}
			case *ast.ExprStmt:
				if v := r.checkBareCall(ctx, node); v != nil {
					violations = append(violations, v)
				}
			}
			return true
		})
	}

	// Callee-gated check: the `err == nil` swallow pattern is specific enough
	// to run everywhere (incl. test helpers) — trigger only on config-load callees.
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		violations = append(violations, r.checkErrNilSwallowInBlock(ctx, block)...)
		return true
	})

	return violations
}

// isConfigPath reports whether the file is part of the config/bootstrap paths
// where silent degradation is not tolerated.
func (r *SilentConfigErrorRule) isConfigPath(pathLower string) bool {
	if strings.Contains(pathLower, "/config/") || strings.HasPrefix(pathLower, "config/") {
		return true
	}
	if strings.Contains(pathLower, "bootstrap_environment_loader") {
		return true
	}
	if strings.Contains(pathLower, "unified_config") {
		return true
	}
	return false
}

// checkBlankAssignment catches `_ = X()` patterns where X is a config-load call.
func (r *SilentConfigErrorRule) checkBlankAssignment(ctx *core.FileContext, stmt *ast.AssignStmt) *core.Violation {
	if len(stmt.Lhs) != 1 || len(stmt.Rhs) != 1 {
		return nil
	}

	lhsIdent, ok := stmt.Lhs[0].(*ast.Ident)
	if !ok || lhsIdent.Name != "_" {
		return nil
	}

	call, ok := stmt.Rhs[0].(*ast.CallExpr)
	if !ok {
		return nil
	}

	funcName := core.ExtractFullFunctionName(call)
	if !r.isConfigLoadCall(funcName) {
		return nil
	}

	pos := ctx.PositionFor(stmt)
	lineContent := ctx.GetLine(pos.Line)

	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"Silently ignored error from "+funcName+" — config error must be explicit")
	v.WithCode(strings.TrimSpace(lineContent))
	v.WithSuggestion("Assign the error to a variable and handle it: `if err := " + funcName +
		"(...); err != nil { return fmt.Errorf(...) }`. CLAUDE.md: \"Fail explicitly, never degrade silently\" — " +
		"this is absolute for config/env-loading paths.")
	return v
}

// checkBareCall catches bare `X(...)` calls whose error return is dropped
// entirely (no assignment, no `_ =`) for config-load functions.
func (r *SilentConfigErrorRule) checkBareCall(ctx *core.FileContext, stmt *ast.ExprStmt) *core.Violation {
	call, ok := stmt.X.(*ast.CallExpr)
	if !ok {
		return nil
	}

	funcName := core.ExtractFullFunctionName(call)
	if !r.isConfigLoadCall(funcName) {
		return nil
	}

	pos := ctx.PositionFor(stmt)
	lineContent := ctx.GetLine(pos.Line)

	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"Dropped error return from "+funcName+" — config error must be explicit")
	v.WithCode(strings.TrimSpace(lineContent))
	v.WithSuggestion("Capture and handle the error: `if err := " + funcName +
		"(...); err != nil { ... }`. CLAUDE.md: \"Fail explicitly, never degrade silently\".")
	return v
}

// isConfigLoadCall reports whether the fully-qualified callee name indicates
// an env/config load function whose error must not be silently dropped.
func (r *SilentConfigErrorRule) isConfigLoadCall(funcName string) bool {
	lower := strings.ToLower(funcName)
	for _, needle := range configLoadFuncNames {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	// Project-wide config loaders: LoadUnifiedConfig, LoadConfig, NewConfig.
	// These are aggregators over the env/godotenv functions above — dropping
	// their error hides the same class of misconfiguration.
	if strings.HasSuffix(lower, ".loadunifiedconfig") ||
		strings.HasSuffix(lower, ".loadconfig") ||
		lower == "loadunifiedconfig" || lower == "loadconfig" {
		return true
	}
	return false
}

// checkErrNilSwallowInBlock walks a block looking for the `err == nil` swallow
// pattern: either an inline `if err := X(); err == nil { ... }` with no else,
// or a prior `_, err := X()` immediately followed by `if err == nil { ... }`
// whose fall-through path silently continues.
//
// Why flag `err == nil`: the canonical Go pattern is `if err != nil { return err }`.
// The inverted `err == nil` check is almost always a silent-ignore smell —
// success is handled, the error path is implicit fall-through.
func (r *SilentConfigErrorRule) checkErrNilSwallowInBlock(ctx *core.FileContext, block *ast.BlockStmt) []*core.Violation {
	var violations []*core.Violation
	for i, stmt := range block.List {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}
		// Case 1: `if err := X(); err == nil { ... }` (inline init).
		if ifStmt.Init != nil {
			if v := r.checkInlineErrNilSwallow(ctx, ifStmt); v != nil {
				violations = append(violations, v)
			}
			continue
		}
		// Case 2: preceding `_, err := X()` then `if err == nil { ... }`.
		if i == 0 {
			continue
		}
		prevAssign, ok := block.List[i-1].(*ast.AssignStmt)
		if !ok {
			continue
		}
		if v := r.checkPrecedingAssignErrNilSwallow(ctx, prevAssign, ifStmt); v != nil {
			violations = append(violations, v)
		}
	}
	return violations
}

// checkInlineErrNilSwallow handles `if err := X(); err == nil { ... }` with
// no else (or empty else). Fires only when X is a config-load callee.
func (r *SilentConfigErrorRule) checkInlineErrNilSwallow(ctx *core.FileContext, ifStmt *ast.IfStmt) *core.Violation {
	assign, ok := ifStmt.Init.(*ast.AssignStmt)
	if !ok {
		return nil
	}
	callee := configLoadCalleeFromAssign(assign)
	if callee == "" || !r.isConfigLoadCall(callee) {
		return nil
	}
	if !isErrEqNilCheck(ifStmt.Cond, assign) {
		return nil
	}
	// Skip when the else branch handles the error (returns / logs).
	if hasErrorHandlingElse(ifStmt) {
		return nil
	}

	pos := ctx.PositionFor(ifStmt)
	lineContent := ctx.GetLine(pos.Line)
	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"`if err := "+callee+"(); err == nil { ... }` — error path silently falls through")
	v.WithCode(strings.TrimSpace(lineContent))
	v.WithSuggestion("Invert the check: `if err := " + callee +
		"(...); err != nil { return fmt.Errorf(...) }`. CLAUDE.md: \"Fail explicitly, never degrade silently\".")
	return v
}

// checkPrecedingAssignErrNilSwallow handles the 2-statement form:
//
//	cfg, err := config.LoadUnifiedConfig()
//	if err == nil { ... }
//
// The error path is the implicit fall-through after the if.
func (r *SilentConfigErrorRule) checkPrecedingAssignErrNilSwallow(ctx *core.FileContext, assign *ast.AssignStmt, ifStmt *ast.IfStmt) *core.Violation {
	callee := configLoadCalleeFromAssign(assign)
	if callee == "" || !r.isConfigLoadCall(callee) {
		return nil
	}
	if !isErrEqNilCheck(ifStmt.Cond, assign) {
		return nil
	}
	if hasErrorHandlingElse(ifStmt) {
		return nil
	}
	pos := ctx.PositionFor(ifStmt)
	lineContent := ctx.GetLine(pos.Line)
	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"`if err == nil { ... }` after "+callee+"() — error falls through to silent default")
	v.WithCode(strings.TrimSpace(lineContent))
	v.WithSuggestion("Handle the error explicitly: `if err != nil { return fmt.Errorf(...) }`. " +
		"CLAUDE.md: \"Fail explicitly, never degrade silently\".")
	return v
}

// configLoadCalleeFromAssign returns the callee name if the assignment's RHS
// is a single call and one of its return targets is a variable named `err`.
// Returns "" otherwise.
func configLoadCalleeFromAssign(assign *ast.AssignStmt) string {
	if len(assign.Rhs) != 1 {
		return ""
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return ""
	}
	hasErr := false
	for _, lhs := range assign.Lhs {
		if id, ok := lhs.(*ast.Ident); ok && id.Name == "err" {
			hasErr = true
			break
		}
	}
	if !hasErr {
		return ""
	}
	return core.ExtractFullFunctionName(call)
}

// isErrEqNilCheck reports whether cond is `err == nil` referring to the same
// err variable assigned by `assign`.
func isErrEqNilCheck(cond ast.Expr, _ *ast.AssignStmt) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op.String() != "==" {
		return false
	}
	var idName string
	if id, ok := bin.X.(*ast.Ident); ok {
		idName = id.Name
	} else if id, ok := bin.Y.(*ast.Ident); ok {
		idName = id.Name
	}
	if idName != "err" {
		return false
	}
	if id, ok := bin.X.(*ast.Ident); ok && id.Name == "nil" {
		return true
	}
	if id, ok := bin.Y.(*ast.Ident); ok && id.Name == "nil" {
		return true
	}
	return false
}

// hasErrorHandlingElse reports whether the if-stmt has an else that contains a
// return/log/fatal — i.e., the error path is explicitly handled.
func hasErrorHandlingElse(ifStmt *ast.IfStmt) bool {
	if ifStmt.Else == nil {
		return false
	}
	block, ok := ifStmt.Else.(*ast.BlockStmt)
	if !ok {
		return false
	}
	for _, s := range block.List {
		switch st := s.(type) {
		case *ast.ReturnStmt:
			if len(st.Results) > 0 {
				// Returns something — assume it propagates error.
				return true
			}
		case *ast.ExprStmt:
			if call, ok := st.X.(*ast.CallExpr); ok {
				name := strings.ToLower(core.ExtractFullFunctionName(call))
				if strings.Contains(name, "fatal") || strings.Contains(name, "panic") ||
					strings.Contains(name, "error") || strings.Contains(name, "warn") {
					return true
				}
			}
		}
	}
	return false
}
