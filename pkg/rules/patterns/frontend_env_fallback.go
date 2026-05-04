package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewFrontendEnvFallbackRule())
}

// FrontendEnvFallbackRule detects frontend public-env patterns that silently
// degrade at build/runtime instead of failing explicitly.
type FrontendEnvFallbackRule struct {
	*rules.BaseRule
	bracketNextPublicEnv *regexp.Regexp
	requiredSupabaseEnv  *regexp.Regexp
}

func NewFrontendEnvFallbackRule() *FrontendEnvFallbackRule {
	return &FrontendEnvFallbackRule{
		BaseRule: rules.NewBaseRule(
			"frontend-env-fallback",
			"patterns",
			"Detects placeholder and fallback public environment configuration in frontend code",
			core.SeverityCritical,
		),
		bracketNextPublicEnv: regexp.MustCompile(`process\.env\[['"]NEXT_PUBLIC_[A-Z0-9_]+['"]\]`),
		requiredSupabaseEnv:  regexp.MustCompile(`process\.env(?:\[['"]NEXT_PUBLIC_SUPABASE_(?:URL|ANON_KEY)['"]\]|\.NEXT_PUBLIC_SUPABASE_(?:URL|ANON_KEY))\s*(?:\|\||\?\?)`),
	}
}

func (r *FrontendEnvFallbackRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if r.shouldSkip(ctx) {
		return nil
	}

	var violations []*core.Violation
	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		switch {
		case strings.Contains(line, "placeholder.supabase.co") || strings.Contains(line, "placeholder-key"):
			violations = append(violations, r.violation(ctx, i+1, line,
				"Supabase placeholder configuration detected in frontend code",
				"Remove placeholder credentials. Required public config must fail explicitly when missing."))
		case r.bracketNextPublicEnv.MatchString(line):
			violations = append(violations, r.violation(ctx, i+1, line,
				"Bracket access for NEXT_PUBLIC env prevents reliable Next.js build-time inlining",
				"Use dot access like process.env.NEXT_PUBLIC_SUPABASE_URL, then validate required values explicitly."))
		case r.requiredSupabaseEnv.MatchString(line):
			violations = append(violations, r.violation(ctx, i+1, line,
				"Required Supabase public env uses a fallback operator",
				"Remove ||/?? fallback and throw an explicit error when Supabase public config is missing."))
		}
	}

	return violations
}

func (r *FrontendEnvFallbackRule) shouldSkip(ctx *core.FileContext) bool {
	path := ctx.RelPath
	if ctx.IsTestFile() {
		return true
	}
	return strings.Contains(path, "/node_modules/") ||
		strings.Contains(path, "/.next/") ||
		strings.Contains(path, "/out/") ||
		strings.Contains(path, "/dist/")
}

func (r *FrontendEnvFallbackRule) violation(ctx *core.FileContext, lineNum int, line string, msg string, suggestion string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, lineNum, msg)
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion(suggestion)
	v.WithContext("pattern", "frontend-env-fallback")
	v.WithContext("language", "typescript")
	return v
}
