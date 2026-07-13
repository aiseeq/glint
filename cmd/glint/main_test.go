package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns"
	"github.com/aiseeq/glint/pkg/rules/typesafety"
)

func TestGetProjectRootExpandsRecursiveCurrentDirectory(t *testing.T) {
	want, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	got, err := getProjectRoot([]string{"./..."})
	if err != nil {
		t.Fatalf("get project root: %v", err)
	}
	if got != want {
		t.Fatalf("got project root %q, want %q", got, want)
	}
}

func TestGetProjectRootRejectsMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	_, err := getProjectRoot([]string{missing})
	if err == nil {
		t.Fatal("expected missing project root to return an error")
	}
}

func goContext(t *testing.T, name, code string) *core.FileContext {
	t.Helper()
	ctx := core.NewFileContext(name, ".", []byte(code), nil)
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile(name, []byte(code))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx.SetGoAST(fset, astFile)
	return ctx
}

// Подавление применяется пайплайном единообразно для правил разных категорий:
// nolint:<rule> или "<rule>: safe" на строке нарушения (или строкой выше)
// гасит находку; чужой маркер — нет.
func TestAnalyzeFilesHonorsSuppression(t *testing.T) {
	cfg := core.DefaultConfig()

	tests := []struct {
		name      string
		rule      rules.Rule
		code      string
		wantCount int
	}{
		{
			name: "patterns rule suppressed by rule-colon-safe",
			rule: patterns.NewMaskedErrorOrConditionRule(),
			code: `package svc

func Get() (*Data, error) {
	d, err := load()
	if err != nil || d == nil {
		// masked-error-in-or-condition: safe — нет данных и сбой равнозначны для кэша
		return nil, nil
	}
	return d, nil
}
`,
			wantCount: 0,
		},
		{
			name: "patterns rule not suppressed by another rule's marker",
			rule: patterns.NewMaskedErrorOrConditionRule(),
			code: `package svc

func Get() (*Data, error) {
	d, err := load()
	if err != nil || d == nil {
		return nil, nil //nolint:some-other-rule
	}
	return d, nil
}
`,
			wantCount: 1,
		},
		{
			name: "typesafety rule suppressed by nolint",
			rule: typesafety.NewAnyInPublicContractRule(),
			code: `package svc

//nolint:any-in-public-contract
func Export() (any, error) {
	return nil, nil
}
`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := goContext(t, "service.go", tt.code)
			violations := analyzeFiles([]*core.FileContext{ctx}, []rules.Rule{tt.rule}, cfg)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d: %+v", len(violations), tt.wantCount, violations)
			}
		})
	}
}

// exemptStubRule — правило-заглушка, отказывающееся от подавления.
type exemptStubRule struct {
	*rules.BaseRule
}

func newExemptStubRule() *exemptStubRule {
	return &exemptStubRule{BaseRule: rules.NewBaseRule(
		"exempt-stub", "patterns", "test stub", core.SeverityHigh)}
}

func (r *exemptStubRule) SuppressionExempt() bool { return true }

func (r *exemptStubRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return []*core.Violation{r.CreateViolation(ctx.RelPath, 1, "always fires")}
}

// SuppressionExempt-правила не глушатся даже точным маркером.
func TestAnalyzeFilesRespectsSuppressionExempt(t *testing.T) {
	cfg := core.DefaultConfig()
	ctx := core.NewFileContext("service.go", ".", []byte("x //nolint:exempt-stub\n"), nil)

	violations := analyzeFiles([]*core.FileContext{ctx}, []rules.Rule{newExemptStubRule()}, cfg)
	if len(violations) != 1 {
		t.Fatalf("exempt rule must not be suppressed, got %d violations", len(violations))
	}
}
