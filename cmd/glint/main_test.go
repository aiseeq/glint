package main

import (
	"errors"
	"go/ast"
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns"
	"github.com/aiseeq/glint/pkg/rules/typesafety"
)

func TestGetProjectRootsExpandsRecursiveCurrentDirectory(t *testing.T) {
	want, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	got, err := getProjectRoots([]string{"./..."})
	if err != nil {
		t.Fatalf("get project roots: %v", err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got project roots %v, want [%s]", got, want)
	}
}

func TestGetProjectRootsRejectsMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	_, err := getProjectRoots([]string{missing})
	if err == nil {
		t.Fatal("expected missing project root to return an error")
	}
}

func TestGetProjectRootsReturnsAbsoluteCleanPath(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "project")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatalf("create project root: %v", err)
	}
	t.Chdir(parent)

	got, err := getProjectRoots([]string{"project/./"})
	if err != nil {
		t.Fatalf("get project roots: %v", err)
	}
	if len(got) != 1 || got[0] != root {
		t.Fatalf("got project roots %v, want [%s]", got, root)
	}
}

func TestShouldFailAnalysisAtHighSeverity(t *testing.T) {
	medium := core.ViolationList{core.NewViolation("medium", "test", "test.go", 1, core.SeverityMedium, "medium")}
	high := core.ViolationList{core.NewViolation("high", "test", "test.go", 1, core.SeverityHigh, "high")}
	critical := core.ViolationList{core.NewViolation("critical", "test", "test.go", 1, core.SeverityCritical, "critical")}

	if shouldFailAnalysis(medium) {
		t.Fatal("medium findings must not fail analysis")
	}
	if !shouldFailAnalysis(high) {
		t.Fatal("high findings must fail analysis")
	}
	if !shouldFailAnalysis(critical) {
		t.Fatal("critical findings must fail analysis")
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

type projectStubRule struct {
	*rules.BaseRule
	requireSSA   bool
	findings     []*core.Violation
	err          error
	projectCalls int
	fileCalls    int
	project      *core.GoProjectContext
}

func newProjectStubRule() *projectStubRule {
	return &projectStubRule{BaseRule: rules.NewBaseRule(
		"project-stub", "patterns", "test project rule", core.SeverityMedium)}
}

func (r *projectStubRule) RequiresSSA() bool { return r.requireSSA }

func (r *projectStubRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	r.projectCalls++
	r.project = ctx
	return r.findings, r.err
}

func (r *projectStubRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	r.fileCalls++
	return nil
}

type astStubRule struct {
	*rules.BaseRule
	calls int
	asts  []*ast.File
}

func newASTStubRule() *astStubRule {
	return &astStubRule{BaseRule: rules.NewBaseRule(
		"ast-stub", "patterns", "test file rule", core.SeverityLow)}
}

func (r *astStubRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.IsGoFile() {
		r.calls++
		r.asts = append(r.asts, ctx.GoAST)
	}
	return nil
}

func writeAnalysisModule(t *testing.T, source string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/check\n\ngo 1.24\n"), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "check.go"), []byte(source), 0644); err != nil {
		t.Fatalf("write check.go: %v", err)
	}
	return root
}

func TestPrepareAnalysisUsesLoaderASTForProjectAndFileRules(t *testing.T) {
	root := writeAnalysisModule(t, "package check\n\nfunc Value() int { return 1 }\n")
	projectRule := newProjectStubRule()
	projectRule.requireSSA = true
	fileRule := newASTStubRule()

	contexts, _, project, err := prepareAnalysis(root, core.DefaultConfig(), []rules.Rule{projectRule, fileRule})
	if err != nil {
		t.Fatalf("prepare analysis: %v", err)
	}
	if project == nil || project.Packages[0].SSA == nil {
		t.Fatal("expected built SSA project")
	}
	if _, err := analyzeProject(contexts, []rules.Rule{projectRule, fileRule}, core.DefaultConfig(), project); err != nil {
		t.Fatalf("analyze project: %v", err)
	}
	if projectRule.projectCalls != 1 || projectRule.fileCalls != 0 {
		t.Fatalf("project calls=%d file calls=%d, want 1 and 0", projectRule.projectCalls, projectRule.fileCalls)
	}
	if fileRule.calls != 1 || len(fileRule.asts) != 1 {
		t.Fatalf("file rule calls=%d ASTs=%d, want one", fileRule.calls, len(fileRule.asts))
	}
	if fileRule.asts[0] != project.Packages[0].Package.Syntax[0] {
		t.Fatal("file rule did not receive loader AST pointer")
	}
}

func TestPrepareAnalysisWithoutProjectRuleUsesWalkerParser(t *testing.T) {
	root := writeAnalysisModule(t, "package check\n")
	fileRule := newASTStubRule()

	contexts, _, project, err := prepareAnalysis(root, core.DefaultConfig(), []rules.Rule{fileRule})
	if err != nil {
		t.Fatalf("prepare analysis: %v", err)
	}
	if project != nil {
		t.Fatal("project context must not be loaded without a project rule")
	}
	if len(contexts) != 1 || contexts[0].GoAST == nil {
		t.Fatal("old walker path must parse Go files")
	}
}

func TestPrepareAnalysisSkipsGoProjectForTreeWithoutGoFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.ts"), []byte("export const x = 1\n"), 0644); err != nil {
		t.Fatalf("write app.ts: %v", err)
	}
	projectRule := newProjectStubRule()

	contexts, _, project, err := prepareAnalysis(root, core.DefaultConfig(), []rules.Rule{projectRule})
	if err != nil {
		t.Fatalf("prepare analysis on TS-only tree must not fail: %v", err)
	}
	if project != nil {
		t.Fatal("Go project context must not be loaded for a tree without Go files")
	}
	if len(contexts) != 1 {
		t.Fatalf("contexts=%d, want 1 (app.ts)", len(contexts))
	}

	if _, err := analyzeProject(contexts, []rules.Rule{projectRule}, core.DefaultConfig(), project); err != nil {
		t.Fatalf("analyze TS-only tree with project rule must not fail: %v", err)
	}
	if projectRule.projectCalls != 0 {
		t.Fatalf("project rule calls=%d, want 0 on a tree without Go files", projectRule.projectCalls)
	}
}

func TestAnalyzeProjectFiltersPackageFindings(t *testing.T) {
	tests := []struct {
		name   string
		cfg    *core.Config
		source string
	}{
		{
			name:   "suppression",
			cfg:    core.DefaultConfig(),
			source: "package check\n\n//nolint:project-stub\nfunc Value() int { return 1 }\n",
		},
		{
			name: "exception",
			cfg: func() *core.Config {
				cfg := core.DefaultConfig()
				category := cfg.Categories["patterns"]
				category.Rules = map[string]core.RuleConfig{
					"project-stub": {Enabled: true, Exceptions: []core.Exception{{File: "check.go"}}},
				}
				cfg.Categories["patterns"] = category
				return cfg
			}(),
			source: "package check\n\nfunc Value() int { return 1 }\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeAnalysisModule(t, tt.source)
			rule := newProjectStubRule()
			rule.findings = []*core.Violation{rule.CreateViolation("check.go", 4, "finding")}
			contexts, _, project, err := prepareAnalysis(root, tt.cfg, []rules.Rule{rule})
			if err != nil {
				t.Fatalf("prepare analysis: %v", err)
			}

			violations, err := analyzeProject(contexts, []rules.Rule{rule}, tt.cfg, project)
			if err != nil {
				t.Fatalf("analyze project: %v", err)
			}
			if len(violations) != 0 {
				t.Fatalf("got findings %+v, want filtered", violations)
			}
		})
	}
}

func TestPrepareAnalysisReturnsLoaderTypeError(t *testing.T) {
	root := writeAnalysisModule(t, "package check\n\nvar Number int = \"wrong\"\n")
	rule := newProjectStubRule()

	_, _, _, err := prepareAnalysis(root, core.DefaultConfig(), []rules.Rule{rule})
	if err == nil {
		t.Fatal("expected typed loader error")
	}
}

func TestAnalyzeProjectReturnsRuleError(t *testing.T) {
	root := writeAnalysisModule(t, "package check\n")
	rule := newProjectStubRule()
	rule.err = errors.New("project analysis failed")
	contexts, _, project, err := prepareAnalysis(root, core.DefaultConfig(), []rules.Rule{rule})
	if err != nil {
		t.Fatalf("prepare analysis: %v", err)
	}

	_, err = analyzeProject(contexts, []rules.Rule{rule}, core.DefaultConfig(), project)
	if !errors.Is(err, rule.err) {
		t.Fatalf("got error %v, want %v", err, rule.err)
	}
}

func TestGetProjectRootsKeepsEveryPath(t *testing.T) {
	parent := t.TempDir()
	first := filepath.Join(parent, "backend")
	second := filepath.Join(parent, "tools")
	for _, dir := range []string{first, second} {
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}

	got, err := getProjectRoots([]string{first, second})
	if err != nil {
		t.Fatalf("get project roots: %v", err)
	}
	if len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("got project roots %v, want [%s %s]", got, first, second)
	}
}

func TestGetProjectRootsDeduplicatesRepeatedPath(t *testing.T) {
	root := t.TempDir()

	got, err := getProjectRoots([]string{root, root + "/."})
	if err != nil {
		t.Fatalf("get project roots: %v", err)
	}
	if len(got) != 1 || got[0] != root {
		t.Fatalf("got project roots %v, want [%s]", got, root)
	}
}

func TestDedupeViolationsDropsRepeatedFinding(t *testing.T) {
	violations := core.ViolationList{
		{Rule: "error-wrap", File: "a.go", Line: 10},
		{Rule: "error-wrap", File: "a.go", Line: 10},
		{Rule: "error-wrap", File: "a.go", Line: 20},
		{Rule: "magic-number", File: "a.go", Line: 10},
	}

	got := dedupeViolations(violations)
	if len(got) != 3 {
		t.Fatalf("got %d violations, want 3", len(got))
	}
}
