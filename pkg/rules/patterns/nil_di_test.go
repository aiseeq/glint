package patterns

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNilDIRule_Metadata(t *testing.T) {
	rule := NewNilDIRule()

	assert.Equal(t, "nil-di", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestNilDIRule_SuppressionWithSharedFileSet(t *testing.T) {
	rule := NewNilDIRule()
	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "first.go", "package svc\n\nvar padding = 1\n", parser.ParseComments)
	require.NoError(t, err)

	code := `package svc

func wire() {
	_ = NewRemoteService(cfg, nil) // nil-di: safe
}
`
	file, err := parser.ParseFile(fset, "wire.go", code, parser.ParseComments)
	require.NoError(t, err)
	ctx := core.NewFileContext("wire.go", ".", []byte(code), nil)
	ctx.SetGoAST(fset, file)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}

// nilDITypes declares the dependency types the detection cases wire.
const nilDITypes = `package svc

type Config struct{}

type Limits struct{}

type Data struct{}

type Logger interface{ Print(msg string) }

type DB interface{ Exec(query string) error }

type Repo interface{ Find(id string) error }

type Service struct{}
`

func TestNilDIRule_Detection(t *testing.T) {
	tests := []struct {
		name        string
		constructor string
		call        string
		expectHits  int
	}{
		{
			name:        "nil logger to service",
			constructor: "func NewMetricsService(cfg *Config, logger Logger) *Service { return &Service{} }",
			call:        "_ = NewMetricsService(&Config{}, nil)",
			expectHits:  1,
		},
		{
			name:        "nil db and logger to handler, limits is not a dependency",
			constructor: "func NewDepositHandler(db DB, logger Logger, limits *Limits, cfg *Config) *Service { return &Service{} }",
			call:        "_ = NewDepositHandler(nil, nil, nil, &Config{})",
			expectHits:  2,
		},
		{
			name:        "nil logger to middleware",
			constructor: "func NewSecurityMiddleware(logger Logger, cfg *Config) *Service { return &Service{} }",
			call:        "_ = NewSecurityMiddleware(nil, &Config{})",
			expectHits:  1,
		},
		{
			name:        "nil db to repository",
			constructor: "func NewUserRepository(db DB, logger Logger) *Service { return &Service{} }",
			call:        "_ = NewUserRepository(nil, nil)",
			expectHits:  2,
		},
		{
			name:        "non-high-risk nil",
			constructor: "func NewSomething(cfg *Config, data *Data, extra *Data) *Service { return &Service{} }",
			call:        "_ = NewSomething(&Config{}, nil, &Data{})",
			expectHits:  0,
		},
		{
			name:        "suppressed with comment",
			constructor: "func NewJWTService(cfg *Config, validator Repo) *Service { return &Service{} }",
			call:        "// nil-di: safe - validator not needed for admin tokens\n\t_ = NewJWTService(&Config{}, nil)",
			expectHits:  0,
		},
		{
			name:        "suppressed inline",
			constructor: "func NewService(cfg *Config, logger Logger) *Service { return &Service{} }",
			call:        "_ = NewService(&Config{}, nil) // nil-di: safe",
			expectHits:  0,
		},
		{
			name:        "multiple nils - only the high-risk parameter",
			constructor: "func NewInvestmentService(cfg *Config, repo Repo, limits *Limits, users Repo, logger Logger) *Service { return &Service{} }",
			call:        "_ = NewInvestmentService(&Config{}, nil, nil, nil, nil)",
			expectHits:  2, // repo and logger; limits and users are not DI names
		},
		{
			name:        "variadic dependency",
			constructor: "func NewPool(size int, loggers ...Logger) *Service { return &Service{} }",
			call:        "_ = NewPool(1, nil)",
			expectHits:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := runRuleOnFiles(t, NewNilDIRule(), map[string]string{
				"svc/types.go":       nilDITypes,
				"svc/constructor.go": "package svc\n\n" + tt.constructor + "\n",
				"svc/wire.go":        "package svc\n\nfunc wire() {\n\t" + tt.call + "\n}\n",
			})
			require.Len(t, violations, tt.expectHits, "%v", violations)
		})
	}
}

// A constructor of another package is resolved the same way.
func TestNilDIRule_DetectsAcrossPackages(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilDIRule(), map[string]string{
		"svc/types.go": nilDITypes,
		"svc/metrics.go": `package svc

func NewCanonicalMetricsService(cfg *Config, logger Logger) *Service { return &Service{} }
`,
		"app/main.go": `package app

import "example.com/rulestest/svc"

func Build() *svc.Service {
	return svc.NewCanonicalMetricsService(&svc.Config{}, nil)
}
`,
	})
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Nil logger argument to constructor NewCanonicalMetricsService")
}

func TestNilDIRule_SkipsTestFiles(t *testing.T) {
	rule := NewNilDIRule()

	code := `package main

func main() {
	svc := NewService(cfg, nil)
}
`
	// Test _test.go files
	ctx := createNilDIContext(t, "service_test.go", code)
	violations := rule.AnalyzeFile(ctx)
	assert.Empty(t, violations, "Test files should be excluded")

	// Test test.go files (benchmarks)
	ctx = createNilDIContext(t, "test.go", code)
	violations = rule.AnalyzeFile(ctx)
	assert.Empty(t, violations, "test.go files should be excluded")
}

func TestNilDIRule_HighRiskParams(t *testing.T) {
	rule := NewNilDIRule()

	tests := []struct {
		paramHint  string
		isHighRisk bool
	}{
		{"logger", true},
		{"log", true},
		{"service", true},
		{"svc", true},
		{"repo", true},
		{"repository", true},
		{"storage", true},
		{"store", true},
		{"handler", true},
		{"client", true},
		{"db", true},
		{"database", true},
		{"cache", true},
		{"metrics", true},
		{"validator", true},
		{"config", false},
		{"options", false},
		{"settings", false},
		{"dependency", false},
		{"data", false},
	}

	for _, tt := range tests {
		t.Run(tt.paramHint, func(t *testing.T) {
			result := rule.isHighRiskParam(tt.paramHint)
			assert.Equal(t, tt.isHighRisk, result, "Expected isHighRisk=%v for %s", tt.isHighRisk, tt.paramHint)
		})
	}
}

// Helper function
func createNilDIContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitNilDILines(code),
		Content: []byte(code),
	}

	if len(path) > 3 && path[len(path)-3:] == ".go" {
		parser := core.NewParser()
		fset, ast, err := parser.ParseGoFile(path, []byte(code))
		if err != nil {
			t.Fatalf("Failed to parse Go code: %v", err)
		}
		ctx.SetGoAST(fset, ast)
	}

	return ctx
}

func splitNilDILines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func TestNilDIResolvedParamName(t *testing.T) {
	rule := NewNilDIRule()

	code := `package svc

func NewDashboardService(adminRepo Repo, db DB, balanceService BalanceService) *Service {
	return &Service{}
}

func wire() {
	_ = NewDashboardService(repo, db, nil)
}
`
	ctx := core.NewFileContext("service.go", ".", []byte(code), nil)
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile("service.go", []byte(code))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx.SetGoAST(fset, astFile)

	violations := rule.AnalyzeFile(ctx)
	if len(violations) != 1 {
		t.Fatalf("want 1 violation, got %d: %+v", len(violations), violations)
	}
	if !strings.Contains(violations[0].Message, "balanceService") {
		t.Errorf("message should name the real parameter, got: %s", violations[0].Message)
	}

	crossFile := `package svc

func wire() {
	_ = NewRemoteService(cfg, nil)
}
`
	ctx2 := core.NewFileContext("wire.go", ".", []byte(crossFile), nil)
	fset2, astFile2, err := parser.ParseGoFile("wire.go", []byte(crossFile))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx2.SetGoAST(fset2, astFile2)

	// Without type information an undeclared constructor is unknown: no
	// guess by position, no finding.
	if violations2 := rule.AnalyzeFile(ctx2); len(violations2) != 0 {
		t.Fatalf("want no violation for an unresolved constructor, got %+v", violations2)
	}
}

// A constructor declared in a sibling file is resolved through type
// information: its real parameter decides, not a guess by position. Guessing
// called the nil limit of NewReportService a logger ("last argument of a
// service") and asked for a dependency the constructor does not take.
func TestNilDIResolvesConstructorFromSiblingFile(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilDIRule(), map[string]string{
		"report/service.go": `package report

type Config struct{}

type ReportService struct{ limit *int }

func NewReportService(cfg *Config, limit *int) *ReportService {
	_ = cfg
	return &ReportService{limit: limit}
}
`,
		"report/wire.go": `package report

func wire() *ReportService {
	return NewReportService(&Config{}, nil)
}
`,
	})
	require.Empty(t, violations)
}

// The same resolution finds the nil dependency the position guess missed, in
// the same package and across packages, and names the real parameter.
func TestNilDIReportsResolvedDependencyAcrossFiles(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilDIRule(), map[string]string{
		"users/service.go": `package users

type Repo interface{ Find(id string) error }

type Logger interface{ Print(msg string) }

type UserService struct {
	repo   Repo
	logger Logger
}

func NewUserService(repo Repo, logger Logger) *UserService {
	return &UserService{repo: repo, logger: logger}
}
`,
		"users/wire.go": `package users

func wire(logger Logger) *UserService {
	return NewUserService(nil, logger)
}
`,
		"app/main.go": `package app

import "example.com/rulestest/users"

func Build(repo users.Repo) *users.UserService {
	return users.NewUserService(repo, nil)
}
`,
	})
	require.Len(t, violations, 2)
	assert.Equal(t, "app/main.go", violations[0].File)
	assert.Contains(t, violations[0].Message, "Nil logger argument")
	assert.Equal(t, "users/wire.go", violations[1].File)
	assert.Contains(t, violations[1].Message, "Nil repo argument")
}

// Without type information a constructor the file does not declare is
// unknown: the rule stays silent rather than guess what its parameter is.
func TestNilDIUntypedUndeclaredConstructorIsSilent(t *testing.T) {
	violations := runRuleOnBrokenFiles(t, NewNilDIRule(), map[string]string{
		"svc/service.go": `package svc

type Service struct{}

func NewMetricsService(cfg *Config, limit *int) *Service { return &Service{} }
`,
		"svc/wire.go": `package svc

func wire() {
	_ = NewMetricsService(nil, nil)
}
`,
		"svc/broken.go": "package svc\n\nfunc broken() int { return \"not an int\" }\n",
	})
	require.Empty(t, violations)
}

// Without type information a constructor declared in the same file still
// names its parameter, and a nil dependency there is still reported.
func TestNilDIUntypedSameFileConstructorIsReported(t *testing.T) {
	violations := runRuleOnBrokenFiles(t, NewNilDIRule(), map[string]string{
		"svc/service.go": `package svc

type Service struct{}

func NewMetricsService(cfg *Config, logger Logger) *Service { return &Service{} }

func wire() {
	_ = NewMetricsService(nil, nil)
}

func broken() int { return "not an int" }
`,
	})
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Nil logger argument")
}
