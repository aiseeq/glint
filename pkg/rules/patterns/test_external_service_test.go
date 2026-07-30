package patterns

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTestExternalServiceRule_Metadata(t *testing.T) {
	rule := NewTestExternalServiceRule()

	assert.Equal(t, "test-external-service", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA(), "правилу хватает типизированных пакетов")
}

// parseForRule разбирает исходник в *ast.File для проверок отдельных предикатов.
func parseForRule(t *testing.T, src string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "sample.go", src, parser.ParseComments)
	require.NoError(t, err)
	return file
}

// typedFile парсит и типизирует исходник: детектор исходящих вызовов работает по
// типам, иначе `once.Do(...)` из sync считался бы отправкой HTTP-запроса.
func typedFile(t *testing.T, src string) (*ast.File, *types.Info) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample.go", src, parser.ParseComments)
	require.NoError(t, err)

	info := &types.Info{
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Types:      map[ast.Expr]types.TypeAndValue{},
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	_, err = conf.Check("sample", fset, []*ast.File{file}, info)
	require.NoError(t, err)
	return file, info
}

// Признак «пакет реально отправляет запросы». Без него внешним считался бы любой
// пакет, где просто упомянут чужой адрес.
func TestTestExternalServiceRule_OutboundDetection(t *testing.T) {
	tests := []struct {
		name   string
		code   string
		expect bool
	}{
		{
			name: "клиент собирает и отправляет запрос",
			code: `package debank

import "net/http"

type Client struct{ httpClient *http.Client }

func (c *Client) fetch(url string) error {
	req, _ := http.NewRequest("GET", url, nil)
	_, err := c.httpClient.Do(req)
	return err
}
`,
			expect: true,
		},
		{
			name: "http.Get напрямую",
			code: `package llama

import "net/http"

func Prices() { _, _ = http.Get("https://coins.llama.fi/prices") }
`,
			expect: true,
		},
		{
			name: "пакет только описывает конфиг",
			code: `package config

type Vendor struct {
	BaseURL string
}

func Defaults() Vendor { return Vendor{BaseURL: "https://api.provider.com"} }
`,
			expect: false,
		},
		{
			// Репро ложного срабатывания на Saga: sync.Once.Do помечал пакет config
			// как HTTP-клиент, и каждый тест, читающий конфиг, попадал в находки.
			name: "sync.Once.Do не является отправкой запроса",
			code: `package config

import "sync"

var once sync.Once

func Bootstrap() { once.Do(func() {}) }
`,
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, info := typedFile(t, tt.code)
			assert.Equal(t, tt.expect, fileIssuesHTTPRequest(file, info))
		})
	}
}

// Литерал URL в теге структуры не означает, что пакет туда ходит: на этом
// Saga-шный пакет config целиком считался внешним.
func TestTestExternalServiceRule_ExternalURLLiteral(t *testing.T) {
	rule := NewTestExternalServiceRule()

	tests := []struct {
		name   string
		code   string
		expect string
	}{
		{
			name: "константа с адресом вендора",
			code: `package debank

const baseURL = "https://pro-openapi.debank.com"
`,
			expect: "https://pro-openapi.debank.com",
		},
		{
			name: "адрес только в теге структуры",
			code: `package config

type Crypto2BConfig struct {
	BaseURL string ` + "`yaml:\"base_url\" default:\"https://api.crypto2b.com\"`" + `
}
`,
			expect: "",
		},
		{
			name: "локальный адрес внешним не считается",
			code: `package common

const baseURL = "http://localhost:8080"
`,
			expect: "",
		},
		{
			name: "домен .local внешним не считается",
			code: `package common

const adminURL = "https://admin.saga.local"
`,
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, rule.externalURLLiteral(parseForRule(t, tt.code)))
		})
	}
}

// Репро с реальных находок Saga (2026-07-30): оба vault-теста были помечены
// «ручными», но гейтились наличием ключа и выполнялись в каждом прогоне.
func TestTestExternalServiceRule_CredentialGate(t *testing.T) {
	rule := NewTestExternalServiceRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "гейт по наличию ключа через переменную",
			code: `package integration

func TestVaultSnapshot_CollectLive(t *testing.T) {
	debankKey := os.Getenv("DEBANK_ACCESS_KEY")
	if debankKey == "" {
		t.Skip("DEBANK_ACCESS_KEY not set")
	}
}
`,
			expectMatch: true,
		},
		{
			name: "гейт по наличию ключа прямо в условии",
			code: `package integration

func TestPayments(t *testing.T) {
	if os.Getenv("STRIPE_SECRET") == "" {
		t.Skipf("no credentials")
	}
}
`,
			expectMatch: true,
		},
		{
			name: "явный переключатель, а не секрет",
			code: `package integration

func TestVaultSnapshot_CollectLive(t *testing.T) {
	if os.Getenv("SAGA_LIVE_EXTERNAL") == "" {
		t.Skip("manual only")
	}
}
`,
			expectMatch: false,
		},
		{
			name: "skip по short-режиму не гейт секретом",
			code: `package integration

func TestHeavy(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
}
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := parseForRule(t, tt.code)
			ctx := createPatternContext(t, "live_test.go", tt.code)

			var found []*core.Violation
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				found = append(found, rule.credentialGates(ctx, fn)...)
			}

			if tt.expectMatch {
				require.NotEmpty(t, found, "ожидалась находка: %s", tt.name)
				assert.Equal(t, "test_external_service", found[0].Context["pattern"])
				assert.Equal(t, "credential_gate", found[0].Context["kind"])
			} else {
				assert.Empty(t, found, "находок быть не должно: %s", tt.name)
			}
		})
	}
}

func TestTestExternalServiceRule_ConfigureGuards(t *testing.T) {
	rule := NewTestExternalServiceRule()

	require.NoError(t, rule.Configure(map[string]any{
		"guard_functions": []any{"tests.RequireLiveExternal"},
	}))

	guarded := parseForRule(t, `package integration

func TestCrypto2BAuthentication(t *testing.T) {
	tests.RequireLiveExternal(t, "crypto2b TakeChannel")
	client := crypto2b.NewHTTPClient(cfg, logger)
	_ = client
}
`)
	plain := parseForRule(t, `package integration

func TestCrypto2BAuthentication(t *testing.T) {
	client := crypto2b.NewHTTPClient(cfg, logger)
	_ = client
}
`)

	assert.True(t, rule.hasGuard(guarded.Decls[0].(*ast.FuncDecl)), "опт-ин должен признаваться")
	assert.False(t, rule.hasGuard(plain.Decls[0].(*ast.FuncDecl)), "без опт-ина тест не защищён")

	require.Error(t, rule.Configure(map[string]any{"guard_functions": "не список"}))
	require.Error(t, rule.Configure(map[string]any{"guard_functions": []any{""}}))
}

// Сквозной репро с Saga: в одном пакете живут и подписывающий HTTP-клиент, и
// безобидный чтец конфигурации. Пока правило считало внешним пакет целиком, под
// раздачу попадал тест на пыль (crypto2b_dust_deposit_test.go), который собирает
// сервис с nil-транспортом и проверяет записи в БД, — он не шлёт ничего.
func TestTestExternalServiceRule_EntryPointsAndNilTransport(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"provider/client.go": `package provider

import (
	"net/http"
	"time"
)

type Config struct {
	BaseURL   string
	PublicKey string
}

type HTTPClient struct {
	config Config
	http   *http.Client
}

func NewHTTPClient(cfg Config) *HTTPClient {
	return &HTTPClient{config: cfg, http: &http.Client{Timeout: time.Second}}
}

func (c *HTTPClient) TakeChannel(id string) error {
	req, err := http.NewRequest("POST", c.config.BaseURL+"/channel/"+id, nil)
	if err != nil {
		return err
	}
	_, err = c.http.Do(req)
	return err
}

type ConfigService struct {
	config Config
}

func NewConfigService(cfg Config) *ConfigService { return &ConfigService{config: cfg} }

func (s *ConfigService) BaseURL() string { return s.config.BaseURL }

type DepositService struct {
	client *HTTPClient
}

func NewDepositService(client *HTTPClient, cfg *ConfigService) *DepositService {
	_ = cfg
	return &DepositService{client: client}
}

func (s *DepositService) Allocate(id string) error { return s.client.TakeChannel(id) }

type Repo struct{}

type PositionService struct {
	repo Repo
	cfg  Config
}

func NewPositionService(repo Repo, cfg Config) *PositionService {
	return &PositionService{repo: repo, cfg: cfg}
}

func (s *PositionService) List() []string      { return nil }
func (s *PositionService) Get(id string) string { return id }
func (s *PositionService) Save(id string) error { return nil }
func (s *PositionService) Refresh(id string) error {
	return NewHTTPClient(s.cfg).TakeChannel(id)
}
`,
		"integration/provider_test.go": `package integration

import (
	"testing"

	"example.com/rulestest/provider"
)

func TestLiveClient(t *testing.T) {
	client := provider.NewHTTPClient(provider.Config{})
	_ = client.TakeChannel("42")
}

func TestConfigOnly(t *testing.T) {
	svc := provider.NewConfigService(provider.Config{})
	_ = svc.BaseURL()
}

func TestDepositWritesToDB(t *testing.T) {
	svc := provider.NewDepositService(nil, provider.NewConfigService(provider.Config{}))
	_ = svc
}

func TestPositionMath(t *testing.T) {
	svc := provider.NewPositionService(provider.Repo{}, provider.Config{})
	_ = svc.Get("id")
}
`,
	})

	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1, "ожидается ровно одна находка, получено: %v", messages(violations))
	assert.Contains(t, violations[0].Message, "TestLiveClient")
	assert.Contains(t, violations[0].Message, "NewHTTPClient")
	assert.Equal(t, "outbound_client", violations[0].Context["kind"])
}

func messages(violations []*core.Violation) []string {
	out := make([]string, 0, len(violations))
	for _, v := range violations {
		out = append(out, v.Message)
	}
	return out
}
