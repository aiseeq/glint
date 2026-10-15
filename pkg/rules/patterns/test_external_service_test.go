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
// stdImporter reads the standard library from export data once for every
// test of the package: a source importer per test would parse and check it
// again each time.
var stdImporter = importer.ForCompiler(token.NewFileSet(), "gc", nil)

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
	conf := types.Config{Importer: stdImporter}
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
			code: `package extvault

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
			// Репро ложного срабатывания на ProjectA: sync.Once.Do помечал пакет config
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
// ProjectA-шный пакет config целиком считался внешним.
func TestTestExternalServiceRule_ExternalURLLiteral(t *testing.T) {
	rule := NewTestExternalServiceRule()

	tests := []struct {
		name   string
		code   string
		expect string
	}{
		{
			name: "константа с адресом вендора",
			code: `package extvault

const baseURL = "https://pro-openapi.extvault.com"
`,
			expect: "https://pro-openapi.extvault.com",
		},
		{
			name: "адрес только в теге структуры",
			code: `package config

type CryptoProvConfig struct {
	BaseURL string ` + "`yaml:\"base_url\" default:\"https://api.cryptoprov.com\"`" + `
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

const adminURL = "https://admin.projectA.local"
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

// Репро с реальных находок ProjectA (2026-07-30): оба vault-теста были помечены
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
	extvaultKey := os.Getenv("EXTVAULT_ACCESS_KEY")
	if extvaultKey == "" {
		t.Skip("EXTVAULT_ACCESS_KEY not set")
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
	if os.Getenv("PROJECTA_LIVE_EXTERNAL") == "" {
		t.Skip("manual only")
	}
}
`,
			expectMatch: false,
		},
		{
			// KEY внутри KEYBOARD — не секрет: это переключатель набора тестов.
			name: "переключатель со словом KEY внутри другого слова",
			code: `package integration

func TestKeyboardOptIn(t *testing.T) {
	if os.Getenv("RUN_KEYBOARD_SUITE") == "" {
		t.Skip("opt-in")
	}
}
`,
			expectMatch: false,
		},
		{
			name: "слитное APIKEY — секрет",
			code: `package integration

func TestPayments(t *testing.T) {
	if os.Getenv("PAYPROV_APIKEY") == "" {
		t.Skip("no key")
	}
}
`,
			expectMatch: true,
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
				found = append(found, rule.credentialGates(ctx, fn, map[string]bool{
					"EXTVAULT_ACCESS_KEY": true, "STRIPE_SECRET": true, "PAYPROV_APIKEY": true,
					"PROJECTA_LIVE_EXTERNAL": true, "RUN_KEYBOARD_SUITE": true,
				})...)
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

// Репро из projectB: reference-тест гейтится ADMIN_TOKEN, но токен — наш
// собственный JWT, а ходит тест в http://localhost:8090.
func TestTestExternalServiceRule_LocalServerGateIsNotReported(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"integration/reference_test.go": `package integration

import (
	"os"
	"testing"
)

const defaultAPIURL = "http://localhost:8090"

func TestReferenceBalances(t *testing.T) {
	token := os.Getenv("ADMIN_TOKEN")
	if token == "" {
		t.Skip("ADMIN_TOKEN не задан")
	}
	_ = defaultAPIURL
}
`,
	})

	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations, "тест против своего сервера находкой быть не должен: %v", messages(violations))
}

// Интеграционный тест против собственной локальной БД гейтится паролем этой
// БД: секрет наш, адрес локальный, но он записан не URL-ом, а DSN, склеенным
// из кусков вокруг пароля.
func TestTestExternalServiceRule_LocalDatabaseGateIsNotReported(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"pipeline/pipeline_integration_test.go": `package pipeline

import (
	"os"
	"testing"
)

func TestPipelineIntegration(t *testing.T) {
	dbPassword := os.Getenv("DB_PASSWORD")
	if dbPassword == "" {
		t.Skip("DB_PASSWORD not set, skipping integration test")
	}
	dsn := "postgres://app:" + dbPassword + "@127.0.0.1:5432/app?sslmode=disable"
	_ = dsn
}
`,
	})

	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations, "тест против локальной БД находкой быть не должен: %v", messages(violations))
}

func TestTestExternalServiceRule_ConfigureGuards(t *testing.T) {
	rule := NewTestExternalServiceRule()

	require.NoError(t, rule.Configure(map[string]any{
		"guard_functions": []any{"tests.RequireLiveExternal"},
	}))

	guarded := parseForRule(t, `package integration

func TestCryptoProvAuthentication(t *testing.T) {
	tests.RequireLiveExternal(t, "cryptoprov TakeChannel")
	client := cryptoprov.NewHTTPClient(cfg, logger)
	_ = client
}
`)
	plain := parseForRule(t, `package integration

func TestCryptoProvAuthentication(t *testing.T) {
	client := cryptoprov.NewHTTPClient(cfg, logger)
	_ = client
}
`)

	assert.True(t, rule.hasGuard(guarded.Decls[0].(*ast.FuncDecl)), "опт-ин должен признаваться")
	assert.False(t, rule.hasGuard(plain.Decls[0].(*ast.FuncDecl)), "без опт-ина тест не защищён")

	require.Error(t, rule.Configure(map[string]any{"guard_functions": "не список"}))
	require.Error(t, rule.Configure(map[string]any{"guard_functions": []any{""}}))
}

// Сквозной репро с ProjectA: в одном пакете живут и подписывающий HTTP-клиент, и
// безобидный чтец конфигурации. Пока правило считало внешним пакет целиком, под
// раздачу попадал тест на пыль (cryptoprov_dust_deposit_test.go), который собирает
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

// Гейт часто перечисляет два секрета через ||: ProjectA-шный cryptoprov-тест пропускался
// именно так, и правило его не видело — разбирался только одиночный `==`.
func TestTestExternalServiceRule_CredentialGateWithOrCondition(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"vendor/vendor_test.go": `package vendor

import (
	"os"
	"testing"
)

func TestLiveVendorAPI(t *testing.T) {
	if os.Getenv("VENDOR_PUBLIC_KEY") == "" || os.Getenv("VENDOR_PRIVATE_KEY") == "" {
		t.Skip("credentials not configured")
	}
}
`,
		".env.example": "VENDOR_PUBLIC_KEY=\nVENDOR_PRIVATE_KEY=\n",
	})

	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1, "%v", messages(violations))
	assert.Equal(t, "credential_gate", violations[0].Context["kind"])
	assert.Equal(t, "VENDOR_PUBLIC_KEY", violations[0].Context["env"])
}

// Тест внутри самого вендорского пакета зовёт клиента без квалификатора — по секции
// import такой вызов не находится, и живой тест cryptoprov оставался невидимым.
func TestTestExternalServiceRule_InPackageTestIsReported(t *testing.T) {
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
`,
		"provider/client_live_test.go": `package provider

import "testing"

func TestLiveChannel(t *testing.T) {
	client := NewHTTPClient(Config{})
	_ = client.TakeChannel("42")
}
`,
	})

	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1, "%v", messages(violations))
	assert.Equal(t, "outbound_client", violations[0].Context["kind"])
	assert.Contains(t, violations[0].Message, "TestLiveChannel")
}

// nil гасит находку только на месте транспорта: nil вместо необязательных опций
// запрос не отменяет, и payprov.FetchRates(ctx, nil) уходит к провайдеру.
func TestTestExternalServiceRule_NilOptionsStillReachTheWire(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"payprov/client.go": `package payprov

import (
	"context"
	"net/http"
)

const baseURL = "https://api.payprov.io/v1"

type Opts struct{ Verbose bool }

func FetchRates(ctx context.Context, opts *Opts) (*http.Response, error) {
	_ = opts
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/rates", nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}
`,
		"svc/svc_test.go": `package svc

import (
	"context"
	"testing"

	"example.com/rulestest/payprov"
)

func TestRatesLive(t *testing.T) {
	_, _ = payprov.FetchRates(context.Background(), nil)
}

func TestRatesLive2(t *testing.T) {
	_, _ = payprov.FetchRates(context.Background(), &payprov.Opts{})
}
`,
	})

	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 2, "%v", messages(violations))
	assert.Contains(t, violations[0].Message, "TestRatesLive ")
	assert.Contains(t, violations[1].Message, "TestRatesLive2")
}

// nil на месте интерфейса, который реализует живой клиент пакета, — транспорта нет.
func TestTestExternalServiceRule_NilInterfaceTransportIsSilent(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"payprov/client.go": `package payprov

import "net/http"

type Doer interface {
	Take(id string) error
}

type Client struct{ http *http.Client }

func (c *Client) Take(id string) error {
	req, err := http.NewRequest("POST", "https://api.payprov.io/take/"+id, nil)
	if err != nil {
		return err
	}
	_, err = c.http.Do(req)
	return err
}

type Service struct{ doer Doer }

func NewService(doer Doer) *Service { return &Service{doer: doer} }

func (s *Service) Allocate(id string) error { return s.doer.Take(id) }

func Allocate(doer Doer, id string) error { return (&Client{}).Take(id) }
`,
		"svc/svc_test.go": `package svc

import (
	"testing"

	"example.com/rulestest/payprov"
)

func TestAllocateOffline(t *testing.T) {
	_ = payprov.Allocate(nil, "42")
}
`,
	})

	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations, "%v", messages(violations))
}

// Пакет с версией в пути импорта называется по своему package, а не "v2".
func TestTestExternalServiceRule_VersionedImportPath(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"provider/v2/client.go": `package provider

import "net/http"

func Fetch() error {
	_, err := http.Get("https://api.provider.io/v2/things")
	return err
}
`,
		"svc/svc_test.go": `package svc

import (
	"testing"

	"example.com/rulestest/provider/v2"
)

func TestFetchLive(t *testing.T) {
	_ = provider.Fetch()
}

// Testdata is not a test function: a lower-case letter follows "Test".
func Testdata() {
	_ = provider.Fetch()
}
`,
	})

	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1, "%v", messages(violations))
	assert.Contains(t, violations[0].Message, "TestFetchLive")
}

// A gate on variables that no env file of the project names is a dedicated
// opt-in: the runner has nothing to export, and the test stays skipped.
func TestTestExternalServiceRule_CredentialGateOutsideEnvFilesIsNotReported(t *testing.T) {
	files := map[string]string{
		"vault/live_test.go": `package vault

import (
	"os"
	"testing"
)

func TestLiveVault(t *testing.T) {
	addr := os.Getenv("LIVE_VAULT_ADDR")
	token := os.Getenv("LIVE_VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("live vault check needs LIVE_VAULT_ADDR and LIVE_VAULT_TOKEN")
	}
}
`,
		".env": "DB_HOST=localhost\n",
	}
	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations, "%v", messages(violations))

	files["deploy/.env.example"] = "LIVE_VAULT_TOKEN=\n"
	violations, err = NewTestExternalServiceRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	require.Len(t, violations, 1, "%v", messages(violations))
	assert.Equal(t, "LIVE_VAULT_TOKEN", violations[0].Context["env"])
}

// ratesClient is a client with its production address built in: New takes
// no address, so a test that builds it with New reaches the live feed.
const ratesClient = `package rates

import (
	"context"
	"net/http"
)

const defaultURL = "https://feed.ratesbank.io/daily.xml"

type Client struct {
	url  string
	http *http.Client
}

func New() *Client { return NewAt(defaultURL) }

func NewAt(url string) *Client { return &Client{url: url, http: &http.Client{}} }

func (c *Client) Rate(ctx context.Context, code string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"?code="+code, nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}
`

// A file whose other tests serve a fake feed through httptest still holds a
// test that builds the client with its production address: the httptest
// import vouches for the tests that use the server, not for the whole file.
// The live test skipped only in -short mode reached the real feed on every
// full run.
func TestTestExternalServiceRule_LiveTestNextToHTTPTestIsReported(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"rates/client.go": ratesClient,
		"rates/server_test.go": `package rates

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var feed = httptest.NewUnstartedServer(http.NotFoundHandler())

func feedURL(t *testing.T) string {
	t.Helper()
	return sharedFeed().URL
}

func sharedFeed() *httptest.Server { return feed }
`,
		"rates/client_test.go": `package rates

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakeFeed(t *testing.T) *Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(srv.Close)
	return NewAt(srv.URL)
}

func TestRateFromFakeFeed(t *testing.T) {
	_, _ = fakeFeed(t).Rate(context.Background(), "USD")
}

func TestRateFromInlineServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	_, _ = NewAt(srv.URL).Rate(context.Background(), "USD")
}

func TestRateFromSharedServer(t *testing.T) {
	_, _ = NewAt(feedURL(t)).Rate(context.Background(), "USD")
}

func TestRate_LiveFeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live feed in short mode")
	}
	_, _ = New().Rate(context.Background(), "USD")
}
`,
	})

	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1, "%v", messages(violations))
	assert.Contains(t, violations[0].Message, "TestRate_LiveFeed")
}

// A test that skips at once unless a dedicated env flag is set does not run
// in an ordinary go test: the live call behind it is an explicit opt-in and
// is not reported. The flag must be one no env file of the project sets and
// the skip must come before the call; a gate on testing.Short() is no flag -
// a full run opens it.
func TestTestExternalServiceRule_EnvFlagSkipIsAnOptIn(t *testing.T) {
	liveTest := func(gate string) map[string]string {
		return map[string]string{
			"rates/client.go": ratesClient,
			"rates/helpers_test.go": `package rates

import (
	"os"
	"testing"
)

func requireLiveFeed(t *testing.T) {
	t.Helper()
	if os.Getenv("RATES_LIVE_TEST") != "1" {
		t.Skip("set RATES_LIVE_TEST=1 to call the live feed")
	}
}
`,
			"rates/live_test.go": `package rates

import (
	"context"
	"os"
	"testing"
)

var _ = os.Getenv

func TestRate_Live(t *testing.T) {
` + gate + `
}
`,
		}
	}
	const call = "\t_, _ = New().Rate(context.Background(), \"USD\")"
	optIns := map[string]string{
		"flag compared to empty":   "\tif os.Getenv(\"RATES_LIVE_TEST\") == \"\" {\n\t\tt.Skip(\"opt-in\")\n\t}\n" + call,
		"flag compared to a value": "\tif os.Getenv(\"RATES_LIVE_TEST\") != \"1\" {\n\t\tt.Skip(\"opt-in\")\n\t}\n" + call,
		"flag through a variable":  "\tlive := os.Getenv(\"RATES_LIVE_TEST\")\n\tif live == \"\" {\n\t\tt.Skip(\"opt-in\")\n\t}\n" + call,
		"flag looked up":           "\tif _, ok := os.LookupEnv(\"RATES_LIVE_TEST\"); !ok {\n\t\tt.SkipNow()\n\t}\n" + call,
		"flag or short mode":       "\tif testing.Short() || os.Getenv(\"RATES_LIVE_TEST\") == \"\" {\n\t\tt.Skip(\"opt-in\")\n\t}\n" + call,
		"flag checked by a helper": "\trequireLiveFeed(t)\n" + call,
	}
	for name, body := range optIns {
		t.Run(name, func(t *testing.T) {
			violations, err := NewTestExternalServiceRule().AnalyzeGoProject(rulestest.Project(t, liveTest(body)))
			require.NoError(t, err)
			assert.Empty(t, violations, "%v", messages(violations))
		})
	}

	reported := map[string]map[string]string{
		"short mode only":           liveTest("\tif testing.Short() {\n\t\tt.Skip(\"short\")\n\t}\n" + call),
		"no gate":                   liveTest(call),
		"skip after the call":       liveTest(call + "\n\tif os.Getenv(\"RATES_LIVE_TEST\") == \"\" {\n\t\tt.Skip(\"too late\")\n\t}"),
		"gate does not skip":        liveTest("\tif os.Getenv(\"RATES_LIVE_TEST\") == \"\" {\n\t\tt.Log(\"no flag\")\n\t}\n" + call),
		"flag skips when it is set": liveTest("\tif os.Getenv(\"RATES_LIVE_TEST\") != \"\" {\n\t\tt.Skip(\"inverted\")\n\t}\n" + call),
	}
	withEnv := liveTest("\trequireLiveFeed(t)\n" + call)
	withEnv[".env"] = "RATES_LIVE_TEST=1\n"
	reported["flag set by an env file"] = withEnv
	for name, files := range reported {
		t.Run(name, func(t *testing.T) {
			violations, err := NewTestExternalServiceRule().AnalyzeGoProject(rulestest.Project(t, files))
			require.NoError(t, err)
			require.Len(t, violations, 1, "%v", messages(violations))
			assert.Equal(t, "outbound_client", violations[0].Context["kind"])
		})
	}
}

// vendorClient takes its address from the caller and also offers the
// production one as a constant and through NewDefault.
const vendorClient = `package vendorapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

const DefaultBaseURL = "https://api.vendorapi.io/core"

type Client struct {
	base, key string
	http      *http.Client
}

func NewClient(base, key string) (*Client, error) {
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("api key is required")
	}
	return &Client{base: base, key: key, http: &http.Client{}}, nil
}

func NewDefault(key string) (*Client, error) { return NewClient(DefaultBaseURL, key) }

func (c *Client) Prices(ctx context.Context, ids []string) (*http.Response, error) {
	if len(ids) == 0 {
		return nil, errors.New("no ids")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/prices?ids="+strings.Join(ids, ","), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Key", c.key)
	return c.http.Do(req)
}
`

// The unit tests of a client - in a file that serves a test server - build it
// to check the key validation, the shared limiter or an empty input that fails
// before any request. None of them sends: building a client is no live call. A
// test of that file is reported when it calls a sending method on a client
// aimed at production - the constructor's own address, or the production URL
// or constant passed in.
func TestTestExternalServiceRule_ClientUnitTestsWithoutRequestAreNotReported(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"vendorapi/client.go": vendorClient,
		"vendorapi/client_test.go": `package vendorapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClientRequiresKey(t *testing.T) {
	if _, err := NewClient("https://api.vendorapi.io/core", "  "); err == nil {
		t.Fatal("a blank key must be rejected")
	}
}

func TestClientsShareOneBase(t *testing.T) {
	c, err := NewClient(DefaultBaseURL, "k")
	if err != nil || c.base != DefaultBaseURL {
		t.Fatal("the base address is kept")
	}
}

func TestPricesEmptyInput(t *testing.T) {
	c, _ := NewClient("http://stub", "k")
	if _, err := c.Prices(context.Background(), nil); err == nil {
		t.Fatal("empty ids must fail before the request")
	}
}

func TestPricesFromTestServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c, _ := NewClient(srv.URL, "k")
	_, _ = c.Prices(context.Background(), []string{"a"})
}

func TestPricesLiveDefault(t *testing.T) {
	c, _ := NewDefault("k")
	_, _ = c.Prices(context.Background(), []string{"a"})
}

func TestPricesLiveConstant(t *testing.T) {
	c, _ := NewClient(DefaultBaseURL, "k")
	_, _ = c.Prices(context.Background(), []string{"a"})
}
`,
		"pricing/pricing_test.go": `package pricing

import (
	"context"
	"net/http/httptest"
	"testing"

	"example.com/rulestest/vendorapi"
)

var _ = httptest.NewServer

func TestKeyCheckedAcrossPackages(t *testing.T) {
	if _, err := vendorapi.NewClient(vendorapi.DefaultBaseURL, ""); err == nil {
		t.Fatal("blank key")
	}
}

func TestPricesLiveAcrossPackages(t *testing.T) {
	c, _ := vendorapi.NewClient(vendorapi.DefaultBaseURL, "k")
	_, _ = c.Prices(context.Background(), []string{"a"})
}
`,
	})

	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	got := messages(violations)
	require.Len(t, violations, 3, "%v", got)
	assert.Contains(t, got[0], "TestPricesLiveAcrossPackages")
	assert.Contains(t, got[1], "TestPricesLiveDefault")
	assert.Contains(t, got[2], "TestPricesLiveConstant")
	for _, msg := range got {
		assert.Contains(t, msg, "https://api.vendorapi.io/core")
	}
}

// A package of two clients holds two addresses: the finding names the one the
// called constructor reaches, not the first literal of the package.
func TestTestExternalServiceRule_FindingNamesTheEntrysOwnAddress(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"feeds/a.go": `package feeds

import "net/http"

const quotesURL = "https://quotes.avendor.io"

type Quotes struct{ http *http.Client }

func NewQuotes() *Quotes { return &Quotes{http: &http.Client{}} }

func (q *Quotes) Get() (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, quotesURL, nil)
	if err != nil {
		return nil, err
	}
	return q.http.Do(req)
}
`,
		"feeds/b.go": `package feeds

import "net/http"

type Chain struct{ http *http.Client }

func NewChain() *Chain { return &Chain{http: &http.Client{}} }

func (c *Chain) Head() (*http.Response, error) {
	req, err := http.NewRequest(http.MethodHead, "https://rpc.bvendor.io", nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}
`,
		"feeds/chain_test.go": `package feeds

import "testing"

func TestChainHead(t *testing.T) {
	_, _ = NewChain().Head()
}
`,
	})

	violations, err := NewTestExternalServiceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1, "%v", messages(violations))
	assert.Contains(t, violations[0].Message, "https://rpc.bvendor.io")
}
