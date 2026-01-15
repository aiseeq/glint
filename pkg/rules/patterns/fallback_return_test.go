package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestFallbackReturnRule(t *testing.T) {
	rule := NewFallbackReturnRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
		wantMsg   string
	}{
		{
			name: "return testProvider on error",
			code: `package main

func GetProvider() Provider {
	provider, err := createProvider()
	if err != nil {
		return testProvider
	}
	return provider
}`,
			filename:  "provider.go",
			wantCount: 1,
			wantMsg:   "Fallback return",
		},
		{
			name: "return mockService on error",
			code: `package main

func GetService() Service {
	svc, err := initService()
	if err != nil {
		return mockService
	}
	return svc
}`,
			filename:  "service.go",
			wantCount: 1,
			wantMsg:   "Fallback return",
		},
		{
			name: "return fallbackConfig on error",
			code: `package main

func LoadConfig() *Config {
	cfg, err := readConfig()
	if err != nil {
		return fallbackConfig
	}
	return cfg
}`,
			filename:  "config_loader.go",
			wantCount: 1,
			wantMsg:   "Fallback return",
		},
		{
			name: "return fallbackHandler on nil",
			code: `package main

func GetHandler(h Handler) Handler {
	if h == nil {
		return fallbackHandler
	}
	return h
}`,
			filename:  "handler.go",
			wantCount: 1,
			wantMsg:   "Fallback return",
		},
		{
			name: "NewMockClient on error",
			code: `package main

func GetClient() Client {
	client, err := connectClient()
	if err != nil {
		return NewMockClient()
	}
	return client
}`,
			filename:  "client.go",
			wantCount: 1,
			wantMsg:   "Fallback return",
		},
		{
			name: "valid error return - should not flag",
			code: `package main

func GetProvider() (Provider, error) {
	provider, err := createProvider()
	if err != nil {
		return nil, err
	}
	return provider, nil
}`,
			filename:  "provider.go",
			wantCount: 0,
		},
		{
			name: "test file - should skip",
			code: `package main

func GetProvider() Provider {
	if err != nil {
		return testProvider
	}
	return provider
}`,
			filename:  "provider_test.go",
			wantCount: 0,
		},
		{
			name: "mock directory - should skip",
			code: `package mock

func GetProvider() Provider {
	return mockProvider
}`,
			filename:  "mock/provider.go",
			wantCount: 0,
		},
		{
			name: "no error context - should not flag",
			code: `package main

func GetProvider() Provider {
	return testProvider
}`,
			filename:  "provider.go",
			wantCount: 0,
		},
		{
			name: "assignment with fallback",
			code: `package main

func InitProvider() {
	provider, err := createProvider()
	if err != nil {
		provider = fallbackProvider // use fallback
	}
	use(provider)
}`,
			filename:  "provider.go",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.filename, ".", []byte(tt.code), nil)

			violations := rule.AnalyzeFile(ctx)

			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d", len(violations), tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s at line %d", v.Message, v.Line)
				}
			}

			if tt.wantMsg != "" && len(violations) > 0 {
				found := false
				for _, v := range violations {
					if strings.Contains(v.Message, tt.wantMsg) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected message containing %q, got %v", tt.wantMsg, violations)
				}
			}
		})
	}
}

func TestFallbackReturnRule_TypeScript(t *testing.T) {
	rule := NewFallbackReturnRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name: "return mockService on error in TS",
			code: `
function getService(): Service {
  const svc = initService();
  if (!svc) {
    return mockService;
  }
  return svc;
}`,
			filename:  "service.ts",
			wantCount: 1,
		},
		{
			name: "test file - should skip",
			code: `
function getService(): Service {
  if (!svc) {
    return mockService;
  }
  return svc;
}`,
			filename:  "service.test.ts",
			wantCount: 0,
		},
		{
			name: "nullish coalescing with fallback",
			code: `
function getConfig() {
  const cfg = loadConfig();
  if (!cfg) {
    return cfg ?? fallbackConfig;
  }
  return cfg;
}`,
			filename:  "config.ts",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.filename, ".", []byte(tt.code), nil)

			violations := rule.AnalyzeFile(ctx)

			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d", len(violations), tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s at line %d", v.Message, v.Line)
				}
			}
		})
	}
}
