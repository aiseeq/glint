package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestLogAndReturnZeroRule(t *testing.T) {
	rule := NewLogAndReturnZeroRule()

	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			name: "empty issuer returned after error log",
			code: `package auth

func (m *TokenManager) getJWTIssuer() string {
	if m.config == nil {
		m.logger.Error("Configuration not available for JWT issuer")
		return ""
	}
	return m.config.GetJWTIssuer()
}
`,
			wantCount: 1,
		},
		{
			name: "zero duration returned after parse warning",
			code: `package config

func (l *Loader) GetServerReadTimeout() time.Duration {
	d, err := time.ParseDuration(l.raw)
	if err != nil {
		logger.Warn("invalid read timeout, using default", "error", err)
		return 0
	}
	return d
}
`,
			wantCount: 1,
		},
		{
			name: "function with error result is out of scope",
			code: `package auth

func (m *TokenManager) getJWTIssuer() (string, error) {
	if m.config == nil {
		m.logger.Error("Configuration not available for JWT issuer")
		return "", fmt.Errorf("config is nil")
	}
	return m.config.GetJWTIssuer(), nil
}
`,
			wantCount: 0,
		},
		{
			name: "info-level log is not an error path",
			code: `package svc

func (s *Service) cacheKey() string {
	if s.prefix == "" {
		s.logger.Info("no prefix configured, using bare keys")
		return ""
	}
	return s.prefix + ":"
}
`,
			wantCount: 0,
		},
		{
			name: "false after log is error-masked-as-false-bool territory",
			code: `package svc

func (s *Service) isReady() bool {
	if s.conn == nil {
		s.logger.Error("connection is nil")
		return false
	}
	return s.conn.Alive()
}
`,
			wantCount: 0,
		},
		{
			name: "http handler writes the error to the response",
			code: `package api

func (h *Handler) resolveTheme(w http.ResponseWriter, r *http.Request) string {
	theme, err := h.svc.Theme(r.Context())
	if err != nil {
		h.logger.Error("theme lookup failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return ""
	}
	return theme
}
`,
			wantCount: 0,
		},
		{
			name: "computed value after log is a real recovery",
			code: `package svc

func (s *Service) endpoint() string {
	if s.override == "" {
		s.logger.Warn("no override, deriving endpoint from region")
		return s.deriveFromRegion()
	}
	return s.override
}
`,
			wantCount: 0,
		},
		{
			name: "nil map returned after error log",
			code: `package svc

func (s *Service) headers() map[string]string {
	if s.cfg == nil {
		s.logger.Error("config missing, headers unavailable")
		return nil
	}
	return s.cfg.Headers
}
`,
			wantCount: 1,
		},
		{
			name: "test files are skipped by IsTestFile guard",
			code: `package svc

func helper() string {
	logger.Error("boom")
	return ""
}
`,
			wantCount: 1,
		},
		{
			// A setup helper that warns and returns leaves the dependency
			// nil: the router starts, every session endpoint fails later.
			name: "setup helper warns and leaves the dependency unset",
			code: `package routing

func createSessionManager(ctx *routerContext) {
	cfg, ok := ctx.config.(*Config)
	if !ok {
		ctx.logger.Warn("config is not the full config, session management disabled")
		return
	}
	if cfg.Secret == "" {
		ctx.logger.Warn("secret not configured, session management disabled")
		return
	}
	ctx.sessionManager = NewSessionManager(cfg.Secret)
	ctx.logger.Info("session manager initialized")
}

func (s *Server) startMetrics() {
	if s.cfg.MetricsAddr == "" {
		s.logger.Info("metrics disabled")
		return
	}
	s.metrics = NewMetrics(s.cfg.MetricsAddr)
}

func (s *Service) appendRewards(address string, wb *WalletBalance) {
	if s.client == nil {
		return
	}
	rewards, err := s.client.Rewards(address)
	if err != nil {
		s.logger.Warn("rewards lookup failed", "error", err)
		return
	}
	wb.Tokens = append(wb.Tokens, rewards...)
	cfg := DefaultConfig()
	if !s.enabled {
		s.logger.Error("scheduler disabled")
		return
	}
	cfg.Port = NewPort()
	wb.Total = sumTokens(wb.Tokens)
}

func stampRate(logger *Logger, pos *Position, snapshot *Snapshot) {
	rate, err := resolveRate(pos)
	if err != nil {
		logger.Warn("rate not resolved", "error", err)
		return
	}
	snapshot.APY = NewDecimal(rate)
}

func (s *Server) refresh() {
	if err := s.load(); err != nil {
		s.logger.Warn("refresh failed", "error", err)
		return
	}
	s.count++
}
`,
			wantCount: 2,
		},
		{
			name: "debug log in an error branch hides the failure as well",
			code: `package svc

func (s *Service) fetchTokens(ctx context.Context, addr string) []Token {
	if err := s.wait(ctx); err != nil {
		s.logger.Debug("wait failed", "error", err)
		return nil
	}
	return s.load(addr)
}
`,
			wantCount: 1,
		},
		{
			name: "lookup failure answered with the function's own input",
			code: `package svc

func (s *Service) canonicalWallet(ctx context.Context, wallet string) string {
	trimmed := strings.TrimSpace(wallet)
	stored, err := s.repo.StoredSpelling(ctx, trimmed)
	if err != nil {
		s.logger.Error("spelling lookup failed", "error", err)
		return trimmed
	}
	if stored != "" {
		return stored
	}
	return trimmed
}
`,
			wantCount: 1,
		},
		{
			name: "normalizer that only ever returns its input is not a fallback",
			code: `package svc

func (s *Service) clean(name string) string {
	if err := s.check(name); err != nil {
		s.logger.Warn("odd name", "error", err)
		return name
	}
	return name
}
`,
			wantCount: 0,
		},
		{
			name: "builder warns on a failed constructor and leaves the client unset",
			code: `package svc

func newClients(cfg *Config) clients {
	c := clients{prices: prices.NewClient(cfg.Timeout)}
	chainClient, err := chain.NewClient(cfg.Timeout, os.Getenv("CHAIN_KEY"))
	if err != nil {
		cfg.Logger.Warn("chain source disabled", "error", err)
	} else {
		c.chain = chainClient
	}
	return c
}
`,
			wantCount: 1,
		},
		{
			name: "builder that fails on a constructor error is fine",
			code: `package svc

func newClients(cfg *Config) (clients, error) {
	c := clients{}
	chainClient, err := chain.NewClient(cfg.Timeout)
	if err != nil {
		cfg.Logger.Warn("chain source disabled", "error", err)
		return c, err
	}
	c.chain = chainClient
	return c, nil
}
`,
			wantCount: 0,
		},
		{
			name: "progress write failure only logged while the result reports failures in its Error field",
			code: `package sync

func (s *Service) syncChain(ctx context.Context, wallet, chain string) *Result {
	result := &Result{Wallet: wallet, Chain: chain}
	outcome, err := s.fetch(ctx, wallet, chain)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.NewCount = outcome.count
	if err := s.repo.FinishSync(ctx, wallet, chain, outcome.cursor); err != nil {
		s.logger.Warn("failed to finish sync", "error", err)
	}
	return result
}
`,
			wantCount: 1,
		},
		{
			name: "a result without an Error field leaves the logged write to the caller's contract",
			code: `package sync

func (s *Service) touch(ctx context.Context, id string) *Entry {
	entry := &Entry{ID: id}
	if err := s.repo.UpdateSeen(ctx, id); err != nil {
		s.logger.Warn("failed to update seen", "error", err)
	}
	return entry
}
`,
			wantCount: 0,
		},
		{
			name: "try function answers nil after a debug line by contract",
			code: `package auth

func (m *Middleware) tryClaimsFromHeader(r *http.Request) *Claims {
	token, err := extractBearer(r)
	if err != nil {
		m.logger.Debug("no bearer token", "reason", err.Error())
		return nil
	}
	return parse(token)
}
`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := rulestest.InMemoryGoFile(t, "service.go", ".", tt.code, nil)

			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d; violations: %+v",
					len(violations), tt.wantCount, violations)
			}
		})
	}
}
