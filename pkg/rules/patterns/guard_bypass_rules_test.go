package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A request field named as a credential that the handler only tests for
// presence: any non-empty signature passes, nothing verifies it.
func TestCredentialPresenceOnly(t *testing.T) {
	file := rulestest.GoFile(t, "api/auth.go", `package api

import (
	"encoding/json"
	"net/http"
)

type service interface {
	Connect(wallet string) error
	Verify(wallet, signature string) error
}

func login(w http.ResponseWriter, r *http.Request, s service) {
	var req struct {
		Wallet    string `+"`json:\"wallet\"`"+`
		Signature string `+"`json:\"signature\"`"+`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}
	if req.Signature == "" {
		http.Error(w, "signature required", http.StatusBadRequest)
		return
	}
	_ = s.Connect(req.Wallet)
}

func verified(w http.ResponseWriter, r *http.Request, s service) {
	var req struct {
		Wallet    string
		Signature string
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}
	if req.Signature == "" {
		return
	}
	_ = s.Verify(req.Wallet, req.Signature)
}

type loginRequest struct {
	Wallet string
	Token  string
}

func (l loginRequest) check() error { return nil }

func wholeValue(r *http.Request, s service) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}
	if len(req.Token) == 0 {
		return
	}
	_ = req.check()
}

func notCredential(r *http.Request, s service) {
	var req struct{ Wallet, Comment string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}
	if req.Comment == "" {
		return
	}
	_ = s.Connect(req.Wallet)
}
`)
	assert.Equal(t, []string{"api/auth.go:21"}, foundLines(NewCredentialPresenceOnlyRule().AnalyzeFile(file)))
}

// A validator that waves through a value marked as test data: in
// production anyone can send that marker.
func TestTestValueBypass(t *testing.T) {
	file := rulestest.GoFile(t, "auth/verify.go", `package auth

import (
	"errors"
	"strings"
)

func verifySignature(signature string) error {
	if !strings.Contains(signature, "testsignature") {
		if len(signature) < 10 {
			return errors.New("bad signature")
		}
	}
	return nil
}

func isChainAddress(address string) bool {
	if strings.HasPrefix(address, "TEST") && len(address) >= 4 {
		return true
	}
	return len(address) == 34
}

func isAccountToken(token string) (bool, error) {
	if token == "fake-token" {
		return true, nil
	}
	return false, nil
}

func describe(name string) bool {
	return strings.HasPrefix(name, "Test")
}

func label(address string) string {
	if strings.HasPrefix(address, "test") {
		return "sandbox"
	}
	return "live"
}

func environment(env string) error {
	if env == "test" {
		return nil
	}
	return errors.New("not test")
}

func isTestEmail(email string) bool {
	if strings.HasPrefix(email, "test") {
		return true
	}
	return strings.HasSuffix(email, "@test.example")
}
`)
	assert.Equal(t, []string{"auth/verify.go:18", "auth/verify.go:25", "auth/verify.go:9"},
		foundLines(NewTestValueBypassRule().AnalyzeFile(file)))
}

// A getter named for a general setting that hands out the value configured
// for tests: production code calling it runs with test timeouts.
func TestTestConfigInProduction(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"config/config.go": `package config

import "time"

type Timeouts struct {
	Test   struct{ Operation time.Duration }
	Server struct{ Write time.Duration }
}

type Config struct{ Timeouts Timeouts }

type Interface interface {
	OperationTimeout() time.Duration
	WriteTimeout() time.Duration
	TestOperationTimeout() time.Duration
}

func (c *Config) OperationTimeout() time.Duration { return c.Timeouts.Test.Operation }

func (c *Config) WriteTimeout() time.Duration { return c.Timeouts.Server.Write }

func (c *Config) TestOperationTimeout() time.Duration { return c.Timeouts.Test.Operation }
`,
		"server/server.go": `package server

import (
	"time"

	"example.com/rulestest/config"
)

func recovery(cfg config.Interface, c *config.Config) []time.Duration {
	return []time.Duration{
		cfg.OperationTimeout(),
		c.OperationTimeout(),
		cfg.WriteTimeout(),
		cfg.TestOperationTimeout(),
	}
}
`,
	})
	violations, err := NewTestConfigInProductionRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []string{"server/server.go:11", "server/server.go:12"}, foundLines(violations))
}

// A rejection that runs only while an optional dependency is set: with the
// dependency missing, the dangerous value goes through.
func TestNilDependencySkipsRejection(t *testing.T) {
	file := rulestest.GoFile(t, "deposit/provider.go", `package deposit

import (
	"errors"
	"fmt"
	"net/http"
)

type registry interface{ IsContract(address string) bool }

type Provider struct {
	registry registry
	metrics  interface{ Inc() }
}

func (p *Provider) address(addr string) (string, error) {
	if p.registry != nil && p.registry.IsContract(addr) {
		return "", fmt.Errorf("address %s is a contract", addr)
	}
	return addr, nil
}

func (p *Provider) serve(w http.ResponseWriter, addr string) {
	if p.registry != nil && p.registry.IsContract(addr) {
		http.Error(w, "contract", http.StatusBadRequest)
		return
	}
}

func (p *Provider) count() error {
	if p.metrics != nil {
		p.metrics.Inc()
	}
	return nil
}

func (p *Provider) required(addr string) error {
	if p.registry == nil {
		return errors.New("registry not configured")
	}
	if p.registry.IsContract(addr) {
		return errors.New("contract")
	}
	return nil
}

func (p *Provider) noRejection(addr string) error {
	if p.registry != nil && p.registry.IsContract(addr) {
		return nil
	}
	return nil
}

type Lock struct{ LockedBy *Actor }

type Actor struct{ ID string }

func (a *Actor) IsValid() bool { return a.ID != "" }

func (l Lock) Validate() error {
	if l.LockedBy != nil && !l.LockedBy.IsValid() {
		return errors.New("invalid actor")
	}
	return nil
}

type named interface{ Pkg() *Actor }

func fromPackage(fn named) error {
	if fn.Pkg() != nil && fn.Pkg().IsValid() {
		return errors.New("from a package")
	}
	return nil
}

type Factory struct{ adminRouter interface{ Service() any } }

func build() (any, error) { return nil, nil }

func (f *Factory) register() error {
	if f.adminRouter != nil && f.adminRouter.Service() != nil {
		if _, err := build(); err != nil {
			return fmt.Errorf("build: %w", err)
		}
	}
	return nil
}
`)
	assert.Equal(t, []string{"deposit/provider.go:17", "deposit/provider.go:24"},
		foundLines(NewNilDependencySkipsRejectionRule().AnalyzeFile(file)))
}

// A safety guard that lists the environments where it refuses lets every
// other value through — an unset or misspelled environment included; and a
// switch that takes an empty setting for development skips the restriction
// when the setting is missing.
func TestEnvironmentCheckFailsOpen(t *testing.T) {
	file := rulestest.GoFile(t, "store/reset.go", `package store

import (
	"errors"
	"strings"
)

type Repo struct{ environment string }

func (r *Repo) Reset() error {
	if r.environment == "production" || r.environment == "staging" {
		return errors.New("reset is forbidden here")
	}
	return nil
}

func (r *Repo) ResetAllowed() error {
	if r.environment != "test" && r.environment != "development" {
		return errors.New("reset is allowed in test and development only")
	}
	return nil
}

func (r *Repo) Cookies() bool {
	if r.environment == "production" {
		return true
	}
	return false
}

type Config struct{ BaseDomain string; Origins []string }

func sanitize(c *Config) {
	base := c.BaseDomain
	if base == "" || base == "app.local" {
		return
	}
	kept := c.Origins[:0]
	for _, origin := range c.Origins {
		if !strings.Contains(origin, ".local") {
			kept = append(kept, origin)
		}
	}
	c.Origins = kept
}

func trim(c *Config) {
	if c.BaseDomain == "" {
		return
	}
	c.BaseDomain = strings.TrimSpace(c.BaseDomain)
}
`)
	assert.Equal(t, []string{"store/reset.go:11", "store/reset.go:35"},
		foundLines(NewEnvironmentCheckFailsOpenRule().AnalyzeFile(file)))
}
