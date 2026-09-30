package patterns

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func violationPlaces(violations []*core.Violation) []string {
	places := make([]string, 0, len(violations))
	for _, v := range violations {
		places = append(places, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	return places
}

// nilDIWiring declares the dependencies and constructors the path cases wire.
const nilDIWiring = `package svc

type Logger interface{ Print(msg string) }

type Repo interface{ Find(id string) error }

type SessionManager struct{ ttl int }

type TxGetter interface{ Get(id string) error }

type AuthServiceDependencies struct{ Logger Logger }

type Service struct{}

type Services struct {
	StorageService Repo
	Logger         Logger
	Name           string
}

type AdminSessionHandler struct{ sessionManager *SessionManager }

func NewStakingService(balanceRepo Repo, logger Logger) *Service { return &Service{} }

func NewAdminSessionHandler(logger Logger, sessionManager *SessionManager) *AdminSessionHandler {
	return &AdminSessionHandler{sessionManager: sessionManager}
}

func NewPollingService(logger Logger, transactionGetter TxGetter) *Service { return &Service{} }

type Factory struct{}

func (f *Factory) CreateAdminAuthService(deps *AuthServiceDependencies) *Service { return &Service{} }
`

// A nil reaches the dependency through a local variable that holds nothing
// else: declared as nil, declared without a value, or a typed nil conversion.
func TestNilDIRule_NilThroughLocalVariable(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilDIRule(), map[string]string{
		"svc/types.go": nilDIWiring,
		"svc/wire.go": `package svc

func wireStaking(l Logger) *Service {
	var balanceRepo Repo = nil
	return NewStakingService(balanceRepo, l)
}

func wireServices(l Logger) Services {
	var storageSvc Repo
	return Services{StorageService: storageSvc, Logger: l}
}

func wireSessions(l Logger) *AdminSessionHandler {
	sessionManager := (*SessionManager)(nil)
	return &AdminSessionHandler{sessionManager: sessionManager}
}

func wireAssigned(l Logger, find func() Repo) *Service {
	var repo Repo
	repo = find()
	return NewStakingService(repo, l)
}

func wireAddressed(l Logger, fill func(*Repo)) *Service {
	var repo Repo
	fill(&repo)
	return NewStakingService(repo, l)
}

func wireName() Services {
	var name string
	return Services{Name: name}
}
`,
	})
	assert.Equal(t, []string{"svc/wire.go:4", "svc/wire.go:9", "svc/wire.go:14"}, violationPlaces(violations))
}

// A nil written straight into the dependency field of a struct literal.
func TestNilDIRule_NilDependencyFieldInLiteral(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilDIRule(), map[string]string{
		"svc/types.go": nilDIWiring,
		"svc/wire.go": `package svc

var _ Repo = (*repoImpl)(nil)

type repoImpl struct{}

func (r *repoImpl) Find(id string) error { return nil }

func wire(l Logger) Services {
	return Services{
		StorageService: nil,
		Logger:         l,
	}
}

func lookup() map[string]Logger {
	return map[string]Logger{"default": nil}
}
`,
	})
	assert.Equal(t, []string{"svc/wire.go:11"}, violationPlaces(violations))
}

// A manager, a getter and a dependencies struct are dependencies too, and a
// Create factory is a constructor.
func TestNilDIRule_ManagerGetterAndFactoryDeps(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilDIRule(), map[string]string{
		"svc/types.go": nilDIWiring,
		"svc/wire.go": `package svc

func wireSession(l Logger) *AdminSessionHandler {
	return NewAdminSessionHandler(l, nil)
}

func wirePolling(l Logger) *Service {
	return NewPollingService(l, nil)
}

func wireAuth() *Service {
	return (&Factory{}).CreateAdminAuthService(nil)
}
`,
	})
	assert.Equal(t, []string{"svc/wire.go:4", "svc/wire.go:8", "svc/wire.go:12"}, violationPlaces(violations))
}

// Test files stay out: a nil that crashes a test fails it, and a nil for a
// dependency the test does not reach is how tests are written.
func TestNilDIRule_TestFilesStaySilent(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilDIRule(), map[string]string{
		"middleware/auth.go": `package middleware

import "errors"

type Logger interface{ Print(msg string) }

type Config struct{}

type AdminAuth struct{ logger Logger }

func NewAdminAuthMiddleware(logger Logger, cfg *Config) *AdminAuth {
	return &AdminAuth{logger: logger}
}

func NewGuardedMiddleware(logger Logger, cfg *Config) (*AdminAuth, error) {
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	return &AdminAuth{logger: logger}, nil
}
`,
		"middleware/auth_test.go": `package middleware

import "testing"

func TestSamePackage(t *testing.T) {
	_ = NewAdminAuthMiddleware(nil, &Config{})
}
`,
		"app/auth_test.go": `package app

import (
	"testing"

	"example.com/rulestest/middleware"
)

func TestAuth(t *testing.T) {
	_ = middleware.NewAdminAuthMiddleware(nil, &middleware.Config{})
	if _, err := middleware.NewGuardedMiddleware(nil, &middleware.Config{}); err == nil {
		t.Fatal("expected an error")
	}
}
`,
	})
	assert.Empty(t, violationPlaces(violations))
}

// In packages that do not type-check a constructor is still found by name:
// in a sibling file of the same directory, or in the directory an import
// path ends with.
func TestNilDIRule_UntypedConstructorInSiblingAndImportedDirectory(t *testing.T) {
	violations := runRuleOnBrokenFiles(t, NewNilDIRule(), map[string]string{
		"services/staking.go": `package services

type BalanceRepository interface{ Balance() int }

type StakingService struct{ repo BalanceRepository }

func NewStakingService(balanceRepo BalanceRepository) *StakingService {
	return &StakingService{repo: balanceRepo}
}

var broken int = "not an int"
`,
		"services/wire.go": `package services

func wireLocal() *StakingService {
	var balanceRepo BalanceRepository = nil
	return NewStakingService(balanceRepo)
}
`,
		"app/main.go": `package app

import admin "example.com/rulestest/services"

func wire() {
	var repo admin.BalanceRepository = nil
	_ = admin.NewStakingService(repo)
}

var alsoBroken int = "x"
`,
	})
	assert.Equal(t, []string{"app/main.go:6", "services/wire.go:4"}, violationPlaces(violations))
}
