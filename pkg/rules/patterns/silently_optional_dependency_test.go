package patterns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestSilentlyOptionalDependencyRule_Metadata(t *testing.T) {
	rule := NewSilentlyOptionalDependencyRule()
	assert.Equal(t, "silently-optional-dependency", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
}

// serviceSource — сервис с зависимостью, которую задают сеттером, и молчаливым выходом
// по её отсутствию. Точки сборки живут в отдельном файле: их количество и решает.
const serviceSource = `package svc

type Alerter interface{ Send() }

type Service struct {
	name    string
	alerter Alerter
}

func NewService(name string) *Service { return &Service{name: name} }

func (s *Service) SetAlerter(a Alerter) { s.alerter = a }

func (s *Service) Report() {
	if s.alerter == nil {
		return
	}
	s.alerter.Send()
}
`

func TestSilentlyOptionalDependencyRule_Detection(t *testing.T) {
	tests := []struct {
		name        string
		service     string
		wiring      string
		expectField string
		expectMsg   string
	}{
		{
			// Ровно форма REF-446: сборок больше, чем вызовов сеттера.
			name:    "one of two construction sites skips the setter",
			service: serviceSource,
			wiring: `package svc

func BuildReporting(a Alerter) *Service {
	s := NewService("reporting")
	s.SetAlerter(a)
	return s
}

func BuildNightly() *Service {
	return NewService("nightly")
}
`,
			expectField: "alerter",
			expectMsg:   "1 of 2 construction sites",
		},
		{
			// Сеттер зовут на каждой сборке — сервис собран правильно.
			name:    "every construction site calls the setter",
			service: serviceSource,
			wiring: `package svc

func BuildReporting(a Alerter) *Service {
	s := NewService("reporting")
	s.SetAlerter(a)
	return s
}

func BuildNightly(a Alerter) *Service {
	s := NewService("nightly")
	s.SetAlerter(a)
	return s
}
`,
		},
		{
			// Единственная точка сборки: потерять зависимость пока негде.
			name:    "single construction site",
			service: serviceSource,
			wiring: `package svc

func Build() *Service { return NewService("only") }
`,
		},
		{
			// Конструктор заполняет поле сам — зависимость обязательная.
			name: "constructor fills the field",
			service: `package svc

type Alerter interface{ Send() }

type Service struct{ alerter Alerter }

func NewService(a Alerter) *Service { return &Service{alerter: a} }

func (s *Service) SetAlerter(a Alerter) { s.alerter = a }

func (s *Service) Report() {
	if s.alerter == nil {
		return
	}
	s.alerter.Send()
}
`,
			wiring: `package svc

func BuildOne(a Alerter) *Service { return NewService(a) }
func BuildTwo(a Alerter) *Service { return NewService(a) }
`,
		},
		{
			// Отсутствие видно вызывающему — это осознанная опциональность, а не пропажа.
			name: "guard returns an error",
			service: `package svc

import "errors"

type Alerter interface{ Send() error }

type Service struct{ alerter Alerter }

func NewService() *Service { return &Service{} }

func (s *Service) SetAlerter(a Alerter) { s.alerter = a }

func (s *Service) Report() error {
	if s.alerter == nil {
		return errors.New("no alerter")
	}
	return s.alerter.Send()
}
`,
			wiring: `package svc

func BuildOne(a Alerter) *Service {
	s := NewService()
	s.SetAlerter(a)
	return s
}

func BuildTwo() *Service { return NewService() }
`,
		},
		{
			// Нет молчаливого выхода: отсутствие зависимости уронит сервис заметно.
			name: "no nil guard at all",
			service: `package svc

type Alerter interface{ Send() }

type Service struct{ alerter Alerter }

func NewService() *Service { return &Service{} }

func (s *Service) SetAlerter(a Alerter) { s.alerter = a }

func (s *Service) Report() { s.alerter.Send() }
`,
			wiring: `package svc

func BuildOne(a Alerter) *Service {
	s := NewService()
	s.SetAlerter(a)
	return s
}

func BuildTwo() *Service { return NewService() }
`,
		},
		{
			// Метод делает не только присваивание — это не инъекция зависимости.
			name: "setter with extra work is not dependency injection",
			service: `package svc

type Alerter interface{ Send() }

type Service struct {
	alerter Alerter
	count   int
}

func NewService() *Service { return &Service{} }

func (s *Service) SetAlerter(a Alerter) {
	s.alerter = a
	s.count++
}

func (s *Service) Report() {
	if s.alerter == nil {
		return
	}
	s.alerter.Send()
}
`,
			wiring: `package svc

func BuildOne(a Alerter) *Service {
	s := NewService()
	s.SetAlerter(a)
	return s
}

func BuildTwo() *Service { return NewService() }
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project := optDepProject(t, map[string]string{
				"service.go": tt.service,
				"wiring.go":  tt.wiring,
			})
			violations, err := NewSilentlyOptionalDependencyRule().AnalyzeGoProject(project)
			require.NoError(t, err)
			if tt.expectField == "" {
				assert.Empty(t, violations, "ожидалось отсутствие находок: %s", tt.name)
				return
			}
			require.Len(t, violations, 1, "ожидалась одна находка: %s", tt.name)
			assert.Equal(t, "silently_optional_dependency", violations[0].Context["pattern"])
			assert.Equal(t, tt.expectField, violations[0].Context["field"])
			assert.Contains(t, violations[0].Message, tt.expectMsg)
		})
	}
}

// Тестовые файлы конструируют сервис без зависимостей намеренно, и в счёт точек
// сборки не идут — иначе правило срабатывало бы на каждом сервисе с юнит-тестами.
func TestSilentlyOptionalDependencyRule_TestFilesDoNotCount(t *testing.T) {
	project := optDepProject(t, map[string]string{
		"service.go": serviceSource,
		"wiring.go": `package svc

func Build(a Alerter) *Service {
	s := NewService("only")
	s.SetAlerter(a)
	return s
}
`,
		"service_test.go": `package svc

import "testing"

func TestReport(t *testing.T) {
	NewService("first").Report()
	NewService("second").Report()
}
`,
	})
	violations, err := NewSilentlyOptionalDependencyRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestSilentlyOptionalDependencyRule_NilProject(t *testing.T) {
	_, err := NewSilentlyOptionalDependencyRule().AnalyzeGoProject(nil)
	require.Error(t, err)
}

func optDepProject(t *testing.T, files map[string]string) *core.GoProjectContext {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/svc\n\ngo 1.24\n"), 0o644))

	var contexts []*core.FileContext
	for name, source := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(path, []byte(source), 0o644))
		ctx, err := core.NewFileContextChecked(path, root, []byte(source), core.DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}

	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	return project
}
