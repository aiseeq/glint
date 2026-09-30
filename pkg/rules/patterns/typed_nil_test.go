package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypedNilIntoInterfaceStoreEvidence(t *testing.T) {
	tests := []struct {
		name      string
		wiring    string
		expectPtr string
	}{
		{
			// Пустой указатель заменён настоящим значением до передачи: после
			// `if m == nil { m = &Mailer{} }` он не пуст.
			name: "pointer replaced when nil before the setter",
			wiring: `package app

func (s *Service) SetAlerter(a Alerter) { s.alerter = a }

func wire(s *Service, m *Mailer) {
	if m == nil {
		m = &Mailer{}
	}
	s.SetAlerter(m)
}
`,
		},
		{
			name: "pointer assigned a new value before the setter",
			wiring: `package app

func (s *Service) SetAlerter(a Alerter) { s.alerter = a }

func wire(s *Service, m *Mailer) bool {
	ok := m != nil
	m = new(Mailer)
	s.SetAlerter(m)
	return ok
}
`,
		},
		{
			// Самая частая форма конструктора: поле интерфейсного типа в литерале.
			name: "nil-able pointer in a composite literal field",
			wiring: `package app

func (f *Factory) enabled() bool { return f.mailer != nil }

func (f *Factory) build() *Service {
	return &Service{alerter: f.mailer}
}
`,
			expectPtr: "f.mailer",
		},
		{
			name: "nil-able pointer as a positional composite literal element",
			wiring: `package app

func (f *Factory) enabled() bool { return f.mailer != nil }

func (f *Factory) build() Service {
	return Service{f.mailer}
}
`,
			expectPtr: "f.mailer",
		},
		{
			name: "composite literal field under a nil guard",
			wiring: `package app

func (f *Factory) build() *Service {
	if f.mailer == nil {
		return &Service{}
	}
	return &Service{alerter: f.mailer}
}
`,
		},
		{
			// Получатель выбирается по тому, что он делает с параметром, а не по
			// имени: Attach хранит его в поле.
			name: "callee storing the parameter whatever its name",
			wiring: `package app

func (s *Service) Attach(a Alerter) { s.alerter = a }

func (f *Factory) enabled() bool { return f.mailer != nil }

func (f *Factory) build(s *Service) {
	s.Attach(f.mailer)
}
`,
			expectPtr: "f.mailer",
		},
		{
			name: "constructor delegating to a storing helper",
			wiring: `package app

func NewServiceFrom(a Alerter) *Service { return newService(a) }

func newService(a Alerter) *Service {
	s := &Service{}
	s.alerter = a
	return s
}

func (f *Factory) enabled() bool { return f.mailer != nil }

func (f *Factory) build() *Service {
	return NewServiceFrom(f.mailer)
}
`,
			expectPtr: "f.mailer",
		},
		{
			// New-префикс ещё не значит, что параметр сохраняется: NewReport
			// только вызывает метод и ничего не хранит.
			name: "New-prefixed callee that does not store the parameter",
			wiring: `package app

func NewReport(a Alerter) string {
	if a == nil {
		return ""
	}
	return "report"
}

func (f *Factory) enabled() bool { return f.mailer != nil }

func (f *Factory) build() string {
	return NewReport(f.mailer)
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project := optDepProject(t, map[string]string{
				"service.go": typedNilBase,
				"wiring.go":  tt.wiring,
			})
			violations, err := NewTypedNilIntoInterfaceRule().AnalyzeGoProject(project)
			require.NoError(t, err)
			if tt.expectPtr == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Equal(t, tt.expectPtr, violations[0].Context["pointer"])
		})
	}
}
