package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestTypedNilIntoInterfaceRule_Metadata(t *testing.T) {
	rule := NewTypedNilIntoInterfaceRule()
	assert.Equal(t, "typed-nil-into-interface", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
}

// Общая часть: сервис, отличающий отсутствие получателя проверкой интерфейса на nil,
// и почтовый сервис, которого может не быть.
const typedNilBase = `package app

type Alerter interface{ Send() error }

type Mailer struct{ host string }

func (m *Mailer) Send() error { return nil }

type Service struct{ alerter Alerter }

func NewService(a Alerter) *Service { return &Service{alerter: a} }

func (s *Service) Report() {
	if s.alerter == nil {
		return
	}
	_ = s.alerter.Send()
}

type Factory struct{ mailer *Mailer }
`

// Проверка на nil должна лежать в том же файле, что и использование: правило берёт
// доказательство «указатель бывает пустым» только внутри файла, иначе поля вроде
// fn.Body, проверяемые на nil в сотнях мест, делают опасным любое их использование.

func TestTypedNilIntoInterfaceRule_Detection(t *testing.T) {
	tests := []struct {
		name        string
		wiring      string
		expectPtr   string
		expectInMsg string
	}{
		{
			// Ровно случай инцидента: указатель сравнивают с nil в другом месте, значит он
			// бывает пустым, а тут он уходит в интерфейс напрямую.
			name: "nil-able pointer passed to interface parameter",
			wiring: `package app

func (f *Factory) enabled() bool { return f.mailer != nil }

func (f *Factory) build() *Service {
	return NewService(f.mailer)
}
`,
			expectPtr:   "f.mailer",
			expectInMsg: "NewService()",
		},
		{
			// Та же ошибка присваиванием, а не аргументом.
			name: "nil-able pointer assigned to interface variable",
			wiring: `package app

func (f *Factory) enabled() bool { return f.mailer != nil }

func (f *Factory) alerter() Alerter {
	var a Alerter
	a = f.mailer
	return a
}
`,
			expectPtr: "f.mailer",
		},
		{
			// Та же ошибка объявлением с инициализатором: var a Alerter = f.mailer.
			name: "nil-able pointer in var declaration with interface type",
			wiring: `package app

func (f *Factory) enabled() bool { return f.mailer != nil }

func (f *Factory) alerter() Alerter {
	var a Alerter = f.mailer
	return a
}
`,
			expectPtr: "f.mailer",
		},
		{
			// Правильная нормализация: присваивание под проверкой указателя.
			name: "assignment guarded by a nil check",
			wiring: `package app

func (f *Factory) enabled() bool { return f.mailer != nil }

func (f *Factory) build() *Service {
	var a Alerter
	if f.mailer != nil {
		a = f.mailer
	}
	return NewService(a)
}
`,
		},
		{
			// Указатель нигде с nil не сравнивают — считать его пустым нет оснований.
			name: "pointer never compared with nil",
			wiring: `package app

func buildFrom(m *Mailer) *Service {
	return NewService(m)
}
`,
		},
		{
			// Явный untyped nil — получатель увидит именно nil, проверка сработает.
			name: "explicit untyped nil is fine",
			wiring: `package app

func (f *Factory) enabled() bool { return f.mailer != nil }

func (f *Factory) build() *Service {
	return NewService(nil)
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
				assert.Empty(t, violations, "ожидалось отсутствие находок: %s", tt.name)
				return
			}
			require.Len(t, violations, 1, "ожидалась одна находка: %s", tt.name)
			assert.Equal(t, "typed_nil_into_interface", violations[0].Context["pattern"])
			assert.Equal(t, tt.expectPtr, violations[0].Context["pointer"])
			if tt.expectInMsg != "" {
				assert.Contains(t, violations[0].Message, tt.expectInMsg)
			}
		})
	}
}

// Пустой интерфейс ничего не обещает: типизированный nil в any безобиден, потому что
// метод на нём никто не зовёт.
func TestTypedNilIntoInterfaceRule_EmptyInterfaceIgnored(t *testing.T) {
	project := optDepProject(t, map[string]string{
		"service.go": typedNilBase,
		"wiring.go": `package app

func (f *Factory) enabled() bool { return f.mailer != nil }

func (f *Factory) log() {
	record(f.mailer)
}

func record(v any) { _ = v }
`,
	})
	violations, err := NewTypedNilIntoInterfaceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestTypedNilIntoInterfaceRule_NilProject(t *testing.T) {
	_, err := NewTypedNilIntoInterfaceRule().AnalyzeGoProject(nil)
	require.Error(t, err)
}

// Проверка на nil в Cleanup/Close — защита разрушения частично собранного объекта, а не
// признак того, что зависимость бывает пустой в работе. Иначе правило ругается на любой
// хелпер с аккуратным teardown.
func TestTypedNilIntoInterfaceRule_TeardownCheckIsNotEvidence(t *testing.T) {
	// Единственная проверка на nil стоит в teardown — доказательством она не считается.
	project := optDepProject(t, map[string]string{
		"service.go": typedNilBase,
		"wiring.go": `package app

func (f *Factory) Cleanup() {
	if f.mailer != nil {
		f.mailer = nil
	}
}

func (f *Factory) build() *Service {
	return NewService(f.mailer)
}
`,
	})
	violations, err := NewTypedNilIntoInterfaceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

// A nil check that rejects the pointer with an error or a panic says nil is not
// allowed there, not that the pointer is sometimes empty: a constructor that
// validates its dependencies before wiring them gives no evidence.
func TestTypedNilIntoInterfaceRule_RejectingCheckIsNotEvidence(t *testing.T) {
	project := optDepProject(t, map[string]string{
		"service.go": typedNilBase,
		"wiring.go": `package app

import "errors"

type deps struct{ mailer *Mailer }

func validate(d *deps) error {
	if d.mailer == nil {
		return errors.New("mailer is required")
	}
	return nil
}

func mustHave(d *deps) {
	if d.mailer == nil {
		panic("mailer is required")
	}
}

func build(d *deps) (*Service, error) {
	if err := validate(d); err != nil {
		return nil, err
	}
	mustHave(d)
	return &Service{alerter: d.mailer}, nil
}
`,
	})
	violations, err := NewTypedNilIntoInterfaceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

// A pointer that is sometimes empty is still reported when the check that
// shows it tolerates the empty case.
func TestTypedNilIntoInterfaceRule_TolerantCheckBesideRejectingOne(t *testing.T) {
	project := optDepProject(t, map[string]string{
		"service.go": typedNilBase,
		"wiring.go": `package app

import "errors"

type deps struct{ mailer *Mailer }

func validate(d *deps) error {
	if d.mailer == nil {
		return errors.New("mailer is required")
	}
	return nil
}

func (d *deps) optional() bool {
	if d.mailer == nil {
		return false
	}
	return true
}

func build(d *deps) *Service {
	return &Service{alerter: d.mailer}
}
`,
	})
	violations, err := NewTypedNilIntoInterfaceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
}

// A typed nil fools only a nil check on the interface. When nothing in the
// project ever compares a value of that interface type with nil, the holder
// calls it as it would call the pointer, and the interface changes nothing.
func TestTypedNilIntoInterfaceRule_InterfaceNeverNilChecked(t *testing.T) {
	project := optDepProject(t, map[string]string{
		"cache.go": `package app

import "context"

type itemLister interface {
	List(ctx context.Context, owner string) ([]string, error)
}

type itemCache struct {
	lister itemLister
	loaded map[string][]string
}

func newItemCache(lister itemLister) *itemCache {
	return &itemCache{lister: lister, loaded: map[string][]string{}}
}

func (c *itemCache) positions(ctx context.Context, owner string) ([]string, error) {
	return c.lister.List(ctx, owner)
}

type ItemService struct{ owners []string }

func (s *ItemService) List(ctx context.Context, owner string) ([]string, error) {
	return s.owners, nil
}

type Linker struct{ items *ItemService }

func (l *Linker) Link(ctx context.Context, owner string) error {
	cache := newItemCache(l.items)
	if l.items == nil {
		return nil
	}
	_, err := cache.positions(ctx, owner)
	return err
}
`,
	})
	violations, err := NewTypedNilIntoInterfaceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}
