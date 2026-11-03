package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Lazy initialization guards the field the same way a check does: the field
// is set inside the nil branch from a local proven non-nil (its error checked,
// later uses of the error variable aside; its own nil check) or by a method of
// the receiver that sets it. A same-package helper that always panics ends the
// branch like panic does. A local whose address escapes before the field is set
// is not known non-nil.
func TestFieldNilCheckInconsistentLazyInitAndOwnTerminators(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"service.go": `package example

import ("errors"; "fmt"; "log/slog")

type Dep struct{}
func (*Dep) Run() int { return 1 }
func open() (*Dep, error) { return &Dep{}, nil }
func other() (*Dep, error) { return nil, errors.New("x") }
func load() *Dep { return nil }
func mayFail() error { return nil }
func reset(d **Dep) { *d = nil }
type PanicHelper struct { dep *Dep }
func (s *PanicHelper) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *PanicHelper) Plain() int { return s.dep.Run() }
func (s *PanicHelper) Form() int {
	if s.dep == nil { s.fail() }
	return s.dep.Run()
}
func (s *PanicHelper) fail() { panic("dep unavailable") }
type ViaPointer struct { dep *Dep }
func (s *ViaPointer) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *ViaPointer) Plain() int { return s.dep.Run() }
func (s *ViaPointer) Form() int {
	d, err := open()
	if err != nil { return 0 }
	reset(&d)
	s.dep = d
	return s.dep.Run()
}
type LazyErrReused struct { dep *Dep }
func (s *LazyErrReused) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *LazyErrReused) Plain() int { return s.dep.Run() }
func (s *LazyErrReused) Form() int {
	if s.dep == nil {
		d, err := open()
		if err != nil { return 0 }
		err = mayFail()
		if err != nil { return 0 }
		s.dep = d
	}
	return s.dep.Run()
}
type LazyErrWrapped struct { dep *Dep }
func (s *LazyErrWrapped) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *LazyErrWrapped) Plain() int { return s.dep.Run() }
func (s *LazyErrWrapped) Form() int {
	if s.dep == nil {
		d, err := open()
		if err != nil {
			err = fmt.Errorf("open: %w", err)
			slog.Warn(err.Error())
			return 0
		}
		s.dep = d
	}
	return s.dep.Run()
}
type LazyErrRedeclared struct { dep *Dep }
func (s *LazyErrRedeclared) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *LazyErrRedeclared) Plain() int { return s.dep.Run() }
func (s *LazyErrRedeclared) Form() int {
	if s.dep == nil {
		d, err := open()
		if err != nil { return 0 }
		_, err = other()
		if err != nil { return 0 }
		s.dep = d
	}
	return s.dep.Run()
}
type LazyLocalNilCheck struct { dep *Dep }
func (s *LazyLocalNilCheck) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *LazyLocalNilCheck) Plain() int { return s.dep.Run() }
func (s *LazyLocalNilCheck) Form() int {
	if s.dep == nil {
		d := load()
		if d == nil { return 0 }
		s.dep = d
	}
	return s.dep.Run()
}
type LazySetupMethod struct { dep *Dep }
func (s *LazySetupMethod) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *LazySetupMethod) Plain() int { return s.dep.Run() }
func (s *LazySetupMethod) Form() int {
	if s.dep == nil {
		if err := s.setup(); err != nil { return 0 }
	}
	return s.dep.Run()
}
func (s *LazySetupMethod) setup() error {
	d, err := open()
	if err != nil { return err }
	s.dep = d
	return nil
}
type LazyEnsure struct { dep *Dep }
func (s *LazyEnsure) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *LazyEnsure) Plain() int { return s.dep.Run() }
func (s *LazyEnsure) Form() int {
	if s.dep == nil {
		if err := s.ensure(); err != nil { return 0 }
	}
	return s.dep.Run()
}
func (s *LazyEnsure) ensure() error {
	if s.dep != nil { return nil }
	d, err := open()
	if err != nil { return err }
	s.dep = d
	return nil
}
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"service.go:105", "service.go:123", "service.go:17", "service.go:28", "service.go:34", "service.go:41", "service.go:57", "service.go:75", "service.go:91"}, patterntest.FoundLines(violations))
}
