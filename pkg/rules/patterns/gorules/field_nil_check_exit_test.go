package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A branch that ends the program or the goroutine (panic, log.Fatal,
// os.Exit) guards what follows as a return does, and so does a tagless switch
// whose nil case returns. A local result assigned to the field counts as
// non-nil only when nothing reassigns it, or the error checked for it, between
// the call and the assignment.
func TestFieldNilCheckInconsistentExitsAndReassignedLocals(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"service.go": `package example

import ("errors"; "log"; "log/slog"; "os")

type Dep struct{}
func (*Dep) Run() int { return 1 }
func open() (*Dep, error) { return &Dep{}, nil }
func other() (*Dep, error) { return nil, errors.New("x") }
type Panics struct { dep *Dep }
func (s *Panics) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *Panics) Plain() int { return s.dep.Run() }
func (s *Panics) Form() int {
	if s.dep == nil { panic("dep") }
	return s.dep.Run()
}
type Fatal struct { dep *Dep }
func (s *Fatal) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *Fatal) Plain() int { return s.dep.Run() }
func (s *Fatal) Form() int {
	if s.dep == nil { log.Fatal("dep") }
	return s.dep.Run()
}
type Exits struct { dep *Dep }
func (s *Exits) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *Exits) Plain() int { return s.dep.Run() }
func (s *Exits) Form() int {
	if s.dep == nil { os.Exit(1) }
	return s.dep.Run()
}
type Switch struct { dep *Dep }
func (s *Switch) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *Switch) Plain() int { return s.dep.Run() }
func (s *Switch) Form() int {
	switch {
	case s.dep == nil:
		return 0
	}
	return s.dep.Run()
}
type SwitchDefault struct { dep *Dep }
func (s *SwitchDefault) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *SwitchDefault) Plain() int { return s.dep.Run() }
func (s *SwitchDefault) Form() int {
	switch {
	case s.dep == nil:
		return 0
	default:
	}
	return s.dep.Run()
}
type Reset struct { dep *Dep }
func (s *Reset) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *Reset) Plain() int { return s.dep.Run() }
func (s *Reset) Form() int {
	d, err := open()
	if err != nil { return 0 }
	d = nil
	s.dep = d
	return s.dep.Run()
}
type OtherError struct { dep *Dep }
func (s *OtherError) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *OtherError) Plain() int { return s.dep.Run() }
func (s *OtherError) Form() int {
	d, err := open()
	_, err = other()
	if err != nil { return 0 }
	s.dep = d
	return s.dep.Run()
}
type Opened struct { dep *Dep }
func (s *Opened) Optional() int {
	if s.dep == nil { slog.Warn("dep unavailable"); return 0 }
	return s.dep.Run()
}
func (s *Opened) Plain() int { return s.dep.Run() }
func (s *Opened) Form() int {
	d, err := open()
	if err != nil { return 0 }
	s.dep = d
	return s.dep.Run()
}
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"service.go:14", "service.go:24", "service.go:34", "service.go:44", "service.go:57", "service.go:71", "service.go:77", "service.go:84", "service.go:90", "service.go:97"}, patterntest.FoundLines(violations))
}

// The prior-case heuristic: a case reached only when an earlier case that
// returns on a nil field was false. The field is optional, so a closure that
// dereferences it with no check is still found.
func TestFieldNilCheckInconsistentShortCircuitAndClosure(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"service.go": `package example

type Dependency struct{}
func (*Dependency) Ready() bool { return true }
type Service struct { dep *Dependency }
func (s *Service) optional() { if s.dep != nil { s.dep.Ready() } }
func (s *Service) ready() bool { return s.dep != nil && s.dep.Ready() }
func (s *Service) readyAssign() bool { ready := s.dep != nil && s.dep.Ready(); return ready }
func (s *Service) readySwitch() bool {
	switch {
	case s.dep != nil:
		return s.dep.Ready()
	default:
		return false
	}
}
func (s *Service) readyAfterPriorCase(stalled bool) bool {
	switch {
	case stalled && s.dep == nil:
		return false
	case stalled:
		return s.dep.Ready()
	default:
		return false
	}
}
func (s *Service) later() { consume(func() { s.dep.Ready() }) }
func consume(func()) {}
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"service.go:27"}, patterntest.FoundLines(violations))
}
