package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func TestDeepEqualShallowCopyRepros(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "pointer map", body: `func f(s *state) bool { before := *s; s.marks["x"] = true; return reflect.DeepEqual(before, *s) }`, want: true},
		{name: "slice field", body: `func f(s list) bool { before := s; s.values[0]++; return reflect.DeepEqual(before, s) }`, want: true},
		{name: "nested map field", body: `func f(s nested) bool { before := s; s.inner.marks["x"] = true; return reflect.DeepEqual(before, s) }`, want: true},
		{name: "reverse arguments", body: `func f(s *state) bool { before := *s; s.marks["x"] = true; return reflect.DeepEqual(*s, before) }`, want: true},
		{name: "struct field copy", body: `func f(h holder) bool { before := h.state; h.state.marks["x"] = true; return reflect.DeepEqual(before, h.state) }`, want: true},
		{name: "dereferenced struct field", body: `func f(w *wrapper) bool { before := *w.inner; w.inner.marks["x"] = true; return reflect.DeepEqual(before, *w.inner) }`, want: true},
		{name: "array of maps", body: `func f(a arrayHolder) bool { before := a; a.marks[0]["x"] = true; return reflect.DeepEqual(before, a) }`, want: true},
		{name: "shadowed local", body: `func f(s *state) bool { before := *s; { before := 1; _ = before }; s.marks["x"] = true; return reflect.DeepEqual(before, *s) }`, want: true},
		{name: "var declaration", body: `func f(s *state) bool { var before = *s; s.marks["x"] = true; return reflect.DeepEqual(before, *s) }`, want: true},
		{name: "embedded", body: `func f(s embedded) bool { before := s; s.marks["x"] = true; return reflect.DeepEqual(before, s) }`, want: true},
		{name: "alias", body: `func f(s alias) bool { before := s; s.marks["x"] = true; return reflect.DeepEqual(before, s) }`, want: true},
		{name: "named type", body: `func f(s named) bool { before := s; s.marks["x"] = true; return reflect.DeepEqual(before, s) }`, want: true},
		{name: "generic struct", body: `func f(s generic[int]) bool { before := s; s.values["x"] = 1; return reflect.DeepEqual(before, s) }`, want: true},
		{name: "clone call", body: `func f(s state) bool { before := s.Clone(); s.marks["x"] = true; return reflect.DeepEqual(before, s) }`},
		{name: "arbitrary call is not a copy", body: `func f(s state) bool { before := makeState(s); s.marks["x"] = true; return reflect.DeepEqual(before, s) }`},
		{name: "plain struct", body: `func f(s plain) bool { before := s; s.value++; return reflect.DeepEqual(before, s) }`},
		{name: "different original", body: `func f(s, other state) bool { before := s; s.marks["x"] = true; return reflect.DeepEqual(before, other) }`},
		{name: "copy reassigned", body: `func f(s state) bool { before := s; s.marks["x"] = true; before = state{}; return reflect.DeepEqual(before, s) }`},
		{name: "copy field replaced", body: `func f(s *state) bool { before := *s; s.marks["x"] = true; before.marks = cloneMarks(s.marks); return reflect.DeepEqual(before, *s) }`},
		{name: "original pointer replaced", body: `func f(s *state, other state) bool { before := *s; s.marks["x"] = true; *s = other; return reflect.DeepEqual(before, *s) }`},
		{name: "original value replaced", body: `func f(s, other state) bool { before := s; s.marks["x"] = true; s = other; return reflect.DeepEqual(before, s) }`},
		{name: "original field replaced", body: `func f(s *state) bool { before := *s; s.marks["x"] = true; s.marks = cloneMarks(s.marks); return reflect.DeepEqual(before, *s) }`},
		{name: "scalar increment is visible", body: `func f(s *mixedState) bool { before := *s; s.value++; return reflect.DeepEqual(before, *s) }`},
		{name: "time replacement is visible", body: `func f(s timedState) bool { before := s; s.value = time.Now(); return reflect.DeepEqual(before, s) }`},
		{name: "deferred pointer method runs after compare", body: `func f(s *state) bool { before := *s; defer s.later(); return reflect.DeepEqual(before, *s) }`},
		{name: "deferred value method runs after compare", body: `func f(s *mixedState) bool { before := *s; defer s.bump(); return reflect.DeepEqual(before, *s) }`},
		{name: "deferred field call runs after compare", body: `func f(s *state) bool { before := *s; defer takeMap(s.marks); return reflect.DeepEqual(before, *s) }`},
		{name: "parent reassignment invalidates nested copy", body: `func f(s *wrapper, other wrapper) bool { before := *s.inner; s.inner.marks["old"] = true; s = &other; s.inner.marks["new"] = true; return reflect.DeepEqual(before, *s.inner) }`},
		{name: "switch cases are exclusive", body: `func f(s *state, which int) bool { var before state; switch which { case 1: before = *s }; s.marks["x"] = true; switch which { case 2: return reflect.DeepEqual(before, *s) }; return false }`},
		{name: "switch default excludes tagged case", body: `func f(s *state, which int) bool { var before state; switch which { case 1: default: before = *s }; s.marks["x"] = true; switch which { case 1: return reflect.DeepEqual(before, *s) }; return false }`},
		{name: "aliased map field", body: `func f(s *state) bool { before := *s; m := s.marks; m["x"] = true; return reflect.DeepEqual(before, *s) }`, want: true},
		{name: "value method on copy mutates shared map", body: `func f(s *state) bool { before := *s; before.setMark("x"); return reflect.DeepEqual(before, *s) }`, want: true},
		{name: "copy from array element", body: `func f(a arrayHolder) bool { before := a.states[0]; a.states[0].marks["x"] = true; return reflect.DeepEqual(before, a.states[0]) }`, want: true},
		{name: "value method on non-reference field is not shared access", body: `func f(s *parentWithChild) bool { before := *s; s.child.bump(); return reflect.DeepEqual(before, *s) }`},
		{name: "value method on reference struct may access shared map", body: `func f(s *mixedState) bool { before := *s; s.bump(); return reflect.DeepEqual(before, *s) }`, want: true},
		{name: "mutually exclusive branches", body: `func f(s *state, cond bool) bool { var before state; if cond { before = *s }; s.marks["x"] = true; if !cond { return reflect.DeepEqual(before, *s) }; return false }`},
		{name: "time value field", body: `func f(s withTime) bool { before := s; s.value = time.Time{}; return reflect.DeepEqual(before, s) }`},
		{name: "tagless switch conditions are exclusive", body: `func f(s *state, cond bool) bool { var before state; switch { case cond: before = *s }; s.marks["x"] = true; switch { case !cond: return reflect.DeepEqual(before, *s) }; return false }`},
		{name: "external unexported references do not imply value method access", body: `func f(s *timeState) bool { before := *s; s.N = 1; s.touch(); return !reflect.DeepEqual(before, *s) }`},
		{name: "time method on field is read only", body: `func f(s *timeState) bool { before := *s; s.N = 1; _ = s.T.String(); return !reflect.DeepEqual(before, *s) }`},
		{name: "different array element comparison", body: `func f(a arrayHolder) bool { before := a.states[0]; a.states[1].marks["x"] = true; return !reflect.DeepEqual(before, a.states[1]) }`},
		{name: "different array element mutation", body: `func f(a arrayHolder) bool { before := a.states[0]; a.states[1].marks["x"] = true; return !reflect.DeepEqual(before, a.states[0]) }`},
		{name: "different map key mutation", body: `func f(m map[string]state, a, b string) bool { before := m[a]; m[b].marks["x"] = true; return !reflect.DeepEqual(before, m[a]) }`},
		{name: "call receives copy reference field", body: `func f(s *state) bool { before := *s; writeMap(before.marks); return !reflect.DeepEqual(before, *s) }`, want: true},
		{name: "call receives copy value", body: `func f(s *state) bool { before := *s; writeStruct(before); return !reflect.DeepEqual(before, *s) }`, want: true},
		{name: "alias before copy mutation", body: `func f(s *state) bool { m := s.marks; before := *s; m["x"] = true; return !reflect.DeepEqual(before, *s) }`, want: true},
		{name: "delete through alias", body: `func f(s *state) bool { before := *s; m := s.marks; delete(m, "x"); return !reflect.DeepEqual(before, *s) }`, want: true},
		{name: "clear through alias", body: `func f(s *state) bool { before := *s; m := s.marks; clear(m); return !reflect.DeepEqual(before, *s) }`, want: true},
		{name: "array index reassigned", body: `func f(a arrayHolder, i, j int) bool { before := a.states[i]; i = j; a.states[i].marks["x"] = true; return !reflect.DeepEqual(before, a.states[i]) }`},
		{name: "map key reassigned", body: `func f(m map[string]state, a, b string) bool { before := m[a]; a = b; m[a].marks["x"] = true; return !reflect.DeepEqual(before, m[a]) }`},
		{name: "array index incremented", body: `func f(a arrayHolder, i int) bool { before := a.states[i]; i++; a.states[i].marks["x"] = true; return !reflect.DeepEqual(before, a.states[i]) }`},
		{name: "array index address escapes", body: `func f(a arrayHolder, i int) bool { before := a.states[i]; mutateIndex(&i); a.states[i].marks["x"] = true; return !reflect.DeepEqual(before, a.states[i]) }`},
		{name: "method mutates original", body: `func f(s *state) bool { before := *s; s.mark("x"); return reflect.DeepEqual(before, *s) }`, want: true},
		{name: "call receives original", body: `func f(s *state) bool { before := *s; apply(s); return reflect.DeepEqual(before, *s) }`, want: true},
		{name: "call without original", body: `func f(s *state) bool { before := *s; log.Print("x"); return reflect.DeepEqual(before, *s) }`},
		{name: "unrelated function call", body: `func f(s *state) bool { before := *s; unrelated(); return reflect.DeepEqual(before, *s) }`},
		{name: "nil argument is unrelated", body: `func f(s *state) bool { before := *s; acceptAny(nil); return reflect.DeepEqual(before, *s) }`},
		{name: "closure captures original", body: `func f(s *state) bool { before := *s; func() { s.mark("x") }(); return reflect.DeepEqual(before, *s) }`, want: true},
		{name: "named closure captures original", body: `func f(s *state) bool { before := *s; mutate := func() { s.mark("x") }; mutate(); return reflect.DeepEqual(before, *s) }`, want: true},
		{name: "unused closure does not mutate", body: `func f(s *state) bool { before := *s; mutate := func() { s.mark("x") }; _ = mutate; return reflect.DeepEqual(before, *s) }`},
		{name: "closure", body: `func f(s *state) func() bool { before := *s; s.marks["x"] = true; return func() bool { return reflect.DeepEqual(before, *s) } }`, want: true},
		{name: "deferred closure", body: `func f(s *state) { before := *s; s.marks["x"] = true; defer func() { _ = reflect.DeepEqual(before, *s) }() }`, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := `package sample
import ("log"; "maps"; "reflect"; "time")
type state struct { marks map[string]bool }
var _ = log.Print
type list struct { values []int }
type inner struct { marks map[string]bool }
type nested struct { inner inner }
type holder struct { state state }
type arrayHolder struct { marks [2]map[string]bool; states [2]state }
type embedded struct { state }
type alias = state
type named state
type generic[T any] struct { values map[string]T }
type plain struct { value int }
type withTime struct { value time.Time }
type mixedState struct { value int; marks map[string]bool }
type timedState struct { value time.Time; marks map[string]bool }
type timeState struct { N int; T time.Time }
type child struct { value int }
type parentWithChild struct { child child; marks map[string]bool }
type wrapper struct { inner *state }
func (s state) Clone() state { return s }
func (s *state) mark(k string) { s.marks[k] = true }
func (s state) setMark(k string) { s.marks[k] = true }
func (s *state) later() {}
func (s plain) bump() {}
func (s mixedState) bump() { _ = s.value }
func (timeState) touch() {}
func (s child) bump() { _ = s.value }
func makeState(s state) state { return s }
func apply(s *state) { s.marks["x"] = true }
func unrelated() {}
func acceptAny(any) {}
func takeMap(map[string]bool) {}
func writeMap(m map[string]bool) { m["x"] = true }
func writeStruct(s state) { s.marks["x"] = true }
func mutateIndex(i *int) { *i++ }
func cloneMarks(m map[string]bool) map[string]bool { return maps.Clone(m) }
` + tc.body + "\n"
			violations := rulestest.RunRuleOnFiles(t, NewDeepEqualShallowCopyRule(), map[string]string{"state.go": source})
			if tc.want {
				require.Len(t, violations, 1, tc.name+"\n"+source)
				require.Equal(t, "deep-equal-shallow-copy", violations[0].Rule)
			} else {
				require.Empty(t, violations, tc.name)
			}
		})
	}
}
