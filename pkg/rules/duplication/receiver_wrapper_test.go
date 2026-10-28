package duplication

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// Repro from a real project: a method that only passes a field of its
// receiver to a function of the package, while the package calls that
// function with the same field directly — two ways of one lookup.
func TestReceiverWrapperDuplicatesCall(t *testing.T) {
	files := map[string]string{
		"lines/line.go": `package lines

type Part struct{ Name string }

type Line struct{ Parts []*Part }

func partNamed(parts []*Part, name string) *Part {
	for _, p := range parts {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func (l *Line) arenaNamedPart(name string) *Part { return partNamed(l.Parts, name) }

func (l *Line) arena() *Part { return l.arenaNamedPart("arena") }
`,
		"lines/defense.go": `package lines

func defense(l *Line) *Part { return partNamed(l.Parts, "defense") }
`,
	}
	assert.Equal(t, []string{"lines/line.go:16"}, rulestest.ProjectRulePlaces(t, NewReceiverWrapperDuplicatesCallRule(), files))
}

// The wrapper is the only way the package takes the field to the function:
// other calls pass another type's field or a slice of their own, and a
// method that adds a value of its own (a literal, a method value) is not a
// wrapper; an exported method is API.
func TestReceiverWrapperAcceptsSingleWay(t *testing.T) {
	files := map[string]string{
		"lines/line.go": `package lines

type Part struct{ Name string }

type Line struct{ Parts []*Part }

type Group struct{ Parts []*Part }

func partNamed(parts []*Part, name string) *Part {
	for _, p := range parts {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func (l *Line) namedPart(name string) *Part { return partNamed(l.Parts, name) }

func (l *Line) arenaPart() *Part { return l.namedPart("arena") }

func (l *Line) live() int { return l.Count(l.alive) }

func (l *Line) alive(*Part) bool { return true }

func (l *Line) any() int { return countWhere(l.Parts, l.alive) }

func (g *Group) lead() *Part { return partNamed(g.Parts, "lead") }

func pick(parts []*Part) *Part { return partNamed(parts, "x") }

func (l *Line) Count(match func(*Part) bool) int { return countWhere(l.Parts, match) }

func countWhere(parts []*Part, match func(*Part) bool) int {
	n := 0
	for _, p := range parts {
		if match(p) {
			n++
		}
	}
	return n
}
`,
	}
	assert.Empty(t, rulestest.ProjectRulePlaces(t, NewReceiverWrapperDuplicatesCallRule(), files))
}
