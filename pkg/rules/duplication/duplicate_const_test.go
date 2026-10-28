package duplication

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// Repro from a real project: a threshold moved into a lower package, and the
// upper one kept its own copy under the same name — a change of one leaves
// the other measuring by the old radius.
func TestDuplicateConstAcrossPackages(t *testing.T) {
	files := map[string]string{
		"plan/threat.go": `package plan

import "example.com/rulestest/plan/situation"

const (
	foeNearBaseR = 15
	FoeLeavingR  = 24
)

func near(d float64) bool { return d <= foeNearBaseR || d <= FoeLeavingR || situation.Near(d) }
`,
		"plan/situation/situation.go": `package situation

const foeNearBaseR = 15

// Near reports a foe near a base.
func Near(d float64) bool { return d <= foeNearBaseR }
`,
	}
	assert.Equal(t, []string{"plan/situation/situation.go:3", "plan/threat.go:6"}, rulestest.ProjectRulePlaces(t, NewDuplicateConstAcrossPackagesRule(), files))
}

// Packages that do not import one another give one role name a setting of
// their own: two services batching their own events.
func TestDuplicateConstAcceptsUnrelatedPackages(t *testing.T) {
	files := map[string]string{
		"events/events.go": `package events

const maxBatchSize = 100

func full(n int) bool { return n >= maxBatchSize }
`,
		"metrics/metrics.go": `package metrics

const maxBatchSize = 100

func full(n int) bool { return n >= maxBatchSize }
`,
	}
	assert.Empty(t, rulestest.ProjectRulePlaces(t, NewDuplicateConstAcrossPackagesRule(), files))
}

// A copy written as a literal with a comment naming the constant it copies:
// the comment says where the value lives, the literal drifts from it. Also
// inside a function.
func TestDuplicateConstReportsLiteralNamingItsSource(t *testing.T) {
	files := map[string]string{
		"plan/units.go": `package plan

// LocalR is the radius of a local fight.
const LocalR = 18

func Local(d float64) bool { return d < LocalR }
`,
		"plan/situation/situation.go": `package situation

func local(d float64) bool {
	const localR = 18.0 // plan.LocalR
	return d < localR
}
`,
	}
	assert.Equal(t, []string{"plan/situation/situation.go:4"}, rulestest.ProjectRulePlaces(t, NewDuplicateConstAcrossPackagesRule(), files))
}

// Different values, one-word names, iota enumerations and a comment naming a
// constant with another value are not copies.
func TestDuplicateConstAcceptsDistinctConstants(t *testing.T) {
	files := map[string]string{
		"a/a.go": `package a

const (
	maxRetries = 3
	limit      = 10
)

const (
	stateIdle = iota
	stateBusy
)

// LocalR is the radius of a local fight.
const LocalR = 18

func use() int { return maxRetries + limit + stateIdle + stateBusy + LocalR }
`,
		"b/b.go": `package b

const (
	maxRetries = 5
	limit      = 10
)

const (
	stateIdle = iota
	stateBusy
)

const wideR = 24 // twice a.LocalR rounded up

func use() int { return maxRetries + limit + stateIdle + stateBusy + wideR }
`,
	}
	assert.Empty(t, rulestest.ProjectRulePlaces(t, NewDuplicateConstAcrossPackagesRule(), files))
}

// A constant defined through the one it names shares it already, and a
// comment naming an alias of the constant itself points back at it.
func TestDuplicateConstAcceptsConstantDefinedThroughItsSource(t *testing.T) {
	files := map[string]string{
		"frame/frame.go": `package frame

// LocalR is the radius of a local fight (plan.LocalR).
const LocalR = 18
`,
		"plan/units.go": `package plan

import "example.com/rulestest/frame"

const localR = frame.LocalR // frame.LocalR

// LocalR is the radius of a local fight.
const LocalR = frame.LocalR

func local(d float64) bool { return d < localR }
`,
	}
	assert.Empty(t, rulestest.ProjectRulePlaces(t, NewDuplicateConstAcrossPackagesRule(), files))
}
