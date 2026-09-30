package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The typed search sees every reference and implementation in the project, so
// a name ending in Reader or Service does not make a dead interface alive.
func TestOrphanedInterfaceTypedIgnoresNameSuffix(t *testing.T) {
	violations := orphanedInterfaceProject(t, map[string]string{
		"store/store.go": `package store

type EventReader interface{ ReadEvent() (string, error) }

type PaymentService interface{ Charge(amount int64) error }

type LedgerClient interface{ Post(entry string) error }

type Used interface{ Get() int }

func Read(u Used) int { return u.Get() }
`,
	})
	require.Len(t, violations, 3)
	assert.Contains(t, violations[0].Message, "'EventReader'")
	assert.Contains(t, violations[1].Message, "'PaymentService'")
	assert.Contains(t, violations[2].Message, "'LedgerClient'")
}

// A nolint for another rule on a nearby line is not an exemption.
func TestOrphanedInterfaceNearbyNolintOfOtherRule(t *testing.T) {
	violations := orphanedInterfaceProject(t, map[string]string{
		"store/store.go": `package store

func helper(x int) int { //nolint:unused-param
	return 1
}

type Lonely interface{ Alone() }
`,
	})
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "'Lonely'")
}

// The interface's own doc comment may exempt it, anywhere in the comment.
func TestOrphanedInterfaceDocCommentExemption(t *testing.T) {
	violations := orphanedInterfaceProject(t, map[string]string{
		"store/store.go": `package store

// Plugin is implemented by plugins built outside this module.
// Their loader checks for it by reflection.
//
//nolint:orphaned-interface
type Plugin interface{ Start() error }

// Hook is the contract of external hooks.
// Used by: the deployment scripts.
type Hook interface{ Fire() error }
`,
	})
	assert.Empty(t, violations)
}
