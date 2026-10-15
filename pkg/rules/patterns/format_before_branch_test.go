package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// formatBeforeBranchSource formats a message on every call that only the
// rare branch below uses. The value is not needed when the branch is not
// taken, so the work belongs inside it. A value the condition reads, one
// used on both sides, one whose arguments change before the branch, and one
// the branch would format once per loop iteration are where they should be.
const formatBeforeBranchSource = `package ledger

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Unit struct{ Tag, HP int }

func Charge(a, t *Unit, dmg int) error {
	msg := fmt.Sprintf("charge %d on %d", a.Tag, t.Tag) // want format-before-branch
	if dmg < 0 {
		return fmt.Errorf("%s: damage %d", msg, dmg)
	}
	t.HP -= dmg
	return nil
}

func Trace(parts []string, debug bool, units []Unit) (string, error) {
	line := strings.Join(parts, ",") // want format-before-branch
	raw, err := json.Marshal(units) // want format-before-branch
	switch {
	case debug:
		fmt.Println(line)
	case len(units) > 9:
		return string(raw), err
	}
	key := fmt.Sprint(parts)
	if key != "" {
		fmt.Println(key)
	}
	both := fmt.Sprint(len(parts))
	if debug {
		fmt.Println(both)
	}
	fmt.Println(both)
	before := fmt.Sprintf("%d", units[0].HP)
	units[0].HP++
	if debug {
		fmt.Println(before)
	}
	each := fmt.Sprint(units)
	for range units {
		if debug {
			fmt.Println(each)
		}
	}
	return "", nil
}

type Catalog struct{ Names map[int]string }

// NameOf picks a default and refines it, the idiom of code that runs once;
// in a loop or a hot function the default is formatted for nothing on every
// call the refinement wins.
func NameOf(c *Catalog, typ int) string {
	name := fmt.Sprint(typ)
	if x, ok := c.Names[typ]; ok {
		name = x
	}
	for range c.Names {
		each := fmt.Sprint(typ) // want format-before-branch
		if x, ok := c.Names[typ]; ok {
			each = x
		}
		name += each
	}
	label := fmt.Sprint(typ)
	if len(label) > 3 {
		label = label[:3]
	}
	tag := fmt.Sprint(typ)
	if typ > 0 {
		fmt.Println(tag)
		tag = "positive"
	}
	return name + label + tag
}

//glint:hot
func Check(a *Unit) error {
	what := fmt.Sprintf("unit %d", a.Tag) // want format-before-branch
	if a.HP < 0 {
		return fmt.Errorf("%s is dead", what)
	}
	return nil
}
`

func TestFormatBeforeBranch(t *testing.T) {
	files := map[string]string{"ledger/ledger.go": formatBeforeBranchSource}
	violations, err := NewFormatBeforeBranchRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "format-before-branch"), foundLines(violations))
}
