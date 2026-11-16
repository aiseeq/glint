package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func TestVariadicAsOptionalParam(t *testing.T) {
	files := map[string]string{
		"sample/api.go": `package sample

type Option func()
type Handler func(string, ...string) string
type Prefixer interface { Prefix(...string) string }

func lookup(values ...*int) { // want variadic-as-optional-param
	if len(values) > 0 { _ = values[0] }
}

func early(values ...int) int { // want variadic-as-optional-param
	if 0 == len(values) { return 0 }
	return values[0]
}

func captured(values ...int) func() int { // want variadic-as-optional-param
	return func() int { if len(values) != 0 { return values[0] }; return 0 }
}

func entire(values ...int) { for _, value := range values { _ = value } }
func spread(values ...int) { consume(values...) }
func length(values ...int) int { return len(values) }
func later(values ...int) int { if len(values) > 1 { return values[1] }; return 0 }
func slice(values ...int) []int { return values[1:] }
func stored(values ...int) []int { result := values; return result }
func unused(_ ...int) {}
func badLen(values ...int) { if len(values) > 0 { _ = len(values) } }
func badCmp(values ...int) { if len(values) > 1 { _ = values[0] } }

func consume(...int) {}

type namedHandler func(string, ...string) string
var _ namedHandler = greet
func greet(name string, extra ...string) string { if len(extra) > 0 { return extra[0] }; return name }

type PrefixerImpl struct{}
func (PrefixerImpl) Prefix(prefix ...string) string { if len(prefix) > 0 { return prefix[0] }; return "" }
var _ Prefixer = PrefixerImpl{}
`,
	}
	found := rulestest.ProjectRulePlaces(t, NewVariadicAsOptionalParamRule(), files)
	require.ElementsMatch(t, []string{
		"sample/api.go:7", "sample/api.go:11", "sample/api.go:16",
	}, found)
}
