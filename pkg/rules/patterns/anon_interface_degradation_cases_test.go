package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// The optional-interface idiom: call the capability when the value has it,
// otherwise answer with the zero value that means "nothing to do". A made-up
// non-zero answer is still a degradation.
func TestAnonInterfaceDegradation_OptionalInterfaceIdiom(t *testing.T) {
	const source = `package opt

import "io"

func Flush(w io.Writer) error {
	if f, ok := w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

func Cause(err error) error {
	if u, ok := err.(interface{ Unwrap() error }); ok {
		return u.Unwrap()
	}
	return nil
}

func IsTimeout(err error) bool {
	if t, ok := err.(interface{ Timeout() bool }); ok {
		return t.Timeout()
	}
	return false
}

func Price(v any) int {
	if p, ok := v.(interface{ Price() int }); ok {
		return p.Price()
	}
	return 100
}
`
	ctx := rulestest.GoFile(t, "opt/o.go", source)
	assert.Equal(t, []int{30}, violationLines(NewAnonInterfaceDegradationRule().AnalyzeFile(ctx)))
}
