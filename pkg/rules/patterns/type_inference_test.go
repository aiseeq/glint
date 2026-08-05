package patterns

import (
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypeInferrer_GetType(t *testing.T) {
	code := `package main
import "time"

var (
	items []string
	m map[string]int
	ch chan bool
	t time.Time
	err error
)
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", code, 0)
	require.NoError(t, err)

	inferrer := NewTypeInferrer(file)

	// Check items
	info, ok := inferrer.GetType("items")
	assert.True(t, ok)
	assert.True(t, info.IsSlice)
	assert.Equal(t, "[]string", info.TypeName)

	// Check map
	info, ok = inferrer.GetType("m")
	assert.True(t, ok)
	assert.True(t, info.IsMap)

	// Check channel
	info, ok = inferrer.GetType("ch")
	assert.True(t, ok)
	assert.True(t, info.IsChan)

	// Check time
	info, ok = inferrer.GetType("t")
	assert.True(t, ok)
	assert.True(t, info.IsTime)
	assert.Equal(t, "time.Time", info.TypeName)

	// Check error
	info, ok = inferrer.GetType("err")
	assert.True(t, ok)
	assert.True(t, info.IsError)

	// Unknown variable
	_, ok = inferrer.GetType("unknown")
	assert.False(t, ok)
}

// IsAny follows the GetType contract: a name the file binds to two different
// types is ambiguous and must not report any type — including any/interface{}.
func TestTypeInferrerIsAnyRespectsAmbiguousNames(t *testing.T) {
	code := `package main

func accept(data any) {}

func slice(data []string) {}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", code, 0)
	require.NoError(t, err)

	inferrer := NewTypeInferrer(file)

	assert.True(t, inferrer.IsAmbiguous("data"))
	assert.False(t, inferrer.IsAny("data"),
		"ambiguous name must not be reported as any even when any was seen first")
}

func TestTypeInferrerIsAnyDetectsUnambiguousAny(t *testing.T) {
	code := `package main

func accept(data any) {}

func raw(payload interface{}) {}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", code, 0)
	require.NoError(t, err)

	inferrer := NewTypeInferrer(file)

	assert.True(t, inferrer.IsAny("data"))
	assert.True(t, inferrer.IsAny("payload"))
	assert.False(t, inferrer.IsAny("unknown"))
}
