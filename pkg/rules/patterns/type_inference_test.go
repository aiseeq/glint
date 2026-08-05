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
