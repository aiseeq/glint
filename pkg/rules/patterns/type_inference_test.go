package patterns

import (
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypeInferrer_SliceDetection(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		varName  string
		isSlice  bool
	}{
		{
			name: "var declaration with slice type",
			code: `package main
var items []string
`,
			varName: "items",
			isSlice: true,
		},
		{
			name: "short declaration with composite literal",
			code: `package main
func f() {
	items := []string{"a", "b"}
}
`,
			varName: "items",
			isSlice: true,
		},
		{
			name: "short declaration with make",
			code: `package main
func f() {
	items := make([]int, 10)
}
`,
			varName: "items",
			isSlice: true,
		},
		{
			name: "function parameter",
			code: `package main
func process(items []string) {}
`,
			varName: "items",
			isSlice: true,
		},
		{
			name: "var declaration with non-slice type",
			code: `package main
var count int
`,
			varName: "count",
			isSlice: false,
		},
		{
			name: "pointer type",
			code: `package main
var ptr *int
`,
			varName: "ptr",
			isSlice: false,
		},
		{
			name: "map type",
			code: `package main
var m map[string]int
`,
			varName: "m",
			isSlice: false,
		},
		{
			name: "append result",
			code: `package main
func f() {
	base := []int{1}
	result := append(base, 2)
}
`,
			varName: "result",
			isSlice: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "test.go", tt.code, 0)
			require.NoError(t, err)

			inferrer := NewTypeInferrer(file)
			assert.Equal(t, tt.isSlice, inferrer.IsSlice(tt.varName),
				"IsSlice(%s) should be %v", tt.varName, tt.isSlice)
		})
	}
}

func TestTypeInferrer_TimeDetection(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		varName string
		isTime  bool
	}{
		{
			name: "var declaration with time.Time",
			code: `package main
import "time"
var t time.Time
`,
			varName: "t",
			isTime:  true,
		},
		{
			name: "short declaration with time.Now()",
			code: `package main
import "time"
func f() {
	now := time.Now()
}
`,
			varName: "now",
			isTime:  true,
		},
		{
			name: "function parameter time.Time",
			code: `package main
import "time"
func process(created time.Time) {}
`,
			varName: "created",
			isTime:  true,
		},
		{
			name: "time.Parse result",
			code: `package main
import "time"
func f() {
	t, _ := time.Parse("2006-01-02", "2025-01-08")
}
`,
			varName: "t",
			isTime:  true,
		},
		{
			name: "non-time variable",
			code: `package main
var count int
`,
			varName: "count",
			isTime:  false,
		},
		{
			name: "time.Duration",
			code: `package main
import "time"
func f() {
	d := time.Since(time.Now())
}
`,
			varName: "d",
			isTime:  false, // Duration, not Time
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "test.go", tt.code, 0)
			require.NoError(t, err)

			inferrer := NewTypeInferrer(file)
			assert.Equal(t, tt.isTime, inferrer.IsTime(tt.varName),
				"IsTime(%s) should be %v", tt.varName, tt.isTime)
		})
	}
}

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
