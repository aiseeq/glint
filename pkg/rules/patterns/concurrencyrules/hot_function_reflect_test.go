package concurrencyrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hotReflectSource carries fields from a record into the frame by name
// through reflect on every tick; a bit mask of the fields and a plain
// assignment do it without reflection. Looking a type up once with
// reflect.TypeFor costs nothing per value, and the same work in an unmarked
// function is ordinary code.
const hotReflectSource = `package copier

import "reflect"

type Unit struct{ X, Y int }

const MaskX = 1

//glint:hot
func Copy(dst, src *Unit, name string, m int) bool {
	reflect.ValueOf(dst).Elem().FieldByName(name).Set(reflect.ValueOf(src).Elem().FieldByName(name)) // want reflect-in-hot-function
	if m&MaskX != 0 {
		dst.X = src.X
	}
	t := reflect.TypeFor[Unit]()
	_ = t.Name() // want reflect-in-hot-function
	same := reflect.DeepEqual(*dst, *src) // want reflect-in-hot-function
	return same && carry(dst, src)
}

func carry(dst, src *Unit) bool {
	reflect.ValueOf(dst).Elem().Set(reflect.ValueOf(src).Elem())
	return true
}

func Cold(dst, src *Unit) bool { return reflect.DeepEqual(dst, src) }
`

func TestReflectInHotFunction(t *testing.T) {
	files := map[string]string{"copier/copier.go": hotReflectSource}
	project := rulestest.Project(t, files)

	violations, err := NewReflectInHotFunctionRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "reflect-in-hot-function"), patterntest.FoundLines(violations))

	rule := NewReflectInHotFunctionRule()
	require.NoError(t, rule.Configure(map[string]any{"transitive": true}))
	violations, err = rule.AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, append(patterntest.WantedLines(files, "reflect-in-hot-function"), "copier/copier.go:22"), patterntest.FoundLines(violations))
}
