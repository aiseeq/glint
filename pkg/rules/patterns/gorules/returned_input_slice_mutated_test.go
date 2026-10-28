package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReturnedInputSliceMutatedWhileOriginalKept(t *testing.T) {
	files := map[string]string{"svc.go": `package svc
type item struct{ label string }
func pass(items []item) []item { return items }
func decorate(items []item) string {
	shown := pass(items)
	decorateOne(&shown[0])
	return items[0].label
}
func decorateOne(i *item) { i.label = "shown" }
func copied(items []item) string {
	shown := append([]item(nil), pass(items)...)
	decorateOne(&shown[0])
	return items[0].label
}
func noLaterRead(items []item) {
	shown := pass(items)
	decorateOne(&shown[0])
}
func reassigned(items []item) string {
	items = pass(items)
	decorateOne(&items[0])
	return items[0].label
}
func readOnly(items []item) string {
	shown := pass(items)
	_ = shown[0]
	return items[0].label
}
`}
	violations := patterntest.RunRuleOnFiles(t, NewReturnedInputSliceMutatedRule(), files)
	require.Len(t, violations, 1)
	assert.Equal(t, "returned-input-slice-mutated-while-original-kept", violations[0].Rule)
}
