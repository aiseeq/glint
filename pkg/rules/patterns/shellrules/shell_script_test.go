package shellrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"github.com/stretchr/testify/assert"
)

// A case arm's ")" closes no group: the commands after an inline case are
// still split, and the loop around it ends at its done.
func TestSegmentsAfterInlineCase(t *testing.T) {
	var texts []string
	for _, s := range patternkit.Segments(`while read -r kv; do case "$kv" in _=*|PWD=*) ;; *) export "$kv";; esac; done < /proc/$P/environ`) {
		texts = append(texts, s.Trimmed())
	}
	assert.Equal(t, []string{
		"while read -r kv",
		`do case "$kv" in _=*|PWD=*)`,
		"",
		`*) export "$kv"`,
		"",
		"esac",
		"done < /proc/$P/environ",
	}, texts)
	var inSubshell []string
	for _, s := range patternkit.Segments(`x=$(echo a; echo b) && (cd "$d"; make)`) {
		inSubshell = append(inSubshell, s.Trimmed())
	}
	assert.Equal(t, []string{`x=$(echo a; echo b)`, `(cd "$d"; make)`}, inSubshell)
}
