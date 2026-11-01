package patternkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedirectedCompoundSegments(t *testing.T) {
	lines := []ShellLine{
		{Text: "if outer; then", starts: []int{0}, Nums: []int{1}},
		{Text: "  if inner; then printf inner; fi > inner.log", starts: []int{0}, Nums: []int{2}},
		{Text: "  printf outer", starts: []int{0}, Nums: []int{3}},
		{Text: "fi > outer.log; printf after", starts: []int{0}, Nums: []int{4}},
		{Text: "while read x; do printf x; done < input", starts: []int{0}, Nums: []int{5}},
		{Text: "if x; then printf x; fi 2> error", starts: []int{0}, Nums: []int{6}},
		{Text: "{ printf x; } | tee out", starts: []int{0}, Nums: []int{7}},
		{Text: "case x in a) printf x;; esac > out", starts: []int{0}, Nums: []int{8}},
		{Text: "{", starts: []int{0}, Nums: []int{9}},
		{Text: "  printf x", starts: []int{0}, Nums: []int{10}},
		{Text: "} > out", starts: []int{0}, Nums: []int{11}},
		{Text: "if x; then", starts: []int{0}, Nums: []int{12}},
		{Text: "  { printf x; } > inner", starts: []int{0}, Nums: []int{13}},
		{Text: "  printf outside", starts: []int{0}, Nums: []int{14}},
		{Text: "fi", starts: []int{0}, Nums: []int{15}},
		{Text: "echo ${out} > file; printf after", starts: []int{0}, Nums: []int{16}},
		{Text: "echo $(printf ')') > file", starts: []int{0}, Nums: []int{17}},
		{Text: "echo fi > f; echo done; echo esac; echo {; echo }", starts: []int{0}, Nums: []int{18}},
		{Text: "if true; then", starts: []int{0}, Nums: []int{19}},
		{Text: "cat <<EOF", starts: []int{0}, Nums: []int{20}},
		{Text: "fi > body.out", starts: []int{0}, Nums: []int{21}},
		{Text: "EOF", starts: []int{0}, Nums: []int{22}},
		{Text: "cat <<'QUOTED'", starts: []int{0}, Nums: []int{23}},
		{Text: "done > body.out", starts: []int{0}, Nums: []int{24}},
		{Text: "QUOTED", starts: []int{0}, Nums: []int{25}},
		{Text: "cat <<-END", starts: []int{0}, Nums: []int{26}},
		{Text: "\tesac > body.out", starts: []int{0}, Nums: []int{27}},
		{Text: "\tEND", starts: []int{0}, Nums: []int{28}},
		{Text: "fi", starts: []int{0}, Nums: []int{29}},
		{Text: "if x; then printf x; fi 2>&1 >&2", starts: []int{0}, Nums: []int{30}},
		{Text: "if x; then printf x; fi >&2 2>&1", starts: []int{0}, Nums: []int{31}},
	}
	assert.False(t, stdoutIsRedirected(" 2>&1 >&2"))
	assert.True(t, stdoutIsRedirected(" >&2 2>&1"))
	assert.NotContains(t, heredocBodyLines(lines), 29)
	got := RedirectedCompoundSegments(lines)
	assert.Equal(t, map[int]map[int]bool{
		0:  {0: true, 10: true},
		1:  {2: true, 12: true, 31: true},
		2:  {2: true},
		3:  {0: true},
		7:  {0: true, 22: true, 24: true},
		8:  {0: true},
		9:  {2: true},
		10: {0: true},
		12: {2: true},
		30: {0: true, 6: true, 21: true},
	}, got)
	assert.Empty(t, got[15])
	assert.Empty(t, got[16])
	assert.Empty(t, got[17])
	assert.Empty(t, got[18])
	assert.Empty(t, got[19])
}
