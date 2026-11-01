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
	}
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
	}, got)
	assert.Empty(t, got[15])
	assert.Empty(t, got[16])
}
