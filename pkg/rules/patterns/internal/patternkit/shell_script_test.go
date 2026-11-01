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
	assert.Equal(t, map[int]map[int]OutputRedirectState{
		0:  {0: OutputRedirected, 10: OutputRedirected},
		1:  {2: OutputRedirected, 12: OutputRedirected, 31: OutputRedirected},
		2:  {2: OutputRedirected},
		3:  {0: OutputRedirected},
		7:  {0: OutputRedirected, 22: OutputRedirected, 24: OutputRedirected},
		8:  {0: OutputRedirected},
		9:  {2: OutputRedirected},
		10: {0: OutputRedirected},
		12: {2: OutputRedirected},
		15: {0: OutputRedirected},
		16: {0: OutputRedirected},
		17: {0: OutputRedirected},
		29: {0: OutputRestored, 6: OutputRestored, 21: OutputRestored},
		30: {0: OutputRedirected, 6: OutputRedirected, 21: OutputRedirected},
	}, got)
	assert.Empty(t, got[18])
	assert.Empty(t, got[19])
}

func TestStdoutIsRedirectedOnlyByStdoutRedirections(t *testing.T) {
	for tail, want := range map[string]bool{
		` > "$f"`:     true,
		` 1>> "$f"`:   true,
		` &> "$f"`:    true,
		` >&2`:        true,
		` 3> "$f"`:    false,
		` 12> "$f"`:   false,
		` 0> "$f"`:    false,
		` 3>&2`:       false,
		` <> "$f"`:    false,
		` < "$f"`:     false,
		` 2> "$f"`:    false,
		` # > file`:   false,
		` | tee "$f"`: false,
		` 3>&1 >&2`:   true,
		` <"$in" >&2`: true,
	} {
		assert.Equal(t, want, stdoutIsRedirected(tail), tail)
	}
}

func TestStdoutRedirectStateTracksDescriptorCopies(t *testing.T) {
	for tail, want := range map[string]OutputRedirectState{
		` > file`:            OutputRedirected,
		` >&2 1>&3`:          OutputRestored,
		` > file 1>&3`:       OutputRestored,
		` >&3`:               OutputRestored,
		` 3>&2 1>&3`:         OutputRedirected,
		` 3> file 1>&3`:      OutputRedirected,
		` 2>&1 >&2`:          OutputRestored,
		` >&2 2>&1`:          OutputRedirected,
		` 2> error`:          OutputUnchanged,
		` 3>&2`:              OutputUnchanged,
		` > file | next`:     OutputRedirected,
		` >&2; printf later`: OutputRedirected,
	} {
		assert.Equal(t, want, stdoutRedirectState(tail), tail)
	}
}
