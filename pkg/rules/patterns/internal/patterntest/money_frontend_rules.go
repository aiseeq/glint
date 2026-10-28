package patterntest

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func AssertLines(t *testing.T, violations []*core.Violation, want []int) {
	t.Helper()
	var got []int
	for _, v := range violations {
		got = append(got, v.Line)
	}
	if len(got) != len(want) {
		t.Fatalf("got lines %v, want %v (%v)", got, want, violationMessages(violations))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got lines %v, want %v (%v)", got, want, violationMessages(violations))
		}
	}
}

func violationMessages(violations []*core.Violation) []string {
	var out []string
	for _, v := range violations {
		out = append(out, v.Message)
	}
	return out
}
