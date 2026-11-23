package frontendrules

import (
	"strings"
	"testing"
	"time"
)

// The backward scan for an if around a mention more than 512 bytes into the
// body walks every earlier if once and stops: it used to add the window start
// to each next position twice and loop forever.
func TestTSConditionalMentionScanEndsFarIntoTheBody(t *testing.T) {
	code := "export function far(m: Record<string, Provider>) {\n" +
		strings.Repeat("  let pad = 0\n", 50) +
		"  if (a) { x() }\n  if (b) { y() }\n  if (c) { z() }\n" +
		"  use(m['K'])\n  return m['K'].name\n}\n"
	mention := strings.Index(code, "m['K']")
	candidate := strings.LastIndex(code, "m['K']")
	if mention <= 512 {
		t.Fatalf("the mention must sit past the 512-byte window, it is at %d", mention)
	}
	done := make(chan bool, 1)
	go func() { done <- tsConditionalMentionIsIneffective(code, mention, candidate) }()
	select {
	case ineffective := <-done:
		if ineffective {
			t.Fatal("a mention outside every if condition is not an ineffective conditional mention")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("tsConditionalMentionIsIneffective did not end")
	}
}
