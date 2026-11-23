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

// Past the 512-byte window the scan still reaches the deciding if when it is
// not the nearest "if" before the mention ("verified" spells one between the
// keyword and the mention), and decides as it does on a short body.
func TestTSConditionalMentionDecidesFarIntoTheBodyAsNearTheStart(t *testing.T) {
	body := func(pad int, condition string) string {
		return "export function far(m: Record<string, Provider>, verified: boolean) {\n" +
			strings.Repeat("  let pad = 0\n", pad) +
			"  if (a) { x() }\n  if (b) { y() }\n" +
			"  if (" + condition + ") console.warn('missing')\n" +
			"  return m['K'].x\n}\n"
	}
	decide := func(code string) bool {
		mention := strings.Index(code, "m['K']")
		candidate := strings.LastIndex(code, "m['K']")
		done := make(chan bool, 1)
		go func() { done <- tsConditionalMentionIsIneffective(code, mention, candidate) }()
		select {
		case ineffective := <-done:
			return ineffective
		case <-time.After(10 * time.Second):
			t.Fatal("tsConditionalMentionIsIneffective did not end")
			return false
		}
	}
	for _, condition := range []string{"m['K'] === undefined", "verified && m['K'] === undefined", "m['K']"} {
		short, long := body(0, condition), body(60, condition)
		if strings.Index(short, "m['K']") > 512 || strings.Index(long, "m['K']") <= 512 {
			t.Fatalf("%q: the short body must keep the mention inside the window and the long one past it", condition)
		}
		if !decide(short) || !decide(long) {
			t.Errorf("%q: a warning-only if does not guard the read, short=%v long=%v, want both true", condition, decide(short), decide(long))
		}
	}
}
