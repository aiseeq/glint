package patternkit

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestSqlLiteralsFoldLocalExpressions(t *testing.T) {
	src := `package p
import (s "strings"; f "fmt")
func query(part string) {
	_ = s.Join([]string{"CREATE", "TABLE one(v int)"}, " ")
	table := s.Join([]string{"accept", "canary"}, "_")
	_ = "select v from " + table
	const name = "other"
	_ = f.Sprintf("select v from %s", name)
	plain := "third"
	_ = "select v from " + plain
	_ = "select v from " + part
	changed := "unsafe"
	if part != "" { changed = part }
	_ = "select v from " + changed
	joined := s.Join([]string{"unsafe", part}, "_")
	_ = "select v from " + joined
	address := "unsafe"
	_ = &address
	_ = "select v from " + address
	captured := "captured_unsafe"
	func() { captured = part }()
	_ = "select v from " + captured
	_ = f.Sprintf("select v from %s", part)
	redeclared := "first"
	redeclared, n := part, 1
	_ = n
	_ = "select v from " + redeclared
	_ = f.Sprintf("select v from %s %s", "missing")
}
func shadow(s struct{ Join func([]string, string) string }) {
	_ = s.Join([]string{"CREATE", "TABLE shadow(v int)"}, " ")
}`
	file, err := parser.ParseFile(token.NewFileSet(), "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, lit := range SqlLiterals(file) {
		got[lit.Text] = true
	}
	for _, want := range []string{"CREATE TABLE one(v int)", "select v from accept_canary", "select v from other", "select v from third"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	for text := range got {
		if strings.Contains(text, "%!") {
			t.Errorf("a format with a missing argument folded into %q", text)
		}
	}
	for _, unwanted := range []string{"select v from unsafe", "select v from captured_unsafe", "CREATE TABLE shadow(v int)", "select v from first"} {
		if got[unwanted] {
			t.Errorf("incorrectly folded %q", unwanted)
		}
	}
}
