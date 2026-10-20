package hist

import (
	"flag"
	"reflect"
	"strings"
	"testing"
)

func TestParseTakesFlagsAfterPositionals(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	interval := fs.Int("interval", 14, "")
	glint := fs.String("glint", "glint", "")
	args, err := Parse(fs, []string{"repo", "--interval", "3", "out.jsonl", "--glint=/bin/g"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"repo", "out.jsonl"}; !reflect.DeepEqual(args, want) {
		t.Errorf("positional = %v, want %v", args, want)
	}
	if *interval != 3 || *glint != "/bin/g" {
		t.Errorf("interval = %d, glint = %q", *interval, *glint)
	}
}

func TestHeadAndTailCountCharacters(t *testing.T) {
	s := strings.Repeat("я", 10)
	if got := Head(s, 3); got != "яяя" {
		t.Errorf("Head = %q", got)
	}
	if got := Tail("abcdef", 2); got != "ef" {
		t.Errorf("Tail = %q", got)
	}
	if got := Tail("ab", 5); got != "ab" {
		t.Errorf("Tail of a short string = %q", got)
	}
}
