package qarules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestTestWithoutParallelRule(t *testing.T) {
	code := `package sample

import (
	"os"
	"testing"
)

func TestMissing(t *testing.T) { work() }
func TestSecond(t *testing.T) { setup(); t.Parallel() }
func TestFirst(t *testing.T) { t.Parallel(); work() }
func TestSetenv(t *testing.T) { t.Setenv("A", "B") }
func TestChdir(t *testing.T) { t.Chdir(".") }
func TestOSChdir(t *testing.T) { os.Chdir(".") }
func TestExcepted(t *testing.T) { work() } //nolint:test-without-parallel -- intentionally shares state
func TestMain(m *testing.M) { os.Exit(m.Run()) }
func helperN4(t *testing.T) { work() }
func BenchmarkN5(b *testing.B) { work() }
func FuzzN6(f *testing.F) { work() }
func ExampleN7() { work() }
`
	ctx := core.NewFileContext("sample_test.go", ".", []byte(code), core.DefaultConfig())
	fset, file, err := core.NewParser().ParseGoFile("sample_test.go", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	ctx.SetGoAST(fset, file)
	rule := NewTestWithoutParallelRule()
	if got := rule.AnalyzeFile(ctx); len(got) != 0 {
		t.Fatalf("rule without require setting reported %d findings", len(got))
	}
	if err := rule.Configure(map[string]any{"require": true}); err != nil {
		t.Fatal(err)
	}
	got := rule.AnalyzeFile(ctx)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %#v", len(got), got)
	}
	for _, violation := range got {
		if violation.Rule != "test-without-parallel" {
			t.Errorf("unexpected rule %q", violation.Rule)
		}
	}
}
