package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func TestVerifiedFileRereadAllowlist(t *testing.T) {
	rule, ok := rules.Get("verified-file-reread")
	require.True(t, ok)
	cases := []struct {
		name, middle string
		want         bool
	}{
		{"check", "", true},
		{"local assignment", "x := 1; _ = x", true},
		{"pure call", "_ = strings.TrimSpace(\" x \")", true},
		{"bytes call", "_ = bytes.Contains(a, []byte(\"x\"))", true},
		{"hash call", "_ = sha256.Sum256(a)", true},
		{"path reassigned", "path = other", false},
		{"unknown call", "touch()", false},
		{"conditional call", "if len(other) > 0 { touch() }", false},
		{"global assignment", "global = other", false},
		{"pointer call", "touchPath(&path)", false},
		{"defer", "defer touch()", false},
		{"go", "go touch()", false},
		{"method", "buf.WriteString(\"x\")", false},
		{"loop", "for range 1 { touch() }", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `package sample
import ("os"; "strings"; "bytes"; "crypto/sha256")
func valid(b []byte) bool { return len(b)>0 }
func touch() {}
func touchPath(*string) {}
var global string
func f(path, other string, buf *bytes.Buffer) [32]byte {
 a, err := os.ReadFile(path); if err != nil { return [32]byte{} }; if !valid(a) { return [32]byte{} }
 ` + tc.middle + `
 b, err := os.ReadFile(path); if err != nil { return [32]byte{} }; return sha256.Sum256(b)
}

var _ = strings.TrimSpace
`
			got := rulestest.RunRuleOnFiles(t, rule, map[string]string{"sample.go": src})
			if tc.want {
				require.Len(t, got, 1)
			} else {
				require.Empty(t, got)
			}
		})
	}
}

func TestVerifiedFileRereadSecondReadChecked(t *testing.T) {
	rule, ok := rules.Get("verified-file-reread")
	require.True(t, ok)
	src := `package sample
import ("os"; "bytes"; "crypto/sha256")
func valid(b []byte) bool { return len(b)>0 }
func f(path string) [32]byte {
 a, _ := os.ReadFile(path); if !valid(a) { return [32]byte{} }
 b, _ := os.ReadFile(path); if !valid(b) { return [32]byte{} }
 return sha256.Sum256(b)
}
func g(path string) [32]byte {
 a, _ := os.ReadFile(path); if !valid(a) { return [32]byte{} }
 b, _ := os.ReadFile(path); same := bytes.Equal(a,b); if !same { return [32]byte{} }
 return sha256.Sum256(b)
}
func sideEffect() int { return 1 }
func h(path string) ([32]byte, int) {
 a, _ := os.ReadFile(path); if !valid(a) { return [32]byte{}, 0 }
 b, _ := os.ReadFile(path)
 return sha256.Sum256(b), sideEffect()
}
func i(path string) [32]byte {
 a, _ := os.ReadFile(path); if !valid(a) { return [32]byte{} }
 before := sha256.Sum256(a)
 b, _ := os.ReadFile(path); after := sha256.Sum256(b)
 if before != after { return [32]byte{} }
 return sha256.Sum256(b)
}
func j(path string) [32]byte {
 a, _ := os.ReadFile(path); if !valid(a) { return [32]byte{} }
 b, _ := os.ReadFile(path)
 switch { case !bytes.Equal(a,b): return [32]byte{} }
 return sha256.Sum256(b)
}
func k(path string) [32]byte {
 a, _ := os.ReadFile(path); if !valid(a) { return [32]byte{} }
 b, _ := os.ReadFile(path)
 switch { case !valid(b): return [32]byte{} }
 return sha256.Sum256(b)
}
func l(path, other string) [32]byte {
 a, _ := os.ReadFile(path)
 if !valid(bytes.Join([][]byte{a, []byte(other)}, nil)) { return [32]byte{} }
 b, _ := os.ReadFile(path)
 return sha256.Sum256(b)
}`
	require.Empty(t, rulestest.RunRuleOnFiles(t, rule, map[string]string{"sample.go": src}))
}
