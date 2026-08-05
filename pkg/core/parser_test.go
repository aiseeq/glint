package core

import (
	"go/ast"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewParser(t *testing.T) {
	p := NewParser()
	assert.NotNil(t, p)
}

func TestParserParseGoFile(t *testing.T) {
	p := NewParser()

	content := []byte("package main\n\nfunc main() {}\n")

	fset, file, err := p.ParseGoFile("test.go", content)
	require.NoError(t, err)
	assert.NotNil(t, fset)
	assert.NotNil(t, file)
	assert.Equal(t, "main", file.Name.Name)
}

func TestParserCache(t *testing.T) {
	p := NewParser()

	content := []byte("package main\n\nfunc main() {}\n")

	fset1, file1, err := p.ParseGoFile("test.go", content)
	require.NoError(t, err)

	// Second parse should return the same cached objects
	fset2, file2, err := p.ParseGoFile("test.go", content)
	require.NoError(t, err)
	assert.Same(t, fset1, fset2)
	assert.Same(t, file1, file2)
}

func TestParserParseError(t *testing.T) {
	p := NewParser()

	// Invalid Go code
	content := []byte("this is not valid go code {{{")

	_, _, err := p.ParseGoFile("invalid.go", content)
	assert.Error(t, err)
}

func parseCalls(t *testing.T, source string, name func(*ast.CallExpr) string) []string {
	t.Helper()

	p := NewParser()
	_, astFile, err := p.ParseGoFile("/project/test.go", []byte(source))
	require.NoError(t, err)

	var calls []string
	ast.Inspect(astFile, func(n ast.Node) bool {
		if ce, ok := n.(*ast.CallExpr); ok {
			if extracted := name(ce); extracted != "" {
				calls = append(calls, extracted)
			}
		}
		return true
	})
	return calls
}

func TestExtractFullFunctionName(t *testing.T) {
	calls := parseCalls(t, `package main

import "fmt"

func localFunc() {}

func main() {
	localFunc()
	fmt.Println("hello")
}
`, ExtractFullFunctionName)

	assert.Contains(t, calls, "localFunc")
	assert.Contains(t, calls, "fmt.Println")
}
