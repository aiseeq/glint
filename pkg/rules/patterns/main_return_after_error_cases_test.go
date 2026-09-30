package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// The deferred-exit idiom: main sets the exit code and returns, so deferred
// cleanups run before the deferred os.Exit reports the code. The return in
// the error branch ends the process with code 1, not 0.
func TestMainReturnAfterError_DeferredExitCode(t *testing.T) {
	const source = `package main

import (
	"fmt"
	"os"
)

func run() error { return nil }

func cleanup() error { return nil }

func main() {
	code := 0
	defer func() { os.Exit(code) }()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
		return
	}
	if err := cleanup(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}
`
	ctx := rulestest.GoFile(t, "cmd/tool/main.go", source)
	assert.Equal(t, []int{22}, violationLines(NewMainReturnAfterErrorRule().AnalyzeFile(ctx)))
}

// stderr is a writer, not an error: a nil check on it is not an error branch.
func TestMainReturnAfterError_StderrIsNotAnError(t *testing.T) {
	const source = `package main

import (
	"io"
	"os"
)

var stderr io.Writer = os.Stderr

func main() {
	if stderr != nil {
		return
	}
}
`
	ctx := rulestest.GoFile(t, "cmd/tool/main.go", source)
	assert.Empty(t, NewMainReturnAfterErrorRule().AnalyzeFile(ctx))
}
