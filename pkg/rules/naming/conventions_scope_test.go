package naming

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeConventions(t *testing.T, path, code string) []*core.Violation {
	t.Helper()
	return NewConventionsRule().AnalyzeFile(rulestest.GoFile(t, path, code))
}

// Nothing imports package main, so its names are never read as main.X: a
// type named MainWindow there does not stutter.
func TestConventionsNoStutterInPackageMain(t *testing.T) {
	violations := analyzeConventions(t, "cmd/tool/main.go", `package main

type MainWindow struct{}

func MainLoop() {}

func main() { _ = MainWindow{}; MainLoop() }
`)
	assert.Empty(t, violations)
}

// The underscore check covers the exported API. A local name is never
// exported, whatever its case, and neither is a type declared in a function.
func TestConventionsSkipsLocalNames(t *testing.T) {
	violations := analyzeConventions(t, "app/app.go", `package app

func run() {
	var Local_Var = 1
	const Local_Const = 2
	type Local_Type struct{}
	_, _, _ = Local_Var, Local_Const, Local_Type{}
}
`)
	assert.Empty(t, violations)
}

// A name made only of initialisms is written in capitals by convention:
// JSONRPC is JSON + RPC, HTTPAPI is HTTP + API. A capitalized word that is not
// an initialism still is ALL_CAPS.
func TestConventionsInitialismCompounds(t *testing.T) {
	violations := analyzeConventions(t, "rpc/rpc.go", `package rpc

type JSONRPC struct{}

type HTTPAPI struct{}

type SQLDB struct{}

type HANDLER struct{}
`)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "HANDLER")
}
