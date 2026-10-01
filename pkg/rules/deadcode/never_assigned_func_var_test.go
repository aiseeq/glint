package deadcode

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A package-level function variable declared for a later wiring that never
// came: every call through it is a nil function call and panics.
func TestNeverAssignedFuncVar(t *testing.T) {
	files := map[string]string{
		"contracts/contracts.go": `package contracts

// VerifySignature checks a wallet signature.
var VerifySignature func(message, signature, address string) error

// Hash is set by the crypto package at start-up.
var Hash func(data []byte) []byte

// Now is the clock, replaced in tests.
var Now func() int64

// OnEvent is an optional hook.
var OnEvent func(name string)

var Format = func(v int) string { return "" }
`,
		"crypto/crypto.go": `package crypto

import "example.com/rulestest/contracts"

func init() {
	contracts.Hash = func(data []byte) []byte { return data }
}
`,
		"auth/login.go": `package auth

import "example.com/rulestest/contracts"

func Login(message, signature, address string) error {
	if err := contracts.VerifySignature(message, signature, address); err != nil {
		return err
	}
	_ = contracts.Hash(nil)
	_ = contracts.Format(1)
	if contracts.OnEvent != nil {
		contracts.OnEvent("login")
	}
	return nil
}

func Retry(message, signature, address string) error {
	return contracts.VerifySignature(message, signature, address)
}
`,
		"auth/login_test.go": `package auth

import "example.com/rulestest/contracts"

func fakeClock() { contracts.Now = func() int64 { return 0 } }
`,
	}
	violations, err := NewNeverAssignedFuncVarRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var places []string
	for _, v := range violations {
		places = append(places, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	assert.Equal(t, []string{"auth/login.go:6", "auth/login.go:18"}, places)
}

// The fix that removes such a call often fixes type errors in the same
// change: the package calling the variable does not type-check, and the
// call is still found.
func TestNeverAssignedFuncVarInBrokenPackage(t *testing.T) {
	root, contexts := rulestest.Module(t, map[string]string{
		"contracts/contracts.go": `package contracts

var VerifySignature func(message, signature string) error
`,
		"auth/login.go": `package auth

import "example.com/rulestest/contracts"

func Login(message, signature string) error {
	var confirmations *int = 1
	_ = confirmations
	return contracts.VerifySignature(message, signature)
}
`,
	})
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{TolerateBrokenPackages: true})
	require.NoError(t, err)
	require.NotEmpty(t, project.SkippedPackages)
	violations, err := NewNeverAssignedFuncVarRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "auth/login.go", violations[0].File)
	assert.Equal(t, 8, violations[0].Line)
}
