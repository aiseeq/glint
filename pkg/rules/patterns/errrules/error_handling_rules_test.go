package errrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/gorules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// errorHandlingRules lists the error-handling rules that share the helpers of
// error_vocabulary.go.
func errorHandlingRules() []rules.Rule {
	return []rules.Rule{
		NewReturnNilErrorRule(), NewErrorMaskingRule(), NewFallbackReturnRule(),
		NewSilentErrorHandlingRule(), NewIgnoredErrorRule(), gorules.NewEmptyStructReturnRule(),
		gorules.NewAnonInterfaceDegradationRule(), NewMainReturnAfterErrorRule(),
		gorules.NewRedundantCompatibilityRule(), NewSilentConfigErrorRule(), NewErrorStringCompareRule(),
		NewErrorStringRule(), NewErrorWrapRule(), NewErrorRebuiltFromTextRule(),
		NewErrorMaskedAsFalseBoolRule(), NewMaskedErrorOrConditionRule(), NewErrorCauseDroppedRule(),
		NewLogAndReturnZeroRule(), gorules.NewConstructorNilReturnRule(), gorules.NewConstructorSwallowsNilDepRule(),
		NewIgnoredDecisionResultRule(), NewErrorLengthCheckRule(),
	}
}

// A function implemented in assembly (or bound with go:linkname) has a
// declaration and no body. Every rule must pass over it instead of walking a
// nil body.
func TestErrorHandlingRules_FunctionWithoutBody(t *testing.T) {
	const source = `package main

// readCounter is implemented in assembly.
func readCounter() (*int, error)

// ReadCounter is implemented in assembly.
func ReadCounter() (int, error)

// GetValue is implemented in assembly.
func GetValue() (int, error)

// NewThing is implemented in assembly.
func NewThing(dep *int) *int

// IsReady is implemented in assembly.
func IsReady() bool

func main()
`
	for _, rule := range errorHandlingRules() {
		t.Run(rule.Name(), func(t *testing.T) {
			ctx := rulestest.GoFile(t, "lib/asm.go", source)
			assert.NotPanics(t, func() { rule.AnalyzeFile(ctx) })
			assert.NotPanics(t, func() {
				patterntest.RunRuleOnFiles(t, rule, map[string]string{
					"lib/asm.go":        source,
					"lib/asm_amd64.s":   "",
					"lib/asm_arm64.s":   "",
					"lib/asm_generic.s": "",
				})
			})
		})
	}
}
