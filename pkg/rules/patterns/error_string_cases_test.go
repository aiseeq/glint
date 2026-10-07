package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A capital letter is allowed at the start only for a word that carries
// another capital or a digit inside it: an initialism (HTTP, TLS1.2) or an
// identifier (GetUser, ValidationService). An English word is not an
// acronym, and a word starting like an identifier prefix (Canceled, Address,
// Reading) is still an English word.
func TestErrorString_CapitalizedEnglishWordsAreReported(t *testing.T) {
	const source = `package p

import (
	"errors"
	"fmt"
)

var (
	e1 = errors.New("Failed to connect to database")
	e2 = errors.New("Invalid input")
	e3 = errors.New("Unable to open file")
	e4 = errors.New("Cannot parse config")
	e5 = errors.New("Canceled by user")
	e6 = errors.New("Address is empty")
	e7 = errors.New("Reading header failed")
	e8 = fmt.Errorf("Something went wrong: %w", e1)
	e9 = errors.New("A token is required")

	ok1 = errors.New("HTTP request failed")
	ok2 = errors.New("TLS1.2 handshake failed")
	ok3 = errors.New("GetUser failed")
	ok4 = errors.New("ValidationService: not ready")
	ok5 = errors.New("SELECT failed")
	ok6 = errors.New("CRYPTOPROV_CONFIG_LOAD_FAILED: missing key")
	ok7 = errors.New("gRPC stream closed")
	ok8 = errors.New("ID is empty")
)
`
	ctx := rulestest.GoFile(t, "p/e.go", source)
	assert.Equal(t, []int{9, 10, 11, 12, 13, 14, 15, 16, 17},
		violationLines(NewErrorStringRule().AnalyzeFile(ctx)))
}

// Go Code Review Comments allow a proper noun at the start of an error
// string. A word the package itself spells as the lead of a declared name
// (bridgoClient, BridgoQuote) or capitalised in the middle of a comment sentence
// is taken for one; the configured proper_nouns list adds the rest. A common
// error opener stays reported even when an identifier starts with it.
func TestErrorString_ProperNounsOfThePackage(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n",
		"bridge/client.go": `package bridge

// Quotes come from Bridgo and are cached per route.
type BridgoQuote struct{ ID string }

var rateCurveLegs = map[string]int{}

var invalidInputs = 0
`,
		"bridge/errs.go": `package bridge

import (
	"errors"
	"fmt"
)

func quote(id string, err error) error { return fmt.Errorf("Bridgo quote %s: %w", id, err) }

var (
	e1 = errors.New("Rate Curve market is closed")
	e2 = errors.New("Yieldo market expired")
	e3 = errors.New("Authbase OTP is not configured")
	e4 = errors.New("Invalid input")
	e5 = errors.New("Failed to fetch quote")
)
`,
		"other/errs.go": `package other

import "errors"

var e1 = errors.New("Bridgo quote missing")
`,
	}
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule := NewErrorStringRule()
	require.NoError(t, rule.Configure(map[string]any{"proper_nouns": []any{"Authbase"}}))
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, rule.AnalyzeFile(ctx)...)
	}
	assert.Equal(t, []string{"bridge/errs.go:12", "bridge/errs.go:14", "bridge/errs.go:15", "other/errs.go:5"}, foundLines(violations))
}
