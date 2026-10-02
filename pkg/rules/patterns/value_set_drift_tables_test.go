package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const valueSetChainModels = `package models

const (
	ChainAlpha   = "alpha"
	ChainBeta    = "beta"
	ChainGamma   = "gamma"
	ChainDelta   = "delta"
	ChainEpsilon = "epsilon"
	ChainZeta    = "zeta"
)

// RuleExactA is a rule a provider confirms.
const RuleExactA = "auto:a"

// RuleExactB is a rule a provider confirms.
const RuleExactB = "auto:b"

// RuleExactC is a rule a provider confirms, added later.
const RuleExactC = "auto:c"

// RulePair is the heuristic rule.
const RulePair = "auto:pair"
`

// A hand-picked set of constants spelled in two places: the next member is
// added to one copy. A set of four or more repeated exactly is reported at
// its later copy; a set one member short of a set spelled the same way twice
// elsewhere is the copy the new member did not reach.
func TestValueSetDriftConstantSets(t *testing.T) {
	files := map[string]string{
		"backend/models/chain.go": valueSetChainModels,
		"backend/ledger/ledger.go": `package ledger

import "example.com/rulestest/backend/models"

func isLedgerChain(chain string) bool {
	switch chain {
	case models.ChainAlpha, models.ChainBeta, models.ChainGamma, models.ChainDelta:
		return true
	}
	return false
}

func isExact(rule string) bool {
	switch rule {
	case models.RuleExactA, models.RuleExactB, models.RuleExactC:
		return true
	}
	return false
}

var allChains = []string{models.ChainAlpha, models.ChainBeta, models.ChainGamma, models.ChainDelta, models.ChainEpsilon, models.ChainZeta}
`,
		"backend/store/query.go": `package store

import (
	"fmt"

	"example.com/rulestest/backend/models"
)

func ledgerCondition(alias string) string {
	return fmt.Sprintf("%s.chain IN ('%s', '%s', '%s', '%s')", alias,
		models.ChainAlpha, models.ChainBeta, models.ChainGamma, models.ChainDelta) // want value-set-drift
}

var exactRules = []string{models.RuleExactA, models.RuleExactB, models.RuleExactC}

func preserved() []string {
	rules := []string{models.RuleExactA, models.RuleExactB} // want value-set-drift
	return rules
}

func pairs(query string, ids []string) string {
	return fmt.Sprintf(query, ids, models.RuleExactA, models.RuleExactB, models.RulePair)
}

var everyChain = []string{models.ChainAlpha, models.ChainBeta, models.ChainGamma, models.ChainDelta, models.ChainEpsilon, models.ChainZeta}

var bridgeChains = []string{models.ChainAlpha, models.ChainGamma, models.ChainEpsilon}

func isBridge(chain string) bool {
	switch chain {
	case models.ChainAlpha, models.ChainBeta, models.ChainEpsilon:
		return true
	}
	return false
}
`,
	}
	assert.Equal(t, wantedLines(files, "value-set-drift"), foundLines(valueSetDriftFindings(t, files)))
}

// A translation table kept twice: a switch mapping slugs to constants copies
// the pairs of a map (here written the other way round) and misses the slugs
// added to the map since.
func TestValueSetDriftTranslationTables(t *testing.T) {
	files := map[string]string{
		"backend/models/chain.go": valueSetChainModels,
		"backend/sync/slugs.go": `package sync

import "example.com/rulestest/backend/models"

var chainToSlug = map[string]string{
	models.ChainAlpha:   "al",
	models.ChainBeta:    "be",
	models.ChainGamma:   "ga",
	models.ChainDelta:   "de",
	models.ChainEpsilon: "ep",
}

var chainNames = map[string]string{
	models.ChainAlpha: "Alpha",
	models.ChainBeta:  "Beta",
	models.ChainZeta:  "Zeta",
}
`,
		"backend/report/normalize.go": `package report

import (
	"strings"

	"example.com/rulestest/backend/models"
)

func normalize(slug string) string {
	switch strings.ToLower(slug) { // want value-set-drift
	case "al":
		return models.ChainAlpha
	case "be":
		return models.ChainBeta
	case "ga", "gam":
		return models.ChainGamma
	default:
		return slug
	}
}

func shortName(chain string) string {
	switch chain {
	case models.ChainAlpha:
		return "al"
	case models.ChainBeta:
		return "be"
	}
	return ""
}
`,
	}
	assert.Equal(t, wantedLines(files, "value-set-drift"), foundLines(valueSetDriftFindings(t, files)))
}

// A switch over some constants of a set whose default makes a value up from
// the input: a constant added to the set gets an invented value instead of
// its own.
func TestValueSetDriftDefaultFromInput(t *testing.T) {
	files := map[string]string{
		"backend/models/chain.go": valueSetChainModels,
		"backend/balance/native.go": `package balance

import (
	"fmt"
	"strings"

	"example.com/rulestest/backend/models"
)

func nativeSymbol(chain string) string {
	switch chain { // want value-set-drift
	case models.ChainAlpha, models.ChainBeta:
		return "ALP"
	case models.ChainGamma:
		return "GAM"
	default:
		return strings.ToUpper(chain)
	}
}

func knownSymbol(chain string) (string, error) {
	switch chain {
	case models.ChainAlpha, models.ChainBeta:
		return "ALP", nil
	default:
		return "", fmt.Errorf("unknown chain %s", chain)
	}
}

func fullSymbol(chain string) string {
	switch chain {
	case models.ChainAlpha, models.ChainBeta, models.ChainGamma:
		return "A"
	case models.ChainDelta, models.ChainEpsilon, models.ChainZeta:
		return "B"
	default:
		return strings.ToUpper(chain)
	}
}

func explorer(chain string) string {
	switch chain {
	case models.ChainAlpha:
		return "https://alpha.example"
	case models.ChainBeta:
		return "https://beta.example"
	default:
		return ""
	}
}
`,
	}
	assert.Equal(t, wantedLines(files, "value-set-drift"), foundLines(valueSetDriftFindings(t, files)))
}

// The values the backend assigns to a JSON field against the TS union of
// that field: a value the union lacks reaches a client that does not know it.
func TestValueSetDriftAssignedFieldValues(t *testing.T) {
	files := map[string]string{
		"backend/models/group.go": `package models

type TxGroup struct {
	ID            string ` + "`json:\"id\"`" + `
	MetadataError string ` + "`json:\"metadataError,omitempty\"`" + `
	Stage         string ` + "`json:\"stage\"`" + `
}
`,
		"backend/sync/meta.go": `package sync

import "example.com/rulestest/backend/models"

const (
	metaUnavailable = "a_unavailable"
	metaMismatch    = "a_mismatch"
	metaConflict    = "a_conflict"
)

const otherUnavailable = "b_unavailable"

func mark(g *models.TxGroup, code int, message string) {
	switch code {
	case 1:
		g.MetadataError = metaUnavailable
	case 2:
		g.MetadataError = metaMismatch
	case 3:
		g.MetadataError = metaConflict
	default:
		g.MetadataError = message
	}
}

func markOther(g *models.TxGroup) {
	g.MetadataError = otherUnavailable
	g.Stage = "new"
}

func fresh() models.TxGroup {
	return models.TxGroup{Stage: "queued"}
}
`,
		"web/src/api.ts": `export interface TxGroup {
  id: string
  metadataError?: 'a_unavailable' | 'a_mismatch' | 'a_conflict' // want value-set-drift
  stage: 'new' | 'queued' | 'done'
}
`,
	}
	assert.Equal(t, wantedLines(files, "value-set-drift"), foundLines(valueSetDriftFindings(t, files)))
}
