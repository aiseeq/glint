package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A switch over an external type string whose default stores the unknown
// variant with a made-up direction: the record is kept, and an unparsed
// event passes for an outgoing transfer.
func TestDefaultInventsDomainValue_GoSwitchDefault(t *testing.T) {
	const source = `package parse

func convert(action Action) Tx {
	tx := Tx{}
	switch action.Type {
	case "Transfer":
		tx.Direction = model.DirectionIn
	case "Swap":
		tx.Direction = model.DirectionSwap
	default:
		tx.TxType = strings.ToLower(action.Type)
		tx.Direction = model.DirectionOut
	}
	return tx
}

func label(action Action) Tx {
	tx := Tx{}
	switch action.Type {
	case "Transfer":
		tx.Direction = model.DirectionIn
	default:
		tx.Direction = model.DirectionUnknown
	}
	return tx
}

func skip(action Action) (Tx, bool) {
	tx := Tx{}
	switch action.Type {
	case "Transfer":
		tx.Direction = model.DirectionIn
	default:
		return tx, false
	}
	return tx, true
}
`
	violations := NewDefaultInventsDomainValueRule().AnalyzeFile(rulestest.GoFile(t, "parse/convert.go", source))
	assert.Equal(t, []int{12}, violationLines(violations))
}
