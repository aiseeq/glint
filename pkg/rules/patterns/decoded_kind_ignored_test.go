package patterns

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func decodedKindFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewDecodedKindFieldIgnoredRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

const decodedKindProviderSource = `package provider

type TokenEvent struct {
	TransactionID string ` + "`json:\"transaction_id\"`" + `
	From          string ` + "`json:\"from\"`" + `
	To            string ` + "`json:\"to\"`" + `
	Value         string ` + "`json:\"value\"`" + `
	Type          string ` + "`json:\"type\"`" + `
}
`

// A converter from a decoded event that never reads the event's type and
// writes one kind for every event stores approvals as transfers.
func TestDecodedKindFieldIgnored(t *testing.T) {
	assert.Equal(t, []string{"ledger/convert.go:17", "ledger/convert.go:32"}, decodedKindFindings(t, map[string]string{
		"provider/types.go": decodedKindProviderSource,
		"ledger/convert.go": `package ledger

import "example.com/rulestest/provider"

type Kind string

const (
	KindTransfer Kind = "transfer"
	KindApprove  Kind = "approve"
)

type Row struct {
	Hash, From, To, Amount string
	Kind                   Kind
}

func convert(event *provider.TokenEvent) *Row {
	row := &Row{Hash: event.TransactionID, From: event.From, To: event.To, Amount: event.Value}
	row.Kind = KindTransfer
	return row
}

func convertChecked(event *provider.TokenEvent) *Row {
	row := &Row{Hash: event.TransactionID, From: event.From, To: event.To, Amount: event.Value}
	row.Kind = KindTransfer
	if event.Type == "Approval" {
		row.Kind = KindApprove
	}
	return row
}

func convertLiteral(event provider.TokenEvent) Row {
	return Row{Hash: event.TransactionID, From: event.From, To: event.To, Amount: event.Value, Kind: KindTransfer}
}

func addresses(event *provider.TokenEvent) []string {
	return []string{event.From, event.To, event.TransactionID}
}
`,
	}))
}

func TestDecodedKindFieldIgnoredRule_Metadata(t *testing.T) {
	rule := NewDecodedKindFieldIgnoredRule()
	assert.Equal(t, "decoded-kind-field-ignored", rule.Name())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

// The kind read by a helper handed the record, or by the dispatcher that
// picked this converter for one kind, is not ignored.
func TestDecodedKindFieldReadElsewhere(t *testing.T) {
	assert.Empty(t, decodedKindFindings(t, map[string]string{
		"provider/types.go": decodedKindProviderSource,
		"ledger/convert.go": `package ledger

import (
	"encoding/json"

	"example.com/rulestest/provider"
)

type Kind string

const (
	KindTransfer Kind = "transfer"
	KindApprove  Kind = "approve"
)

type Row struct {
	Hash, From, To, Amount, Raw string
	Kind                        Kind
}

func kindOf(event *provider.TokenEvent) Kind {
	if event.Type == "Approval" {
		return KindApprove
	}
	return KindTransfer
}

func raw(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

func convert(event *provider.TokenEvent) *Row {
	row := &Row{Hash: event.TransactionID, From: event.From, To: event.To, Amount: event.Value, Raw: raw(event)}
	row.Kind = kindOf(event)
	if row.Kind == KindApprove {
		row.Kind = KindApprove
	}
	return row
}

func dispatch(event *provider.TokenEvent) *Row {
	switch event.Type {
	case "Transfer":
		return convertTransfer(event)
	}
	return nil
}

func convertTransfer(event *provider.TokenEvent) *Row {
	return &Row{Hash: event.TransactionID, From: event.From, To: event.To, Amount: event.Value, Kind: KindTransfer}
}
`,
	}))
}
