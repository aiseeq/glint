package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A provider sends "status": null for a payment still being set up; the
// enum's UnmarshalJSON maps null to "" and rejects it as an unknown status,
// so the whole callback fails to decode.
func TestUnmarshalJSONRejectsNull(t *testing.T) {
	violations := NewUnmarshalJSONRejectsNullRule().AnalyzeFile(rulestest.GoFile(t, "payprov/types.go", `package payprov

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Status string

var statusByName = map[string]Status{"pending": "Pending", "paid": "Paid"}

func (s *Status) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("status must be a string: %w", err)
	}
	if v, ok := statusByName[strings.ToLower(raw)]; ok {
		*s = v
		return nil
	}
	return fmt.Errorf("unknown status %q", raw)
}

type Grade string

func (g *Grade) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	switch strings.ToLower(raw) {
	case "low", "high":
		*g = Grade(raw)
		return nil
	default:
		return errors.New("unknown grade")
	}
}

type Network string

func (n *Network) UnmarshalJSON(data []byte) error {
	raw, err := strconv.Unquote(string(data))
	if err != nil {
		return err
	}
	*n = Network(raw)
	return nil
}

type Risk string

func (r *Risk) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw != "low" && raw != "high" {
		return fmt.Errorf("unknown risk %q", raw)
	}
	*r = Risk(raw)
	return nil
}

type Kind string

func (k *Kind) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	s, err := strconv.Unquote(string(data))
	if err != nil {
		return err
	}
	*k = Kind(s)
	return nil
}

type Channel string

func (c *Channel) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == "" {
		return nil
	}
	if raw != "web" {
		return errors.New("unknown channel")
	}
	*c = Channel(raw)
	return nil
}

type Label string

func (l *Label) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*l = Label(strings.TrimSpace(raw))
	return nil
}

type Order struct{ ID string }

func (o *Order) UnmarshalJSON(data []byte) error {
	type plain Order
	return json.Unmarshal(data, (*plain)(o))
}
`))
	assert.Equal(t, []string{"payprov/types.go:16", "payprov/types.go:30", "payprov/types.go:46"}, foundLines(violations))
}
