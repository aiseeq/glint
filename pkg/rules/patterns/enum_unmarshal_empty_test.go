package patterns

import "testing"

// An UnmarshalJSON of a status that rejects unknown values but lets "" pass
// leaves the zero status: a message without a status goes on to processing
// as if one came. A set whose constants hold "" decodes it as a member.
func TestEnumUnmarshalAcceptsEmpty(t *testing.T) {
	assertWanted(t, NewEnumUnmarshalAcceptsEmptyRule(), `package payprov

import (
	"encoding/json"
	"fmt"
	"strings"
)

type OrderStatus string

const (
	DepositPending OrderStatus = "Pending"
	DepositSuccess OrderStatus = "Success"
)

var depositStatusByName = map[string]OrderStatus{"pending": DepositPending, "success": DepositSuccess}

func (s *OrderStatus) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("status must be a string: %w", err)
	}
	if raw == "" { // want
		return nil
	}
	if v, ok := depositStatusByName[strings.ToLower(raw)]; ok {
		*s = v
		return nil
	}
	return fmt.Errorf("unknown status %q", raw)
}

type Network string

const (
	NetworkNone Network = ""
	NetworkTron Network = "tron"
)

func (n *Network) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == "" {
		return nil
	}
	if raw != string(NetworkTron) {
		return fmt.Errorf("unknown network %q", raw)
	}
	*n = Network(raw)
	return nil
}

type Label string

func (l *Label) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == "" {
		return nil
	}
	*l = Label(strings.TrimSpace(raw))
	return nil
}
`)
}
