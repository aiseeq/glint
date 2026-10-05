package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A field that comes as a string or as a list is told apart by trying one
// decode and taking its failure for the other shape: a malformed value of the
// first shape is reported as a broken list, and a third shape passes as
// whatever the fallback makes of it.
func TestJSONShapeByFailedUnmarshal(t *testing.T) {
	files := map[string]string{
		"feed/fields.go": `package feed

import (
	"encoding/json"
	"fmt"
)

type Field struct {
	Name       string
	Validation json.RawMessage
}

type option struct{ ID, Name string }

func parseOptions(raw json.RawMessage) ([]option, error) {
	var options []option
	if err := json.Unmarshal(raw, &options); err != nil {
		return nil, err
	}
	return options, nil
}

func requirement(f Field) (string, error) {
	var rule string
	if err := json.Unmarshal(f.Validation, &rule); err != nil { // want json-shape-by-failed-unmarshal
		if _, optErr := parseOptions(f.Validation); optErr != nil {
			return "", fmt.Errorf("%s: %w", f.Name, optErr)
		}
		return "unknown", nil
	}
	return rule, nil
}

func validation(f Field) (string, error) {
	var text string
	if err := json.Unmarshal(f.Validation, &text); err == nil { // want json-shape-by-failed-unmarshal
		return text, nil
	}
	options, err := parseOptions(f.Validation)
	if err != nil {
		return "", err
	}
	return fmt.Sprint(options), nil
}

// amount tries a number and then the same value as text: both are scalars,
// a decode of one cannot hide a broken field of the other.
func amount(raw []byte) (float64, error) {
	var n float64
	err := json.Unmarshal(raw, &n)
	if err != nil {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("amount as text: %s", s)
	}
	return n, nil
}

// decimalText reads a number sent quoted or bare.
func decimalText(raw []byte) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return "", err
	}
	return n.String(), nil
}

// listOrMap tries a list of records and then a map of them: a record field of
// the wrong type in the list is reported as "not a map".
func listOrMap(raw json.RawMessage) (int, error) {
	var asList []option
	if err := json.Unmarshal(raw, &asList); err == nil { // want json-shape-by-failed-unmarshal
		return len(asList), nil
	}
	var asMap map[string]option
	if err := json.Unmarshal(raw, &asMap); err != nil {
		return 0, err
	}
	return len(asMap), nil
}

// shape decodes once into any and switches on what came.
func shape(raw json.RawMessage) (string, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	switch v := value.(type) {
	case string:
		return v, nil
	}
	return "", fmt.Errorf("unexpected shape")
}

// twoFields decodes two different inputs.
func twoFields(a, b json.RawMessage) error {
	var x, y string
	if err := json.Unmarshal(a, &x); err != nil {
		return json.Unmarshal(b, &y)
	}
	return nil
}
`,
	}
	violations, err := NewJSONShapeByFailedUnmarshalRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "json-shape-by-failed-unmarshal"), foundLines(violations))
}
