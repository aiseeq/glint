package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A secret scanner script lists the shape of a password as a regular
// expression: a class and a counted repetition are no password. A real value
// on the same key is still one.
func TestHardcodedSecretsSkipsRegexpShapeInScripts(t *testing.T) {
	rule := NewHardcodedSecretsRule()
	scan := "#!/usr/bin/env bash\nset -euo pipefail\npatterns=(\n    'PGPASSWORD=[A-Za-z0-9_./+=-]{20,}'\n)\nprintf '%s\\n' \"${patterns[@]}\"\n"
	assert.Empty(t, rule.AnalyzeFile(rulestest.TextFile(t, "scripts/scan.sh", scan)))
	load := "#!/usr/bin/env bash\nPGPASS" + "WORD=s3cr3tP4ssw0rdValue123 psql -h 127.0.0.1\n"
	found := rule.AnalyzeFile(rulestest.TextFile(t, "scripts/load.sh", load))
	require.Len(t, found, 1)
	assert.Equal(t, 2, found[0].Line)
}
