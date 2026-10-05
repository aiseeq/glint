package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const identifierLengthSource = `package testdb

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func longName(test string) string {
	name := strings.ToLower(test)
	if len(name) > 40 {
		name = name[:40]
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("app_test_%s_%d_%s", name, time.Now().UnixNano(), hex.EncodeToString(b)) // want postgres-identifier-exceeds-63-bytes
}

func shortName(test string) string {
	name := strings.ToLower(test)
	if len(name) > 16 {
		name = name[:16]
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fmt.Sprintf("app_test_%s_%s", name, hex.EncodeToString(b))
}

func unboundedName(test string) string {
	return fmt.Sprintf("app_test_%s_%d", test, time.Now().UnixNano())
}

func Create(db *sql.DB, test string) error {
	name := longName(test)
	if _, err := db.Exec(fmt.Sprintf("CREATE DATABASE %s TEMPLATE base", name)); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE DATABASE " + shortName(test)); err != nil {
		return err
	}
	if _, err := db.Exec(fmt.Sprintf("CREATE DATABASE %s", unboundedName(test))); err != nil {
		return err
	}
	schema := fmt.Sprintf("tenant_%x_%d_archive_of_the_ledger_rows", make([]byte, 0), time.Now().Unix())
	_, err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema))
	return err
}

func Label(test string) string {
	return fmt.Sprintf("app_test_%s_%d_%s_and_more_words_that_are_not_a_name", test, time.Now().UnixNano(), test)
}
`

// A database name whose fixed text, cut test name, UnixNano and random hex
// pass 63 bytes is cut by PostgreSQL; a name that fits, one whose parts are
// unbounded, and a Sprintf no CREATE uses are left alone.
func TestPostgresIdentifierExceedsLimit(t *testing.T) {
	files := map[string]string{
		"go.mod":           "module example.com/rulestest\n\ngo 1.24\n",
		"testdb/testdb.go": identifierLengthSource,
	}
	violations, err := NewPostgresIdentifierExceedsLimitRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "postgres-identifier-exceeds-63-bytes"), foundLines(violations))
}
