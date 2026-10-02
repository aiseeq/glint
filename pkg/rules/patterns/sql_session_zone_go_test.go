package patterns

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A timestamp read from the database carries the session's zone: cut into a
// calendar date in Go, it lands on another day when the connection string
// leaves that zone to the server.
func TestSQLSessionTimeZoneGoDateCut(t *testing.T) {
	files := map[string]string{
		"storage/db.go": `package storage

import "fmt"

func DSN(host, name string) string {
	return fmt.Sprintf("host=%s dbname=%s sslmode=disable", host, name)
}
`,
		"model/transfer.go": `package model

import "time"

type Transfer struct {
	ID        string     ` + "`db:\"id\"`" + `
	Timestamp time.Time  ` + "`db:\"timestamp\"`" + `
	SettledAt *time.Time ` + "`db:\"settled_at\"`" + `
	Received  time.Time  ` + "`json:\"received\"`" + `
}
`,
		"ledger/ledger.go": `package ledger

import (
	"fmt"
	"time"
)

func dates(tr *model.Transfer) []string {
	return []string{
		tr.Timestamp.Format("2006-01-02"),
		tr.Timestamp.UTC().Format("2006-01-02"),
		tr.Timestamp.Format("2006-01-02 15:04:05"),
		tr.Received.Format("2006-01-02"),
		tr.SettledAt.Format(time.DateOnly),
		"settled " + tr.Timestamp.Format("2006-01-02"),
		fmt.Sprintf("%s | %s", tr.ID, tr.Timestamp.Format("2006-01-02")),
	}
}
`,
	}
	run := func(path string) []int {
		_, contexts := rulestest.Module(t, files)
		rule := NewSQLSessionTimeZoneRule()
		for _, ctx := range contexts {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, ctx.Path, ctx.Content, parser.ParseComments)
			require.NoError(t, err)
			ctx.SetGoAST(fset, file)
		}
		rule.UseProjectFiles(contexts)
		for _, ctx := range contexts {
			if ctx.RelPath == path {
				return sqlRuleLines(t, rule, ctx)
			}
		}
		t.Fatal("no " + path)
		return nil
	}
	assert.Equal(t, []int{10, 14}, run("ledger/ledger.go"))
	assert.Equal(t, []int{6}, run("storage/db.go"))
	files["storage/db.go"] = strings.Replace(files["storage/db.go"], "sslmode=disable", "sslmode=disable timezone=UTC", 1)
	assert.Empty(t, run("ledger/ledger.go"))
}
