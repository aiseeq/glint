package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSQLInjectionWhitelistedLoopValueInDeferredQuery(t *testing.T) {
	tests := []struct {
		name   string
		params string
		body   string
		want   int
	}{
		{name: "scan into outer variable then query in goroutine", params: ", value string", want: 1, body: `	for rows.Next() {
		if err := rows.Scan(&value); err != nil { return }
		switch value { case "name": default: continue }
		go func() { db.Query("SELECT " + value) }()
	}
`},
		{name: "assignment then deferred query", params: ", value string", want: 1, body: `	for _, raw := range raws {
		value = raw
		if value != "name" { continue }
		defer func() { db.Query("SELECT " + value) }()
	}
`},
		{name: "stored closure called after loop", params: ", value string", want: 1, body: `	var run func()
	for _, raw := range raws {
		value = raw
		switch value { case "name": default: continue }
		run = func() { db.Query("SELECT " + value) }
	}
	if run != nil { run() }
`},
		{name: "parameter rewritten before goroutine query", params: ", value string", want: 1, body: `	for _, raw := range raws {
		value = raw
		if value != "name" { continue }
		go func() { db.Query("SELECT " + value) }()
	}
`},
		{name: "same turn closure checks then queries outer value", params: ", checked string", want: 1, body: `	for _, raw := range raws {
		checked = raw
		go func() {
		switch checked { case "name": default: return }
		db.Query("SELECT " + checked)
		}()
	}
`},
		{name: "immediate closure query", want: 0, body: `	var checked string
	for rows.Next() {
		if err := rows.Scan(&checked); err != nil { return }
		switch checked { case "name": default: continue }
		func() { db.Query("SELECT " + checked) }()
	}
`},
		{name: "direct query in same turn", want: 0, body: `	var checked string
	for rows.Next() {
		if err := rows.Scan(&checked); err != nil { return }
		switch checked { case "name": default: continue }
		db.Query("SELECT " + checked)
	}
`},
		{name: "variable of the turn in goroutine query", want: 0, body: `	for _, raw := range raws {
		value := raw
		if value != "name" { continue }
		go func() { db.Query("SELECT " + value) }()
	}
`},
		{name: "outer value passed to goroutine as argument", params: ", value string", want: 0, body: `	for _, raw := range raws {
		value = raw
		if value != "name" { continue }
		go func(v string) { db.Query("SELECT " + v) }(value)
	}
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code := `package main
import "database/sql"
func query(db *sql.DB, rows *sql.Rows, raws []string` + tt.params + `) {
` + tt.body + `}
`
			assert.Len(t, analyzeSQLInjection(t, code), tt.want, "Code:\n%s", code)
		})
	}
}
