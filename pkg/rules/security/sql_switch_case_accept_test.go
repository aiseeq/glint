package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Inside a case listing constants the switch tag equals one of them, so a
// query built from the tag there is as safe as one built after a switch whose
// default rejects the value. A branch the tag can reach with any value keeps
// the finding.
func TestSQLInjectionQueryInsideConstantCaseOfSwitch(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "query in a constant case of a rejecting switch",
			code: `package main

import "database/sql"

func byColumn(db *sql.DB, value string) {
	switch value {
	case "name", "email":
		db.Query("SELECT " + value + " FROM users")
	default:
		return
	}
}`,
		},
		{
			name: "query in the second constant case",
			code: `package main

import (
	"database/sql"
	"errors"
)

func byColumn(db *sql.DB, value string) error {
	switch value {
	case "name":
		return nil
	case "email", "phone":
		_, err := db.Query("SELECT " + value + " FROM users")
		return err
	default:
		return errors.New("unknown column")
	}
}`,
		},
		{
			name: "query in the default branch",
			code: `package main

import "database/sql"

func byColumn(db *sql.DB, value string) {
	switch value {
	case "name", "email":
		return
	default:
		db.Query("SELECT " + value + " FROM users")
	}
}`,
			want: 1,
		},
		{
			name: "default without return reaches the query after the switch",
			code: `package main

import "database/sql"

func byColumn(db *sql.DB, value string) {
	switch value {
	case "name", "email":
	default:
		value = value + ""
	}
	db.Query("SELECT " + value + " FROM users")
}`,
			want: 1,
		},
		{
			name: "default falls through into the constant case",
			code: `package main

import "database/sql"

func byColumn(db *sql.DB, value string) {
	switch value {
	default:
		fallthrough
	case "name", "email":
		db.Query("SELECT " + value + " FROM users")
	}
}`,
			want: 1,
		},
		{
			name: "tag rewritten in the case before the query",
			code: `package main

import "database/sql"

func byColumn(db *sql.DB, value, raw string) {
	switch value {
	case "name", "email":
		value = raw
		db.Query("SELECT " + value + " FROM users")
	default:
		return
	}
}`,
			want: 1,
		},
		{
			name: "case lists a variable",
			code: `package main

import "database/sql"

func byColumn(db *sql.DB, value, other string) {
	switch value {
	case "name", other:
		db.Query("SELECT " + value + " FROM users")
	default:
		return
	}
}`,
			want: 1,
		},
		{
			name: "query in a type switch case inside the default branch",
			code: `package main

import "database/sql"

func byColumn(db *sql.DB, value string, arg any) {
	switch value {
	case "name", "email":
	default:
		switch arg.(type) {
		case int:
			db.Query("SELECT " + value + " FROM users")
		}
		return
	}
}`,
			want: 1,
		},
		{
			name: "query in a select case inside the default branch",
			code: `package main

import "database/sql"

func byColumn(db *sql.DB, value string, ready chan bool) {
	switch value {
	case "name", "email":
	default:
		select {
		case <-ready:
			db.Query("SELECT " + value + " FROM users")
		}
		return
	}
}`,
			want: 1,
		},
		{
			name: "query in a case of another switch before the whitelist",
			code: `package main

import "database/sql"

func byColumn(db *sql.DB, mode, value string) {
	switch mode {
	case "a":
		db.Query("SELECT " + value + " FROM users")
		switch value {
		case "name":
		default:
			return
		}
	}
}`,
			want: 1,
		},
		{
			name: "tag is an expression, not the queried variable",
			code: `package main

import (
	"database/sql"
	"strings"
)

func byColumn(db *sql.DB, value string) {
	switch strings.ToLower(value) {
	case "name", "email":
		db.Query("SELECT " + value + " FROM users")
	default:
		return
	}
}`,
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel() // each case loads its own module
			violations := analyzeSQLInjection(t, tt.code)
			assert.Len(t, violations, tt.want, "Code:\n%s", tt.code)
		})
	}
}
