package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A value checked against a whitelist stays safe only while nothing writes it
// before the query runs. A write the query can reach — on the next turn of a
// loop, through a pointer, inside a closure called in between or through &v
// passed to a call — brings the raw value back. An address of the value kept
// anywhere but a direct call argument, or a closure that writes it and is used
// other than by a direct call, drops the whitelist in the whole function.
func TestSQLInjectionWhitelistedValueRewrittenBeforeQuery(t *testing.T) {
	const caseCheck = `	switch value {
	case "name":
	default:
		return
	}
`
	const ifCheck = `	if value != "name" {
		return
	}
`
	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "loop in a case writes after the query", want: 1, body: `	switch value {
	case "name":
		for i := 0; i < n; i++ {
			db.Query("SELECT " + value)
			value = raw
		}
	default:
		return
	}
`},
		{name: "goto back in a case writes after the query", want: 1, body: `	switch value {
	case "name":
		i := 0
	again:
		db.Query("SELECT " + value)
		value = raw
		i++
		if i < n {
			goto again
		}
	default:
		return
	}
`},
		{name: "inner loop writes on an earlier turn", want: 1, body: `	switch value {
	case "name":
		for i := 0; i < n; i++ {
			if i > 0 {
				db.Query("SELECT " + value)
			}
			if i == 0 {
				value = raw
			}
		}
	default:
		return
	}
`},
		{name: "loop after a switch writes after the query", want: 1, body: caseCheck + `	for i := 0; i < n; i++ {
		db.Query("SELECT " + value)
		value = raw
	}
`},
		{name: "goto back after a switch", want: 1, body: caseCheck + `	i := 0
again:
	db.Query("SELECT " + value)
	value = raw
	i++
	if i < n {
		goto again
	}
`},
		{name: "loop after an if check writes after the query", want: 1, body: ifCheck + `	for i := 0; i < n; i++ {
		db.Query("SELECT " + value)
		value = raw
	}
`},
		{name: "pointer taken before the check, written in a case", want: 1, body: `	p := &value
	switch value {
	case "name":
		*p = raw
		db.Query("SELECT " + value)
	default:
		return
	}
`},
		{name: "pointer taken before the check, written after the switch", want: 1, body: `	p := &value
` + caseCheck + `	*p = raw
	db.Query("SELECT " + value)
`},
		{name: "closure writing the value called in a case", want: 1, body: `	set := func() { value = raw }
	switch value {
	case "name":
		set()
		db.Query("SELECT " + value)
	default:
		return
	}
`},
		{name: "closure writing the value called after the switch", want: 1, body: `	set := func() { value = raw }
` + caseCheck + `	set()
	db.Query("SELECT " + value)
`},
		{name: "address passed to a call in a case", want: 1, body: `	switch value {
	case "name":
		fmt.Sscan(raw, &value)
		db.Query("SELECT " + value)
	default:
		return
	}
`},
		{name: "address passed to a call after an if check", want: 1, body: ifCheck + `	fmt.Sscan(raw, &value)
	db.Query("SELECT " + value)
`},

		{name: "no check at all", want: 1, body: `	db.Query("SELECT " + value)
`},
		{name: "loop after a switch without a write", want: 0, body: caseCheck + `	for i := 0; i < n; i++ {
		db.Query("SELECT " + value)
	}
`},
		{name: "loop writes another variable", want: 0, body: ifCheck + `	other := raw
	for i := 0; i < n; i++ {
		db.Query("SELECT " + value)
		other = value
	}
	_ = other
`},
		{name: "goto back without a write", want: 0, body: caseCheck + `	i := 0
again:
	db.Query("SELECT " + value)
	i++
	if i < n {
		goto again
	}
`},
		{name: "pointer taken anywhere drops the whitelist even if only read", want: 1, body: `	p := &value
` + caseCheck + `	_ = *p
	db.Query("SELECT " + value)
`},
		{name: "pointer taken before the check drops the whitelist", want: 1, body: `	p := &value
	*p = raw
` + caseCheck + `	db.Query("SELECT " + value)
`},
		{name: "closure that writes and is stored, not called, drops the whitelist", want: 1, body: `	set := func() { value = raw }
	_ = set
` + caseCheck + `	db.Query("SELECT " + value)
`},
		{name: "address of another variable passed to a call", want: 0, body: ifCheck + `	var other string
	fmt.Sscan(raw, &other)
	db.Query("SELECT " + value)
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel() // each case loads its own module
			code := `package main

import (
	"database/sql"
	"fmt"
)

var _ = fmt.Sscan

func byColumn(db *sql.DB, value, raw string, n int) {
` + tt.body + `}
`
			violations := analyzeSQLInjection(t, code)
			assert.Len(t, violations, tt.want, "Code:\n%s", code)
		})
	}
}
