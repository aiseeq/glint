package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A page size read from the query goes to the query unbounded: limit=1000000
// loads the whole table. A cap, or a range check, bounds it.
func TestPaginationLimitUncapped(t *testing.T) {
	code := `package api

import (
	"net/http"
	"strconv"
)

const maxLimit = 100

func parsePagination(req *http.Request, defaultLimit int) int {
	limit := defaultLimit
	if s := req.URL.Query().Get("limit"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			limit = v
		}
	}
	return limit
}

func capped(req *http.Request) int {
	limit := 20
	if v, err := strconv.Atoi(req.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return limit
}

func ranged(req *http.Request) int {
	q := req.URL.Query()
	size, err := strconv.Atoi(q.Get("page_size"))
	if err != nil || size < 1 || size > 500 {
		return 50
	}
	return size
}

func viaForm(req *http.Request) int64 {
	n, _ := strconv.ParseInt(req.FormValue("per_page"), 10, 64)
	return n
}

func offsetOnly(req *http.Request) int {
	offset, _ := strconv.Atoi(req.URL.Query().Get("offset"))
	return offset
}

func pageAfterLimit(req *http.Request) (int, int) {
	limit, page := 20, 1
	if s := req.URL.Query().Get("limit"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 && v <= maxLimit {
			limit = v
		}
	}
	if s := req.URL.Query().Get("page"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			page = n
		}
	}
	return limit, page
}
`
	assert.Equal(t, []int{13, 41}, ruleLines(t, NewPaginationLimitUncappedRule(), code))
}

// A file at a fixed or $$-named path under /tmp, then used by sudo: another
// local user creates it first (or a symlink in its place) and root runs or
// writes their file. mktemp names are not predictable.
func TestShellPredictableTmpUnderSudo(t *testing.T) {
	script := `#!/bin/bash
set -euo pipefail

scp -q "$0" "${USER_AT}@${HOST}:/tmp/diagnose.sh"
ssh "${USER_AT}@${HOST}" "sudo bash /tmp/diagnose.sh $args"

REMOTE_TMP="/tmp/site-docs-$$.tar.gz"
ssh "$HOST" "sudo docker load -i $REMOTE_TMP"

safe=$(ssh "$HOST" "mktemp /tmp/diagnose-XXXXXX.sh")
ssh "$HOST" "sudo bash '${safe}'"

LOG=/tmp/build.log
make build > "$LOG" 2>&1
# sudo cat /tmp/notes.txt
sudo mv /tmp/site.conf /etc/nginx/conf.d/site.conf
ssh "$HOST" 'sudo -u postgres pg_dump app' > /tmp/app_dump.sql
sudo -u postgres psql -d app < "$DUMP" > /tmp/restore.log 2>&1
sudo -u root bash /tmp/fix.sh
sudo mv "$REMOTE_TMP" /opt/app/bin/app
`
	assert.Equal(t, []int{5, 8, 16, 19, 20}, textRuleLines(t, NewShellPredictableTmpRule(), "deploy/diagnose.sh", script))
}

// A page size above the bound replaced by a smaller default: the caller asked
// for more and takes the shorter page as all of it.
func TestPaginationLimitReplacedWithDefault(t *testing.T) {
	code := `package journal

const maxLimit = 500

const defaultLimit = 100

type Filter struct{ Limit, Offset int }

func list(f Filter) (int, int) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return limit, f.Offset
}

func listNamed(f Filter) int {
	limit := f.Limit
	if limit > maxLimit {
		limit = defaultLimit
	}
	return limit
}

func clamped(f Filter) int {
	limit := f.Limit
	if limit > maxLimit {
		limit = maxLimit
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	return limit
}
`
	assert.Equal(t, []int{12, 20}, ruleLines(t, NewPaginationLimitUncappedRule(), code))
}
