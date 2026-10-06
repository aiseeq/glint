package patterns

import (
	"testing"
)

// Repro from a real project: the inclusive end of a day was next midnight
// minus a nanosecond; the database rounded it back to midnight and the
// filter took in the next day's rows. Batch rows ordered by nanosecond
// offsets got one created_at.
func TestSubMicrosecondOffsetStored(t *testing.T) {
	decimalWanted(t, NewSubMicrosecondOffsetStoredRule(), `package ledger

import "time"

type OrderFilter struct {
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
}

type Order struct {
	ID        string    `+"`db:\"id\"`"+`
	CreatedAt time.Time `+"`db:\"created_at\"`"+`
}

type window struct {
	end time.Time
}

func list(f OrderFilter) {}

func dayFilter(next time.Time) OrderFilter {
	var f OrderFilter
	endOfDay := next.Add(-time.Nanosecond) // want
	f.CreatedBefore = &endOfDay
	return f
}

func batch(now time.Time, n int) []Order {
	var out []Order
	for i := 0; i < n; i++ {
		var o Order
		o.CreatedAt = now.Add(time.Duration(i) * time.Nanosecond) // want
		out = append(out, o)
	}
	return out
}

func claims(from, to time.Time) {
	toTime := to.Add(24*time.Hour - time.Nanosecond) // want
	load(from, toTime)
}

func load(from, to time.Time) {
	list(OrderFilter{CreatedAfter: &from, CreatedBefore: &to})
}

func micro(next time.Time) OrderFilter {
	end := next.Add(-time.Microsecond)
	return OrderFilter{CreatedBefore: &end}
}

func inMemory(next time.Time, t time.Time) bool {
	end := next.Add(-time.Nanosecond)
	w := window{end: end}
	return t.Before(w.end)
}
`)
}

// Repro from a real project: the edit form sent the operation date as
// YYYY-MM-DD, the update wrote it to created_at, and every edit reset the
// moment of the transfer to midnight.
func TestDateOnlyValueSetOnTimestampColumn(t *testing.T) {
	decimalWanted(t, NewDateOnlyValueSetOnTimestampColumnRule(), `package ledger

import "time"

type UpdateRequest struct {
	OperationDate *string
	ExecutedAt    *string
	Notes         *string
	DueDate       string
	StartDateTime string
}

type update struct {
	clauses []string
	args    []any
}

func (u *update) set(column string, value any) {
	u.clauses = append(u.clauses, column)
	u.args = append(u.args, value)
}

func build(req *UpdateRequest, at time.Time) *update {
	u := &update{}
	if req.OperationDate != nil {
		u.set("created_at", *req.OperationDate) // want
	}
	u.set("due_at", req.DueDate) // want
	if req.Notes != nil {
		u.set("notes", *req.Notes)
	}
	u.set("executed_at", at)
	u.set("starts_at", req.StartDateTime)
	u.set("due_date", req.DueDate)
	return u
}
`)
}

// Repro from a real project: a back-dated operation got the host's time of
// day and zone; the moment, and the day of the snapshot it fell into,
// depended on where and when it was entered.
func TestDateFromLocalClockHostZoneMoment(t *testing.T) {
	decimalWanted(t, NewDateFromLocalClockRule(), `package ledger

import "time"

func operationAt(s string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, err
	}
	now := time.Now()
	return time.Date(parsed.Year(), parsed.Month(), parsed.Day(), // want
		now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), now.Location()), nil
}

func operationAtUTC(s string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, err
	}
	now := time.Now().UTC()
	return time.Date(parsed.Year(), parsed.Month(), parsed.Day(),
		now.Hour(), now.Minute(), now.Second(), 0, now.Location()), nil
}

func inZone(d time.Time, loc *time.Location) time.Time {
	return time.Date(d.Year(), d.Month(), d.Day(), 12, 0, 0, 0, loc)
}
`)
}

// Repro from a real project: a client without a membership row was shown as
// a member "since" the moment of the request.
func TestMissingTimestampNotFoundRowAsQueryMoment(t *testing.T) {
	decimalWanted(t, NewMissingTimestampDefaultedToNowRule(), `package ledger

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type Group struct{ Name string }

type row struct {
	Name  string
	Since time.Time
}

func query(db *sql.DB, user string, at time.Time) (row, error) {
	var r row
	err := db.QueryRow("SELECT name, since FROM members WHERE user_id = $1 AND since <= $2", user, at).Scan(&r.Name, &r.Since)
	return r, err
}

func currentGroup(db *sql.DB, user string, at time.Time) (Group, time.Time, error) {
	r, err := query(db, user, at)
	if err == nil {
		return Group{Name: r.Name}, r.Since, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Group{}, time.Time{}, fmt.Errorf("member: %w", err)
	}
	name, since := "regular", at
	return Group{Name: name}, since, nil // want
}

func lastSeen(db *sql.DB, user string) (time.Time, error) {
	r, err := query(db, user, time.Now())
	if errors.Is(err, sql.ErrNoRows) {
		return time.Now(), nil // want
	}
	if err != nil {
		return time.Time{}, err
	}
	return r.Since, nil
}

func asOf(db *sql.DB, user string, at time.Time) (time.Time, error) {
	_, err := query(db, user, at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return at, err
}
`)
}
