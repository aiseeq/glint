package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The branch of a failed call logs and goes on; the result below is the zero
// value the call left, used as if the call had succeeded.
func TestFallbackReturn_FailedResultUsedAfterBranch(t *testing.T) {
	const source = `package svc

import "strconv"

type Logger interface{ Warn(msg string, args ...any) }

type Svc struct {
	logger Logger
	admin  func() (string, bool)
}

func (s *Svc) Amount(raw string, decimals int) int {
	amount, err := strconv.Atoi(raw)
	if err != nil {
		s.logger.Warn("failed to parse amount", "error", err)
	}
	if decimals > 0 {
		amount = amount / decimals
	}
	return amount
}

func (s *Svc) Actor() string {
	adminID, ok := s.admin()
	if !ok {
		s.logger.Warn("admin id missing")
	}
	return adminID
}
`
	assert.Equal(t, []int{14, 25}, fallbackReturnLines(t, source))
}

// A default declared before the call and replaced only in the else branch:
// after a failure the default is used as the result.
func TestFallbackReturn_DefaultKeptWhenCallFails(t *testing.T) {
	const source = `package svc

type Logger interface{ Warn(msg string, args ...any) }

type Svc struct {
	logger Logger
	price  func() (float64, error)
}

func (s *Svc) Total(amounts []float64) float64 {
	price := 0.0
	p, err := s.price()
	if err != nil {
		s.logger.Warn("price failed", "error", err)
	} else {
		price = p
	}
	total := 0.0
	for _, a := range amounts {
		total += a * price
	}
	return total
}
`
	assert.Equal(t, []int{13}, fallbackReturnLines(t, source))
}

// A loop that skips the items whose call failed and sums the rest returns a
// partial total as the whole.
func TestFallbackReturn_TotalOfItemsThatDidNotFail(t *testing.T) {
	const source = `package svc

import "fmt"

type Balance struct{ Amount int }

type Svc struct{ balance func(page int) (Balance, error) }

func (s *Svc) Total() int {
	total := 0
	for _, page := range []int{5, 10, 20} {
		b, err := s.balance(page)
		if err != nil {
			fmt.Printf("no balance for %d: %v\n", page, err)
			continue
		}
		total += b.Amount
	}
	return total
}
`
	assert.Equal(t, []int{13}, fallbackReturnLines(t, source))
}

// What stays out: a branch that leaves, a result not read below, a result
// replaced by another call, an error handed on, a loop that collects the
// items to report them rather than summing.
func TestFallbackReturn_FailedResultNotUsed(t *testing.T) {
	const source = `package svc

import (
	"errors"
	"strconv"
)

var errInvalid = errors.New("invalid")

type Logger interface{ Warn(msg string, args ...any) }

type Svc struct {
	logger Logger
	errs   []error
}

func (s *Svc) Leaves(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil {
		s.logger.Warn("parse failed", "error", err)
		return -1
	}
	return n
}

func (s *Svc) NotRead(raw string) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		s.logger.Warn("parse failed", "error", err)
	}
	_ = raw
	n = 3
	_ = n
}

func (s *Svc) LoggedOnly(read func() ([]byte, error)) {
	body, err := read()
	if err != nil {
		s.logger.Warn("read body failed", "error", err)
	}
	s.logger.Warn("upstream answered", "body", string(body))
}

func (s *Svc) ZeroChecked(lookup func() (string, error), fallback string) string {
	network, err := lookup()
	if err != nil {
		s.logger.Warn("lookup failed, taking the fallback", "error", err)
	}
	if network == "" {
		network = fallback
	}
	return network
}

func (s *Svc) FailsClosed(valid func() (bool, error)) error {
	ok, err := valid()
	if err != nil {
		s.logger.Warn("validation failed", "error", err)
	}
	if !ok {
		return errInvalid
	}
	return nil
}

func (s *Svc) Collected(raw []string) []int {
	var out []int
	for _, r := range raw {
		n, err := strconv.Atoi(r)
		if err != nil {
			s.errs = append(s.errs, err)
			continue
		}
		out = append(out, n)
	}
	return out
}
`
	assert.Empty(t, fallbackReturnLines(t, source))
}
