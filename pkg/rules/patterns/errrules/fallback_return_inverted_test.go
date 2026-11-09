package errrules

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A loop that adds only the items whose call succeeded, with no else and the
// sum returned, drops a failed item as silently as `if err != nil { continue }`
// does: the caller gets a partial total as the whole.
func TestFallbackReturn_InvertedCheckReturnsPartialSum(t *testing.T) {
	const source = `package metrics

import (
	"strconv"
	"strings"
)

type Balance struct{ Amount int }

type Svc struct{ balance func(page int) (Balance, error) }

func CPUTotal(lines []string) float64 {
	cpu := 0.0
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		if v, e := strconv.ParseFloat(fields[2], 64); e == nil {
			cpu += v
		}
	}
	return cpu
}

func (s *Svc) Total() int {
	total := 0
	for _, page := range []int{5, 10, 20} {
		b, err := s.balance(page)
		if err == nil {
			total += b.Amount
		}
	}
	return total
}

func Forever(next func() (int, error), done func() bool) int {
	total := 0
	for {
		if v, e := next(); e == nil {
			total += v
		}
		if done() {
			break
		}
	}
	return total
}

func Nested(groups [][]string) int {
	total := 0
	for _, group := range groups {
		for i := 0; i < len(group); i++ {
			if n, err := strconv.Atoi(group[i]); err == nil {
				total += n
			}
		}
	}
	return total
}

func Named(raw []string) (total int) {
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		}
	}
	return
}

func Doubled(raw []string) int {
	total := 0
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			n *= 2
			total = total + n
		}
	}
	return total
}
`
	assert.Equal(t, []int{19, 30, 40, 54, 64, 74}, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "metrics/metrics.go", source))
}

// Any else is the author's answer to the failure, whatever it does.
func TestFallbackReturn_InvertedCheckWithElse(t *testing.T) {
	const source = `package metrics

import (
	"fmt"
	"strconv"
)

func ElseLogs(raw []string) int {
	total := 0
	for _, r := range raw {
		n, err := strconv.Atoi(r)
		if err == nil {
			total += n
		} else {
			fmt.Printf("bad %q: %v\n", r, err)
		}
	}
	return total
}

func ElseContinues(raw []string) int {
	total := 0
	for _, r := range raw {
		n, err := strconv.Atoi(r)
		if err == nil {
			total += n
		} else {
			continue
		}
	}
	return total
}

func ElseReturns(raw []string) (int, error) {
	total := 0
	for _, r := range raw {
		n, err := strconv.Atoi(r)
		if err == nil {
			total += n
		} else {
			return 0, fmt.Errorf("parse %q: %w", r, err)
		}
	}
	return total, nil
}

func ElseKeepsError(raw []string) (int, []error) {
	total := 0
	var errs []error
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		} else {
			errs = append(errs, err)
		}
	}
	return total, errs
}

func ElseIf(raw []string, verbose bool) int {
	total := 0
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		} else if verbose {
			fmt.Println("bad", r)
		}
	}
	return total
}
`
	assert.Empty(t, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "metrics/metrics.go", source))
}

// A sum that is not returned is not the partial total this form is about.
func TestFallbackReturn_InvertedCheckSumNotReturned(t *testing.T) {
	const source = `package metrics

import (
	"fmt"
	"strconv"
)

type Res struct{ total int }

type Svc struct{ total int }

func SumOnlyPrinted(raw []string) {
	sum := 0
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			sum += n
		}
	}
	fmt.Println("sum", sum)
}

func (s *Svc) StoredInField(raw []string) {
	sum := 0
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			sum += n
		}
	}
	s.total = sum
}

func SteersTheLoop(files []string, size, limit int64, stat func(string) (int64, error)) {
	for size > limit && len(files) > 0 {
		path := files[0]
		files = files[1:]
		if n, err := stat(path); err == nil {
			size -= n
		}
	}
}

func ReturnedBeforeTheLoop(raw []string) int {
	total := 0
	if len(raw) == 0 {
		return total
	}
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		}
	}
	fmt.Println(total)
	return 0
}

func SameNames(raw []string) Res {
	total := 0
	var s Svc
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		}
	}
	fmt.Println(total)
	s.total = 0
	return Res{total: s.total}
}

func OnlyInErrorText(raw []string, limit int) error {
	total := 0
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		}
	}
	if total > limit {
		return fmt.Errorf("total %d is over %d", total, limit)
	}
	return nil
}

func ClosureReturn(raw []string) func() int {
	total := 0
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		}
	}
	fmt.Println(total)
	return func() int { total := 7; return total }
}
`
	assert.Empty(t, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "metrics/metrics.go", source))
}

// The failure is not silent: the then branch leaves the iteration so the code
// below it deals with the failure, or the error is read after the check.
func TestFallbackReturn_InvertedCheckFailureHandledBelow(t *testing.T) {
	const source = `package metrics

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

func ThenContinues(raw []string) (int, error) {
	total := 0
	for _, r := range raw {
		n, err := strconv.Atoi(r)
		if err == nil {
			total += n
			continue
		}
		return 0, fmt.Errorf("parse %q: %w", r, err)
	}
	return total, nil
}

func ThenBreaks(paths []string) int64 {
	var size int64
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil {
			size += info.Size()
			break
		}
	}
	return size
}

func ThenReturns(try func() (int, error)) int {
	total := 1
	for i := 0; i < 3; i++ {
		if v, err := try(); err == nil {
			total += v
			return total
		}
	}
	return 0
}

func ErrorJoinedAfter(raw []string) (int, error) {
	total := 0
	var result error
	for _, r := range raw {
		n, err := strconv.Atoi(r)
		if err == nil {
			total += n
		}
		result = errors.Join(result, err)
	}
	return total, result
}

func OuterErrorReturned(raw []string) (int, error) {
	total := 0
	var err error
	for _, r := range raw {
		var n int
		n, err = strconv.Atoi(r)
		if err == nil {
			total += n
		}
	}
	return total, err
}
`
	assert.Empty(t, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "metrics/metrics.go", source))
}

// Shapes that are out of the rule: no loop, a sum per item, a missing key, a
// collection, a stated reason, a closure in a loop, the old guard in a switch.
func TestFallbackReturn_InvertedCheckOutOfScope(t *testing.T) {
	const source = `package metrics

import (
	"fmt"
	"strconv"
)

type Set struct{}

func (Set) Add(int) {}

func NotInLoop(raw string) int {
	total := 10
	if n, err := strconv.Atoi(raw); err == nil {
		total += n
	}
	return total
}

func SumPerItem(raw []string) int {
	for _, r := range raw {
		sum := 1
		if n, err := strconv.Atoi(r); err == nil {
			sum += n
		}
		if sum > 5 {
			return sum
		}
	}
	return 0
}

func MissingKey(keys []string, m map[string]int) int {
	total := 0
	for _, k := range keys {
		if v, ok := m[k]; ok {
			total += v
		}
	}
	return total
}

func Collects(raw []string) []int {
	var out []int
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func AddMethod(raw []string) Set {
	var seen Set
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			seen.Add(n)
		}
	}
	return seen
}

func ExplainedAbove(raw []string) int {
	total := 0
	for _, r := range raw {
		// Optional: blank and malformed entries are skipped by design.
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		}
	}
	return total
}

func ExplainedInside(raw []string) int {
	total := 0
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			// Optional entries: the malformed ones are skipped by design.
			total += n
		}
	}
	return total
}

func ClosureInLoop(raw []string) {
	for _, r := range raw {
		parse := func() int {
			sum := 0
			if n, err := strconv.Atoi(r); err == nil {
				sum += n
			}
			return sum
		}
		fmt.Println(parse())
	}
}

func GuardInSwitch(raw []string, on bool) int {
	total := 0
	for _, r := range raw {
		sum := 0
		switch {
		case on:
			n, err := strconv.Atoi(r)
			if err != nil {
				continue
			}
			sum += n
		}
		total = sum
	}
	return total
}
`
	assert.Empty(t, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "metrics/metrics.go", source))
}

// A sum handed back with the failure dropped on the way: the error declared in
// the if is not the one returned, one path leaves it out, a sum per group, and
// the guard form in a classic for.
func TestFallbackReturn_InvertedCheckErrorNotHandedBack(t *testing.T) {
	const source = `package metrics

import "strconv"

func InitShadowsNamed(raw []string) (total int, err error) {
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		}
	}
	return
}

func InitShadowsOuter(raw []string, load func() error) (int, error) {
	total := 0
	err := load()
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		}
	}
	return total, err
}

func OnePathDropsError(raw []string, fast bool) (int, error) {
	total := 0
	var err error
	for _, r := range raw {
		var n int
		n, err = strconv.Atoi(r)
		if err == nil {
			total += n
		}
	}
	if fast {
		return total, nil
	}
	return total, err
}

func PerGroupClassic(groups [][]string) int {
	for _, group := range groups {
		sum := 0
		for i := 0; i < len(group); i++ {
			if n, err := strconv.Atoi(group[i]); err == nil {
				sum += n
			}
		}
		if sum > 5 {
			return sum
		}
	}
	return 0
}

func PerGroupRange(groups [][]string) int {
	for i := 0; i < len(groups); i++ {
		sum := 0
		for _, r := range groups[i] {
			if n, err := strconv.Atoi(r); err == nil {
				sum += n
			}
		}
		if sum > 5 {
			return sum
		}
	}
	return 0
}

func GuardInClassicFor(raw []string) int {
	total := 0
	for i := 0; i < len(raw); i++ {
		n, err := strconv.Atoi(raw[i])
		if err != nil {
			continue
		}
		total += n
	}
	return total
}
`
	assert.Equal(t, []int{7, 18, 31, 45, 60, 75}, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "metrics/metrics.go", source))
}

// The error is seen after the check, a named result is not what comes back, a
// then branch that continues leaves the failure to the code below it, a reason
// is given further down the branch, or another error is the one checked.
func TestFallbackReturn_InvertedCheckFailureSeenAfter(t *testing.T) {
	const source = `package metrics

import (
	"errors"
	"fmt"
	"log"
	"strconv"
)

func ErrorLoggedAfter(raw []string) int {
	total := 0
	for _, r := range raw {
		n, err := strconv.Atoi(r)
		if err == nil {
			total += n
		}
		log.Printf("parsed %q: %v", r, err)
	}
	return total
}

func ErrorReadLater(raw []string) (int, error) {
	total := 0
	var result error
	for _, r := range raw {
		n, err := strconv.Atoi(r)
		if err == nil {
			total += n
		}
		fmt.Println(r)
		result = errors.Join(result, err)
	}
	return total, result
}

func ReturnWrapsError(raw []string) (int, error) {
	total := 0
	var err error
	for _, r := range raw {
		var n int
		n, err = strconv.Atoi(r)
		if err == nil {
			total += n
		}
	}
	return total, fmt.Errorf("last: %w", err)
}

func NamedNotReturned(raw []string) (total int) {
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		}
	}
	return 7
}

func NamedErrorBareReturn(raw []string) (total int, err error) {
	for _, r := range raw {
		var n int
		n, err = strconv.Atoi(r)
		if err == nil {
			total += n
		}
	}
	return
}

func ThenContinuesToReport(raw []string) int {
	total := 0
	for _, r := range raw {
		n, err := strconv.Atoi(r)
		if err == nil {
			total += n
			continue
		}
		fmt.Println("bad", r)
	}
	return total
}

func ExplainedFurtherDown(raw []string) int {
	total := 0
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			n *= 2
			// Optional entries: the malformed ones are skipped by design.
			total += n
		}
	}
	return total
}

func OtherErrorChecked(raw []string, other error) int {
	total := 0
	for _, r := range raw {
		n, err := strconv.Atoi(r)
		if other != nil {
			fmt.Println("stop")
			continue
		}
		total += n + len(err.Error())
	}
	return total
}
`
	assert.Empty(t, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "metrics/metrics.go", source))
}

// Only an error declared by the if is out of scope at the return; one assigned
// there is the outer variable. A named error that the return leaves out is
// dropped, and a bare return of a function with no results returns nothing.
func TestFallbackReturn_InvertedCheckNamedAndAssignedError(t *testing.T) {
	const source = `package metrics

import (
	"fmt"
	"strconv"
)

func NamedErrorNotReturned(raw []string) (total int, err error) {
	for _, r := range raw {
		var n int
		n, err = strconv.Atoi(r)
		if err == nil {
			total += n
		}
	}
	return total, nil
}

func BareReturnNoResults(raw []string) {
	total := 0
	for _, r := range raw {
		if n, err := strconv.Atoi(r); err == nil {
			total += n
		}
	}
	fmt.Println(total)
	return
}

func AssignedInInit(raw []string) (int, error) {
	total := 0
	var err error
	for _, r := range raw {
		var n int
		if n, err = strconv.Atoi(r); err == nil {
			total += n
		}
	}
	return total, err
}
`
	assert.Equal(t, []int{12}, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "metrics/metrics.go", source))
}
