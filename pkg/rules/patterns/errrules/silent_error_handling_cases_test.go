package errrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

const silentRatesSource = `package rates

import "strconv"

type Rate struct{ V int }

func LatestA(s string) *Rate {
	v, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &Rate{V: v}
}
`

// Only test files are skipped: latest_rates.go contains "test_" and a
// testimonials directory starts with "/test", yet both are production code.
func TestSilentErrorHandling_ProductionFilesWithTestLikeNames(t *testing.T) {
	for _, path := range []string{"rates/latest_rates.go", "web/testimonials/rates.go", "rates/test.go"} {
		t.Run(path, func(t *testing.T) {
			ctx := rulestest.GoFile(t, path, silentRatesSource)
			assert.Equal(t, []int{9}, rulestest.ViolationLines(NewSilentErrorHandlingRule().AnalyzeFile(ctx)))
		})
	}
}

// A declared function answering with one bool leaves its error branches that
// return true/false to error-masked-as-false-bool and error-masking; the same
// branch is not reported by two rules.
func TestSilentErrorHandling_BoolFunctionBranchBelongsToBoolRules(t *testing.T) {
	const source = `package p

import "strconv"

func Publish(s string) bool {
	_, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return true
}

func Process(s string) bool {
	_, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return true
}
`
	ctx := rulestest.GoFile(t, "p/p.go", source)
	assert.Empty(t, NewSilentErrorHandlingRule().AnalyzeFile(ctx))
}

// A branch that answers the client through the handler's http.ResponseWriter
// has reported the failure, whatever the responder helper is called; a CLI
// branch that writes to stderr and returns an exit code has reported it too.
// A logger obtained from a factory call is still a logger, and the cause
// travelling inside a concatenated message or a field of the error value is
// still the cause. A branch that does none of that stays reported.
func TestSilentErrorHandling_ReportedThroughResponseStderrOrMessage(t *testing.T) {
	const source = `package payprov

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
)

type paramError struct{ message, details string }

func (e *paramError) Error() string { return e.message }

func parseQuery(s string) (int, *paramError) { return 0, nil }

func HandleLimit(w http.ResponseWriter, req *http.Request) {
	_, err := strconv.Atoi(req.URL.Query().Get("limit"))
	if err != nil {
		apihttp.RejectInput(w, req, "limit must be a number", "")
		return
	}
	var body map[string]any
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest)
		return
	}
	if from, parseErr := strconv.Atoi(req.URL.Query().Get("from")); parseErr != nil {
		apihttp.Reply(nil, req, "invalid 'from': "+parseErr.Error())
		return
	} else {
		_ = from
	}
	_, queryErr := parseQuery(req.URL.RawQuery)
	if queryErr != nil {
		apihttp.Reply(nil, req, queryErr.message, queryErr.details)
		return
	}
}

func writeProblem(w http.ResponseWriter, status int) { w.WriteHeader(status) }

func validateCommand() int {
	_, err := strconv.Atoi(os.Getenv("PAYPROV_LIMIT"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "payprov limit is invalid")
		return 2
	}
	return 0
}

func decodeMetadata(payload string) map[string]any {
	raw := map[string]any{}
	if err := json.Unmarshal([]byte(payload), &raw); err != nil {
		obs.DefaultLogger().Debug("skipping unparseable metadata: " + err.Error())
		return nil
	}
	return raw
}

func quietLimit(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
`
	ctx := rulestest.GoFile(t, "payprov/handlers.go", source)
	assert.Equal(t, []int{63}, rulestest.ViolationLines(NewSilentErrorHandlingRule().AnalyzeFile(ctx)))
}

func TestSilentErrorHandling_ForLoopAndNamedResultSlice(t *testing.T) {
	const source = `package p

import "strconv"

type Item struct{ Message string }

func load() error { return nil }

func WithForLoop(items []Item) {
	err := load()
	if err != nil {
		for i := 0; i < len(items); i++ {
			items[i].Message = err.Error()
		}
	}
}

func WithNamedResult(s string) (selected []string) {
	_, err := strconv.Atoi(s)
	if err != nil {
		selected = append(selected, s)
		return selected
	}
	return nil
}

func ClosureDoesNotHandle(s string) {
	err := load()
	if err != nil {
		func() { _ = err.Error() }()
	}
}
`
	ctx := rulestest.GoFile(t, "p/p.go", source)
	assert.Equal(t, []int{20, 29}, rulestest.ViolationLines(NewSilentErrorHandlingRule().AnalyzeFile(ctx)))
}

// A branch that appends to the returned slice answers a check whose only
// answer is its error (_, err := parse(s)) when it hands the checked item on
// as it is or marked. Any other append - a cached item, a zero, defaults,
// even into a slice of failures, which the success path may fill some other
// way - keeps the finding.
func TestSilentErrorHandling_AppendTellsFailureApart(t *testing.T) {
	const source = `package p

import (
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Row struct{ Addr string }

func fetch(k string) (string, error) { return "", errors.New("down") }
func parse(s string) (string, error) { return s, nil }
func filter(out []string, s string) []string { return out }
func use([]string)                     {}

func FromCache(keys []string, cache map[string]string) []string {
	var items []string
	for _, k := range keys {
		item, err := fetch(k)
		if err != nil {
			items = append(items, cache[k])
			continue
		}
		items = append(items, item)
	}
	return items
}

func ZeroFallback(raw []string) []int {
	var out []int
	for _, s := range raw {
		n, err := strconv.Atoi(s)
		if err != nil {
			out = append(out, 0)
			continue
		}
		out = append(out, n)
	}
	return out
}

func ReturnsOtherwise(raw []string) ([]string, error) {
	var out []string
	for _, s := range raw {
		if _, err := parse(s); err != nil {
			out = append(out, s)
			return nil, nil
		}
		out = append(out, s)
	}
	return out, nil
}

func Shadowed(raw []string) []string {
	var out []string
	for _, s := range raw {
		if _, err := parse(s); err != nil {
			out := append(out, s)
			use(out)
			continue
		}
		out = append(out, s)
	}
	return out
}

func DeclaredInBranch(raw []string) []string {
	var out []string
	for _, s := range raw {
		if _, err := parse(s); err != nil {
			var out []string
			out = append(out, s)
			continue
		}
		out = append(out, s)
	}
	return out
}

func NestedIf(raw []string, verbose bool) []string {
	var out []string
	for _, s := range raw {
		if _, err := parse(s); err != nil {
			if verbose {
				out = append(out, s)
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

func NotAppend(raw []string) []string {
	var out []string
	for _, s := range raw {
		if _, err := parse(s); err != nil {
			out = filter(out, s)
			continue
		}
		out = append(out, s)
	}
	return out
}

func AppendsOther(raw, other []string) []string {
	var out []string
	for _, s := range raw {
		if _, err := parse(s); err != nil {
			out = append(other, s)
			continue
		}
		out = append(out, s)
	}
	return out
}

func InClosure(raw []string) []string {
	var out []string
	for _, s := range raw {
		if _, err := parse(s); err != nil {
			func() { out = append(out, s) }()
			continue
		}
		out = append(out, s)
	}
	return out
}

func ChangedItem(raw []string) []string {
	var out []string
	for _, s := range raw {
		if _, err := parse(s); err != nil {
			out = append(out, strings.ToUpper(s))
			continue
		}
		out = append(out, s)
	}
	return out
}

func ValueKept(raw []string) ([]string, int) {
	var out []string
	total := 0
	for _, s := range raw {
		if n, err := strconv.Atoi(s); err != nil {
			out = append(out, s)
			continue
		} else {
			total += n
		}
		out = append(out, s)
	}
	return out, total
}

func KeptAsIs(rows []Row) []Row {
	var out []Row
	for _, row := range rows {
		if _, err := parse(row.Addr); err != nil {
			out = append(out, row)
			continue
		}
		row.Addr = strings.ToLower(row.Addr)
		out = append(out, row)
	}
	return out
}

func OtherChecked(raw []string, prefix string) []string {
	var out []string
	for _, s := range raw {
		if _, err := parse(prefix); err != nil {
			out = append(out, s)
			continue
		}
		out = append(out, prefix+s)
	}
	return out
}

func DefaultsOnFailure(path string, defaults []string) (peers []string) {
	data, err := os.ReadFile(path)
	if err != nil {
		peers = append(peers, defaults...)
		return
	}
	peers = strings.Split(string(data), "\n")
	return
}

func DefaultsReturned(path string, defaults []string) []string {
	var peers []string
	data, err := os.ReadFile(path)
	if err != nil {
		peers = append(peers, defaults...)
		return peers
	}
	peers = strings.Fields(string(data))
	return peers
}

func SchemeGuessed(raw []string) []string {
	var out []string
	for _, r := range raw {
		u, err := url.Parse(r)
		if err != nil {
			out = append(out, "https://"+r)
			continue
		}
		out = append(out, u.String())
	}
	return out
}

func Seeded(raw []string) []string {
	out := []string{"default"}
	for _, s := range raw {
		v, err := fetch(s)
		if err != nil {
			out = append(out, s)
			continue
		}
		use([]string{v})
	}
	return out
}

func VarSeeded(raw []string) []string {
	var out = []string{"default"}
	for _, s := range raw {
		v, err := fetch(s)
		if err != nil {
			out = append(out, s)
			continue
		}
		use([]string{v})
	}
	return out
}

func Prefilled(raw []string) []string {
	out := make([]string, len(raw))
	for _, s := range raw {
		v, err := fetch(s)
		if err != nil {
			out = append(out, s)
			continue
		}
		use([]string{v})
	}
	return out
}

func FromSeed(raw, seed []string) []string {
	out := seed
	for _, s := range raw {
		v, err := fetch(s)
		if err != nil {
			out = append(out, s)
			continue
		}
		use([]string{v})
	}
	return out
}

func MarkedAhead(raw []string) []string {
	var out []string
	for _, s := range raw {
		if _, err := parse(s); err != nil {
			out = append(out, "unknown: "+s)
			continue
		}
		out = append(out, s)
	}
	return out
}

func FailuresApart(raw []string) ([]string, []string) {
	var good, failed []string
	for _, s := range raw {
		v, err := fetch(s)
		if err != nil {
			failed = append(failed, s)
			continue
		}
		good = append(good, v)
	}
	return good, failed
}
`
	ctx := rulestest.GoFile(t, "p/p.go", source)
	assert.Equal(t, []int{22, 35, 47, 59, 72, 85, 99, 111, 123, 135, 148, 175, 186, 197, 209, 222, 235, 248, 261, 286}, rulestest.ViolationLines(NewSilentErrorHandlingRule().AnalyzeFile(ctx)))
}

// A suppression answers before the explanation is looked for: with an
// "optional" in its reason the rule would otherwise fall silent and the
// suppression look stale. The same words in a plain comment still explain
// the branch.
func TestSilentErrorHandling_SuppressionReasonIsNoExplanation(t *testing.T) {
	const source = `package p

import "strconv"

func Parse(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil { //nolint:silent-error-handling // the value is optional here
		return 0, nil
	}
	return n, nil
}

func Plain(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil { // the value is optional here
		return 0, nil
	}
	return n, nil
}
`
	rule := NewSilentErrorHandlingRule()
	ctx := rulestest.GoFile(t, "p/p.go", source)
	assert.Empty(t, rule.AnalyzeFile(ctx))
	assert.Equal(t, []int{7}, ctx.TakeSuppressionHits(rule.Name()), "the suppression silences the finding")
}
