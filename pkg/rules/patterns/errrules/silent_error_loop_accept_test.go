package errrules

import (
	"strconv"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
)

// An error whose text a branch writes into the data the caller or the
// operator reads is not lost, whether the write sits in the branch or in a
// loop of it, and a failure the branch records in the result the function
// returns is reported to the caller. A branch that drops the error, a loop
// that writes nothing of it and a slice nobody reads still lose it.
func TestSilentErrorHandling_ErrorTextReachesData(t *testing.T) {
	code := `package monitor

import (
	"errors"
	"fmt"
	"strings"

	"example.com/feed"
)

type Holding struct {
	Symbol    string
	Price     float64
	Unchecked string
}

func quote(sym string) (float64, error)        { return 0, errors.New("down") }
func quotes(syms []string) (map[string]float64, error) { return nil, errors.New("down") }
func parseAddr(addr string) (string, error)    { return "", errors.New("bad") }
func normalize(addr string) string             { return addr }

func Check(holdings []*Holding) {
	for _, holding := range holdings {
		price, quoteErr := feed.Quote(holding.Symbol)
		if quoteErr != nil {
			holding.Unchecked = fmt.Sprintf("price source did not answer: %v", quoteErr)
			continue
		}
		hist, historyErr := feed.History(holding.Symbol)
		if historyErr != nil {
			holding.Unchecked = fmt.Sprintf("price source did not answer: %v", historyErr)
			continue
		}
		holding.Price = price + float64(len(hist))
	}
}

type Monitor struct{ notify func(string) }

func (m *Monitor) CheckAndNotify(holdings []*Holding) {
	for _, holding := range holdings {
		price, quoteErr := feed.Quote(holding.Symbol)
		if quoteErr != nil {
			holding.Unchecked = fmt.Sprintf("price source did not answer: %v", quoteErr)
			continue
		}
		hist, historyErr := feed.History(holding.Symbol)
		if historyErr != nil {
			holding.Unchecked = fmt.Sprintf("price source did not answer: %v", historyErr)
			continue
		}
		holding.Price = price + float64(len(hist))
	}
	var b strings.Builder
	for _, h := range holdings {
		if h.Unchecked != "" {
			b.WriteString(h.Symbol + ": " + h.Unchecked + "\n")
		}
	}
	m.notify(b.String())
}

func Selected(addrs []string) []string {
	selected := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if _, err := parseAddr(addr); err != nil {
			// rows in another spelling are kept as they are
			selected = append(selected, addr)
			continue
		}
		selected = append(selected, normalize(addr))
	}
	return selected
}

func CheckAll(holdings []*Holding, syms []string) map[string]float64 {
	prices, err := quotes(syms)
	if err != nil {
		for _, holding := range holdings {
			holding.Unchecked = fmt.Sprintf("price source did not answer: %v", err)
		}
	}
	return prices
}

func CheckAllByIndex(holdings []Holding, syms []string) map[string]float64 {
	prices, err := quotes(syms)
	if err != nil {
		for i := range holdings {
			holdings[i].Unchecked = "price source did not answer: " + err.Error()
		}
	}
	return prices
}

func Report(addrs []string) []string {
	var out []string
	for _, addr := range addrs {
		if _, err := parseAddr(addr); err != nil {
			out = append(out, addr+" (not a known address)")
			continue
		}
		out = append(out, addr)
	}
	return out
}

func DropInLoop(holdings []*Holding) {
	for _, holding := range holdings {
		price, err := quote(holding.Symbol)
		if err != nil { // WANT
			continue
		}
		holding.Price = price
	}
}

func LoopWritesNothingOfIt(holdings []*Holding, syms []string) map[string]float64 {
	prices, err := quotes(syms)
	if err != nil { // WANT
		for _, holding := range holdings {
			holding.Price = 0
		}
	}
	return prices
}

func UnreadSlice(addrs []string) int {
	var skipped []string
	good := 0
	for _, addr := range addrs {
		if _, err := parseAddr(addr); err != nil { // WANT
			skipped = append(skipped, addr)
			continue
		}
		good++
	}
	return good
}
`
	var want []string
	for i, line := range strings.Split(code, "\n") {
		if strings.Contains(line, "// WANT") {
			want = append(want, "monitor.go:"+strconv.Itoa(i+1))
		}
	}
	ctx := createSilentErrorContext(t, "monitor.go", code)
	found := patterntest.FoundLines(NewSilentErrorHandlingRule().AnalyzeFile(ctx))
	assert.ElementsMatch(t, want, found)
}
