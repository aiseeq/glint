package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A constructor that replaces a nil dependency with a package default hides
// the wiring mistake: the caller that passed nil is never told. A default for
// an option, or a nil dependency replaced loudly, is not this.
func TestConstructorSwallowsNilDep_SilentDefault(t *testing.T) {
	const source = `package svc

import (
	"log/slog"
	"net/http"
	"time"
)

type Repo struct{}

type Calculator struct {
	repo   *Repo
	logger *slog.Logger
}

func NewCalculator(repo *Repo, logger *slog.Logger) *Calculator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Calculator{repo: repo, logger: logger}
}

type Fetcher struct{ client *http.Client }

func NewFetcher(client *http.Client) *Fetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return &Fetcher{client: client}
}

type Options struct{ Timeout time.Duration }

func NewPoller(opts *Options, logger *slog.Logger) *Calculator {
	if opts == nil {
		opts = &Options{Timeout: time.Second}
	}
	if logger == nil {
		logger = slog.Default()
		logger.Warn("no logger passed, using the default one")
	}
	return &Calculator{logger: logger}
}
`
	ctx := rulestest.GoFile(t, "svc/svc.go", source)
	assert.Equal(t, []int{17, 26}, violationLines(NewConstructorSwallowsNilDepRule().AnalyzeFile(ctx)))
}
