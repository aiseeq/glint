package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// After slog.SetDefault the standard log package writes through slog at
// INFO: log.Fatal in an entry point reports a fatal startup failure as an
// INFO line, below any ERROR alerting. Entry points are otherwise free to use
// log; one that never installs a slog default keeps that freedom.
func TestNonCanonicalLoggerStdlibLogAfterSlogDefault(t *testing.T) {
	files := map[string]string{
		"cmd/server/main.go": `package main

import (
	"log"
	"os"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err) // want non-canonical-logger
	}
	os.Exit(0)
}
`,
		"cmd/server/logger.go": `package main

import (
	"log/slog"
	"os"
)

func run() error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	return nil
}
`,
		"cmd/seed/main.go": `package main

import (
	"fmt"
	"log"
)

func main() {
	fmt.Println("seeding")
	log.Fatalf("connect: %v", 1)
}
`,
	}
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule := NewNonCanonicalLoggerRule()
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, rule.AnalyzeFile(ctx)...)
	}
	assert.Equal(t, wantedLines(files, "non-canonical-logger"), foundLines(violations))
}
