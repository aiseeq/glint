package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestMainReturnAfterErrorRule_Metadata(t *testing.T) {
	rule := NewMainReturnAfterErrorRule()
	assert.Equal(t, "main-return-after-error", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

// Репро с ревью ipop 2026-08 (№27): шесть cmd-утилит логировали ошибку и
// выходили из main обычным return — процесс отчитывался кодом 0, скрипты и
// люди считали провалившийся запуск успешным.
func TestMainReturnAfterErrorRule_Detection(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   int
	}{
		{
			name: "log then bare return in error branch",
			source: `package main

import "log"

func run() error { return nil }

func main() {
	if err := run(); err != nil {
		log.Printf("Error: %v", err)
		return
	}
	log.Println("done")
}
`,
			want: 1,
		},
		{
			name: "silent bare return in error branch",
			source: `package main

func run() error { return nil }

func main() {
	if err := run(); err != nil {
		return
	}
}
`,
			want: 1,
		},
		{
			name: "os.Exit(1) in error branch is honest",
			source: `package main

import (
	"log"
	"os"
)

func run() error { return nil }

func main() {
	if err := run(); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}
`,
			want: 0,
		},
		{
			name: "log.Fatal in error branch is honest",
			source: `package main

import "log"

func run() error { return nil }

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
`,
			want: 0,
		},
		{
			name: "panic in error branch is honest",
			source: `package main

func run() error { return nil }

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}
`,
			want: 0,
		},
		{
			name: "non-error condition is not the pattern",
			source: `package main

import "os"

func main() {
	if len(os.Args) > 5 {
		return
	}
}
`,
			want: 0,
		},
		{
			name: "helper functions outside main are not checked",
			source: `package main

import "log"

func helper() {
	if err := work(); err != nil {
		log.Printf("Error: %v", err)
		return
	}
}

func work() error { return nil }

func main() { helper() }
`,
			want: 0,
		},
	}

	rule := NewMainReturnAfterErrorRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := rulestest.GoFile(t, "main.go", tt.source)
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.want)
		})
	}
}

// Библиотечный пакет с функцией main-омонимом правило не трогает.
func TestMainReturnAfterErrorRule_IgnoresNonMainPackage(t *testing.T) {
	source := `package tool

import "log"

func run() error { return nil }

func main() {
	if err := run(); err != nil {
		log.Printf("Error: %v", err)
		return
	}
}
`
	ctx := rulestest.GoFile(t, "tool.go", source)
	assert.Empty(t, NewMainReturnAfterErrorRule().AnalyzeFile(ctx))
}
