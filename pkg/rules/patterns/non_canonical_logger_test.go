package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestNonCanonicalLoggerRule(t *testing.T) {
	rule := NewNonCanonicalLoggerRule()

	tests := []struct {
		name          string
		path          string
		code          string
		expectedCount int
	}{
		{
			name: "log.Printf in production code",
			path: "/src/backend/service.go",
			code: `package service
import "log"
func Foo() {
	log.Printf("hello %s", "world")
}`,
			expectedCount: 1,
		},
		{
			name: "log.Println in production code",
			path: "/src/backend/service.go",
			code: `package service
import "log"
func Foo() { log.Println("x") }`,
			expectedCount: 1,
		},
		{
			name: "log.Fatal in production code",
			path: "/src/backend/service.go",
			code: `package service
import "log"
func Foo() { log.Fatal("boom") }`,
			expectedCount: 1,
		},
		{
			name: "fmt.Println used as diagnostic output",
			path: "/src/backend/handler.go",
			code: `package handler
import "fmt"
func H() { fmt.Println("debug") }`,
			expectedCount: 1,
		},
		{
			name: "fmt.Printf used as diagnostic output",
			path: "/src/backend/handler.go",
			code: `package handler
import "fmt"
func H() { fmt.Printf("v=%d\n", 1) }`,
			expectedCount: 1,
		},
		{
			name: "fmt.Errorf is NOT flagged",
			path: "/src/backend/handler.go",
			code: `package handler
import "fmt"
func H() error { return fmt.Errorf("bad %s", "thing") }`,
			expectedCount: 0,
		},
		{
			name: "fmt.Sprintf is NOT flagged",
			path: "/src/backend/handler.go",
			code: `package handler
import "fmt"
func H() string { return fmt.Sprintf("x=%d", 1) }`,
			expectedCount: 0,
		},
		{
			name: "zap import in production code",
			path: "/src/backend/handler.go",
			code: `package handler
import "go.uber.org/zap"
var _ = zap.NewNop()`,
			expectedCount: 1,
		},
		{
			name: "logrus import in production code",
			path: "/src/backend/handler.go",
			code: `package handler
import log "github.com/sirupsen/logrus"
var _ = log.New()`,
			expectedCount: 1,
		},
		{
			name: "zerolog import in production code",
			path: "/src/backend/handler.go",
			code: `package handler
import "github.com/rs/zerolog"
var _ = zerolog.Nop()`,
			expectedCount: 1,
		},
		{
			name: "test file is skipped (log.Printf allowed)",
			path: "/src/backend/service_test.go",
			code: `package service
import "log"
func TestFoo() { log.Printf("t") }`,
			expectedCount: 0,
		},
		{
			name: "cmd/*/main.go is skipped",
			path: "/src/cmd/jwt-helper/main.go",
			code: `package main
import "fmt"
func main() { fmt.Println("ok") }`,
			expectedCount: 0,
		},
		{
			name: "root main.go is skipped",
			path: "/src/main.go",
			code: `package main
import "fmt"
func main() { fmt.Println("ok") }`,
			expectedCount: 0,
		},
		{
			name: "tools package main stdout is skipped",
			path: "/src/tools/report/output.go",
			code: `package main
import "fmt"
func report() { fmt.Println("complete") }`,
			expectedCount: 0,
		},
		{
			name: "nolint:non-canonical-logger opt-out is honored",
			path: "/src/backend/service.go",
			code: `package service
import "log"
func Foo() {
	log.Printf("shh") //nolint:non-canonical-logger // by design
}`,
			expectedCount: 0,
		},
		{
			name: "both forbidden import AND call are flagged",
			path: "/src/backend/handler.go",
			code: `package handler
import "go.uber.org/zap"
import "log"
func H() {
	log.Printf("x")
	_ = zap.NewNop()
}`,
			expectedCount: 2, // 1 import + 1 call
		},
		{
			name: "canonical slog is NOT flagged",
			path: "/src/backend/handler.go",
			code: `package handler
import "log/slog"
func H() { slog.Info("ok") }`,
			expectedCount: 0,
		},
		{
			// The project's own logger package is also called log — it is the canonical one.
			name: "project's own log package is NOT flagged",
			path: "/src/app/app.go",
			code: `package app
import "example.com/misc/internal/log"
func Serve() { log.Printf("started") }`,
			expectedCount: 0,
		},
		{
			name: "aliased stdlib log is flagged",
			path: "/src/app/app.go",
			code: `package app
import stdlog "log"
func Serve() { stdlog.Printf("started") }`,
			expectedCount: 1,
		},
		{
			name: "local variable named log is NOT the log package",
			path: "/src/app/app.go",
			code: `package app
func Serve(log Logger) { log.Printf("started") }`,
			expectedCount: 0,
		},
		{
			name: "zerolog subpackage import is flagged",
			path: "/src/app/app.go",
			code: `package app
import "github.com/rs/zerolog/log"
func Serve() { log.Info().Msg("x") }`,
			expectedCount: 1,
		},
		{
			name: "zapcore import is flagged",
			path: "/src/app/app.go",
			code: `package app
import "go.uber.org/zap/zapcore"
var level = zapcore.InfoLevel`,
			expectedCount: 1,
		},
		{
			name: "module with a forbidden prefix but another name is NOT flagged",
			path: "/src/app/app.go",
			code: `package app
import "go.uber.org/zapx"
var x = zapx.X`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projectRoot := "/src"
			ctx := core.NewFileContext(tt.path, projectRoot, []byte(tt.code), core.DefaultConfig())

			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile(tt.path, []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}

			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

func TestNonCanonicalLoggerNonGoFile(t *testing.T) {
	rule := NewNonCanonicalLoggerRule()
	ctx := core.NewFileContext("/src/file.ts", "/src", []byte(`import log from "log"`), core.DefaultConfig())
	assert.Empty(t, rule.AnalyzeFile(ctx))
}
