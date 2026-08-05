package patterns

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestSilentConfigErrorRule_ErrEqNilSwallow(t *testing.T) {
	rule := NewSilentConfigErrorRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name: "inline if err := godotenv.Load(); err == nil - no else",
			code: `package config

import "github.com/joho/godotenv"

func loadEnv() error {
	if err := godotenv.Load("/tmp/.env"); err == nil {
		return nil
	}
	return nil
}`,
			filename:  "config/loader.go",
			wantCount: 1,
		},
		{
			name: "preceding assign + if err == nil - fall-through default",
			code: `package common

func GetBaseURL() string {
	var baseURL string
	cfg, err := LoadUnifiedConfig()
	if err == nil {
		baseURL = cfg.URL
		return baseURL
	}
	baseURL = ""
	return baseURL
}`,
			filename:  "tests/common/base_url.go",
			wantCount: 1,
		},
		{
			name: "inline if err := X(); err == nil WITH error-handling else - ok",
			code: `package config

import "github.com/joho/godotenv"

func loadEnv() error {
	if err := godotenv.Load("/tmp/.env"); err == nil {
		return nil
	} else {
		return fmt.Errorf("load failed: %w", err)
	}
}`,
			filename:  "config/loader.go",
			wantCount: 0,
		},
		{
			name: "canonical err != nil pattern - ok",
			code: `package config

import "github.com/joho/godotenv"

func loadEnv() error {
	if err := godotenv.Load("/tmp/.env"); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	return nil
}`,
			filename:  "config/loader.go",
			wantCount: 0,
		},
		{
			name: "inline if err := godotenv.Load(); nil == err (yoda) - flagged",
			code: `package config

import "github.com/joho/godotenv"

func loadEnv() error {
	if err := godotenv.Load("/tmp/.env"); nil == err {
		return nil
	}
	return nil
}`,
			filename:  "config/loader.go",
			wantCount: 1,
		},
		{
			name: "non-config callee - not flagged",
			code: `package app

func run() {
	if err := someRandomFunc(); err == nil {
		return
	}
}`,
			filename:  "app/run.go",
			wantCount: 0,
		},
		{
			name: "LoadConfig aggregator flagged",
			code: `package tests

func helper() {
	cfg, err := config.LoadConfig()
	if err == nil {
		_ = cfg
	}
}`,
			filename:  "tests/helpers/setup.go",
			wantCount: 1,
		},
		{
			name: "_test.go file skipped",
			code: `package config

func TestLoad(t *testing.T) {
	if err := godotenv.Load("/tmp/.env"); err == nil {
		return
	}
}`,
			filename:  "config/loader_test.go",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.filename, ".", []byte(tt.code), core.DefaultConfig())
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile(tt.filename, []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}
			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d", len(violations), tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s at line %d", v.Message, v.Line)
				}
			}
		})
	}
}

// isErrEqNilCheck обещает сверять имя переменной в условии с err-переменной,
// присвоенной в assign: чужой err из внешней области — не проверка этого err.
func TestIsErrEqNilCheckMatchesAssignedErrVariable(t *testing.T) {
	parseBody := func(t *testing.T, body string) []ast.Stmt {
		t.Helper()
		src := "package p\n\nfunc f() {\n" + body + "\n}\n"
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "p.go", src, 0)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return file.Decls[0].(*ast.FuncDecl).Body.List
	}

	t.Run("same err variable - matches", func(t *testing.T) {
		stmts := parseBody(t, "err := load()\nif err == nil {\n}")
		assign := stmts[0].(*ast.AssignStmt)
		cond := stmts[1].(*ast.IfStmt).Cond
		if !isErrEqNilCheck(cond, assign) {
			t.Error("want true: condition checks the err assigned in assign")
		}
	})

	t.Run("yoda nil == err - matches", func(t *testing.T) {
		stmts := parseBody(t, "err := load()\nif nil == err {\n}")
		assign := stmts[0].(*ast.AssignStmt)
		cond := stmts[1].(*ast.IfStmt).Cond
		if !isErrEqNilCheck(cond, assign) {
			t.Error("want true: nil == err is the same check in reversed order")
		}
	})

	t.Run("different err variable from outer scope - no match", func(t *testing.T) {
		stmts := parseBody(t, "otherErr := load()\nif err == nil {\n}")
		assign := stmts[0].(*ast.AssignStmt)
		cond := stmts[1].(*ast.IfStmt).Cond
		if isErrEqNilCheck(cond, assign) {
			t.Error("want false: condition checks an err the assign did not bind")
		}
	})

	t.Run("non-error variable bound by assign - no match", func(t *testing.T) {
		stmts := parseBody(t, "cfg, err := load()\nif cfg == nil {\n}")
		assign := stmts[0].(*ast.AssignStmt)
		cond := stmts[1].(*ast.IfStmt).Cond
		if isErrEqNilCheck(cond, assign) {
			t.Error("want false: cfg == nil is not an error check")
		}
	})
}

func TestSilentConfigErrorRule_PathGatedBlankAssign(t *testing.T) {
	rule := NewSilentConfigErrorRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name: "_ = godotenv.Load in config path",
			code: `package config

import "github.com/joho/godotenv"

func init() {
	_ = godotenv.Load("/tmp/.env")
}`,
			filename:  "config/loader.go",
			wantCount: 1,
		},
		{
			name: "_ = godotenv.Load outside config path - not flagged",
			code: `package main

import "github.com/joho/godotenv"

func main() {
	_ = godotenv.Load("/tmp/.env")
}`,
			filename:  "cmd/app/main.go",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.filename, ".", []byte(tt.code), core.DefaultConfig())
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile(tt.filename, []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}
			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d", len(violations), tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s at line %d", v.Message, v.Line)
				}
			}
		})
	}
}
