package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shadowCases are checked both with and without type information: shadowing
// is lexical, the file alone decides it.
var shadowCases = []struct {
	name      string
	code      string
	wantLines []int
}{
	{
		name: "if-init variable stays in the if statement",
		code: `package main

import "fmt"

func example(m map[string]int, k string, cond bool) {
	if val, found := m[k]; found {
		fmt.Println(val)
	}
	if cond {
		val := 3
		fmt.Println(val)
	}
}
`,
	},
	{
		name: "shadow inside a switch case",
		code: `package main

import "fmt"

func example(name string, xs []int) {
	switch len(xs) {
	case 1:
		name := "a"
		fmt.Println(name)
	}
	fmt.Println(name)
}
`,
		wantLines: []int{8},
	},
	{
		name: "shadow inside a type switch case",
		code: `package main

import "fmt"

func example(name string, v any) {
	switch v.(type) {
	case int:
		name := "a"
		fmt.Println(name)
	}
	fmt.Println(name)
}
`,
		wantLines: []int{8},
	},
	{
		name: "shadow inside a select case",
		code: `package main

import "fmt"

func example(count int, ch chan int) {
	select {
	case <-ch:
		count := 5
		fmt.Println(count)
	default:
	}
	fmt.Println(count)
}
`,
		wantLines: []int{8},
	},
	{
		name: "shadow inside a goroutine closure",
		code: `package main

import "fmt"

func example(name string) {
	go func() {
		name := "b"
		fmt.Println(name)
	}()
	fmt.Println(name)
}
`,
		wantLines: []int{7},
	},
	{
		name: "copy of the outer variable is the capture idiom",
		code: `package main

import "fmt"

func example(names []string) {
	for _, name := range names {
		name := name
		go func() { fmt.Println(name) }()
	}
}
`,
	},
	{
		name: "err in if-init beside an outer err",
		code: `package main

import "os"

func example(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return nil
}
`,
	},
	{
		name: "outer variable no longer read after the inner declaration",
		code: `package main

import "fmt"

func lookup(primary, fallback map[string]string, key string) string {
	if value, found := primary[key]; found {
		return value
	} else if value := fallback[key]; value != "" {
		return value
	}
	return ""
}

func first(paths []string, configured string) string {
	path := configured
	if path != "" {
		return path
	}
	for _, path := range paths {
		fmt.Println(path)
	}
	return ""
}
`,
	},
	{
		name: "named result shadowed in a branch that returns",
		code: `package main

func parse(raw string) (value string, err error) {
	if raw == "" {
		value, err := fallback()
		return value, err
	}
	return raw, nil
}

func fallback() (string, error) { return "", nil }
`,
	},
	{
		name: "named result shadowed before a bare return",
		code: `package main

func parse(raw string) (value string, err error) {
	if raw == "" {
		value, err := fallback()
		_, _ = value, err
	}
	return
}

func fallback() (string, error) { return "", nil }
`,
		wantLines: []int{5},
	},
	{
		name: "a variable of another type is another thing",
		code: `package main

import "fmt"

func describe(size string, sizes []int) string {
	for _, size := range sizes {
		fmt.Println(size)
	}
	return size
}
`,
	},
	{
		name: "outer variable read after the inner declaration",
		code: `package main

import "fmt"

func load(ids []string) string {
	result := ""
	for _, id := range ids {
		if id != "" {
			result := id
			fmt.Println(result)
		}
	}
	return result
}
`,
		wantLines: []int{9},
	},
	{
		name: "variables of sibling functions do not shadow each other",
		code: `package main

import "fmt"

func first() {
	name := "a"
	fmt.Println(name)
}

func second() {
	name := "b"
	fmt.Println(name)
}
`,
	},
}

func TestShadowVariableUntypedScopes(t *testing.T) {
	for _, tt := range shadowCases {
		t.Run(tt.name, func(t *testing.T) {
			violations := NewShadowVariableRule().AnalyzeFile(createShadowContext(t, "service.go", tt.code))
			assert.Equal(t, tt.wantLines, shadowViolationLines(violations))
		})
	}
}

func TestShadowVariableTypedScopes(t *testing.T) {
	for _, tt := range shadowCases {
		t.Run(tt.name, func(t *testing.T) {
			violations := runRuleOnFiles(t, NewShadowVariableRule(), map[string]string{"service.go": tt.code})
			assert.Equal(t, tt.wantLines, shadowViolationLines(violations))
			for _, v := range violations {
				require.Equal(t, "service.go", v.File)
			}
		})
	}
}

func shadowViolationLines(violations []*core.Violation) []int {
	var lines []int
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	return lines
}
