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
