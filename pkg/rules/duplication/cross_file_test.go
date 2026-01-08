package duplication

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestCrossFileDuplicateRule(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	rule.minBlockSize = 8 // Match the test data

	// Substantial duplicate block (10 meaningful lines)
	duplicateBlock := []string{
		"func processData(input []byte, config *Config) (*Result, error) {",
		"    if input == nil || len(input) == 0 {",
		"        return nil, errors.New(\"input cannot be empty\")",
		"    }",
		"    result := &Result{Data: make([]byte, len(input))}",
		"    for i, b := range input {",
		"        result.Data[i] = b ^ config.XORMask",
		"    }",
		"    result.Checksum = calculateChecksum(result.Data)",
		"    return result, nil",
	}

	// File 1 (note: avoid /test/ in path as it triggers IsTestFile)
	ctx1 := &core.FileContext{
		Path:    "/project/pkg/processor/data.go",
		RelPath: "pkg/processor/data.go",
		Lines:   append([]string{"package processor", ""}, duplicateBlock...),
	}

	// File 2 - contains same duplicate
	ctx2 := &core.FileContext{
		Path:    "/project/pkg/transformer/data.go",
		RelPath: "pkg/transformer/data.go",
		Lines:   append([]string{"package transformer", ""}, duplicateBlock...),
	}

	// Reset rule state
	rule.Reset()

	// Process file 1 - should find no violations yet
	violations1 := rule.AnalyzeFile(ctx1)
	if len(violations1) != 0 {
		t.Errorf("Expected 0 violations for first file, got %d", len(violations1))
	}

	// Process file 2 - should detect duplicate from file 1
	violations2 := rule.AnalyzeFile(ctx2)
	if len(violations2) == 0 {
		t.Error("Expected to find cross-file duplicate")
	}

	// Verify violation details
	if len(violations2) > 0 {
		v := violations2[0]
		if v.Rule != "cross-file-duplicate" {
			t.Errorf("Expected rule 'cross-file-duplicate', got '%s'", v.Rule)
		}
		if v.Context["original_file"] != "pkg/processor/data.go" {
			t.Errorf("Expected original_file 'pkg/processor/data.go', got '%s'", v.Context["original_file"])
		}
	}
}

func TestCrossFileDuplicateRule_NoDuplicate(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	rule.minBlockSize = 5

	ctx1 := &core.FileContext{
		Path:    "/project/pkg/a/file1.go",
		RelPath: "pkg/a/file1.go",
		Lines: []string{
			"package main",
			"func foo() {",
			"    a := 1",
			"    b := 2",
			"    c := 3",
			"    fmt.Println(a + b + c)",
			"}",
		},
	}

	ctx2 := &core.FileContext{
		Path:    "/project/pkg/b/file2.go",
		RelPath: "pkg/b/file2.go",
		Lines: []string{
			"package main",
			"func bar() {",
			"    x := 10",
			"    y := 20",
			"    z := 30",
			"    fmt.Println(x * y * z)",
			"}",
		},
	}

	rule.Reset()

	violations1 := rule.AnalyzeFile(ctx1)
	violations2 := rule.AnalyzeFile(ctx2)

	if len(violations1) != 0 || len(violations2) != 0 {
		t.Error("Expected no violations for different code")
	}
}

func TestCrossFileDuplicateRule_SkipsTests(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	rule.Reset()

	ctx := &core.FileContext{
		Path:    "/test/file_test.go",
		RelPath: "file_test.go",
		Lines: []string{
			"package main",
			"func TestFoo(t *testing.T) {",
			"    // test code",
			"}",
		},
	}

	violations := rule.AnalyzeFile(ctx)
	if violations != nil {
		t.Error("Expected nil for test files")
	}
}

func TestCrossFileDuplicateRule_Reset(t *testing.T) {
	rule := NewCrossFileDuplicateRule()

	// Add some state
	rule.blockHashes["test"] = []BlockLocation{{File: "test.go"}}
	rule.reported["test"] = true

	// Reset should clear
	rule.Reset()

	if len(rule.blockHashes) != 0 {
		t.Error("Expected blockHashes to be empty after Reset")
	}
	if len(rule.reported) != 0 {
		t.Error("Expected reported to be empty after Reset")
	}
}
