package fix

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// A path outside a repository is a state the caller has to react to, not a
// failure: reporting it as an error made `glint fix` unusable there.
func TestCheckWorkingTreeReportsPathOutsideRepository(t *testing.T) {
	engine := NewEngine(NewRegistry(), true)

	state, err := engine.CheckWorkingTree(t.TempDir())
	require.NoError(t, err)
	require.Equal(t, WorkingTreeUntracked, state)
}

func TestCheckWorkingTreeDetectsDirtyTree(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "glint@example.com"},
		{"config", "user.name", "glint"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		require.NoError(t, cmd.Run(), "git %v", args)
	}

	engine := NewEngine(NewRegistry(), true)
	state, err := engine.CheckWorkingTree(root)
	require.NoError(t, err)
	require.Equal(t, WorkingTreeClean, state)

	require.NoError(t, os.WriteFile(filepath.Join(root, "a.go"), []byte("package a\n"), 0o644))
	state, err = engine.CheckWorkingTree(root)
	require.NoError(t, err)
	require.Equal(t, WorkingTreeDirty, state)
}

func interfaceAnyViolation(line, column int) *core.Violation {
	return &core.Violation{Rule: "interface-any", File: "rule.go", Line: line, Column: column}
}

func TestInterfaceAnyFixer(t *testing.T) {
	ctx := fixerContext(t, `package sample

func foo(x interface{}) {}

var data map[string]interface{}

func bar() interface{} { return "interface{}" }

func baz(a interface{}, b interface{ }) {}
`)

	tests := []struct {
		name         string
		line, column int
		oldText      string
	}{
		{"parameter", 3, 12, "interface{}"},
		{"map value", 5, 21, "interface{}"},
		{"result", 7, 12, "interface{}"},
		{"second of a line", 9, 27, "interface{ }"},
	}

	fixer := NewInterfaceAnyFixer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixes := fixer.GenerateFix(ctx, interfaceAnyViolation(tt.line, tt.column))
			require.Len(t, fixes, 1)
			assert.Equal(t, tt.oldText, fixes[0].OldText)
			assert.Equal(t, "any", fixes[0].NewText)
			assert.Equal(t, tt.column, fixes[0].StartCol)
		})
	}

	// The column of the string literal holds no interface type.
	assert.Empty(t, fixer.GenerateFix(ctx, interfaceAnyViolation(7, 33)))
}

func TestInterfaceAnyFixerCanFix(t *testing.T) {
	fixer := NewInterfaceAnyFixer()

	tests := []struct {
		name      string
		violation *core.Violation
		expected  bool
	}{
		{"interface-any rule", interfaceAnyViolation(1, 5), true},
		{"no column", &core.Violation{Rule: "interface-any", Line: 1}, false},
		{"other rule", &core.Violation{Rule: "other-rule", Line: 1, Column: 5}, false},
		{"empty rule", &core.Violation{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fixer.CanFix(tt.violation); got != tt.expected {
				t.Errorf("CanFix() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func boolCompareViolation(line, column int) *core.Violation {
	return &core.Violation{Rule: "bool-compare", File: "rule.go", Line: line, Column: column}
}

func TestBoolCompareFixer(t *testing.T) {
	ctx := fixerContext(t, `package sample

type user struct{ IsActive bool }

func f(x, isEnabled, trueSeen bool, u user, n int, p *bool) {
	_ = x == true
	_ = x == false
	_ = true == x
	_ = false == x
	_ = x != true
	_ = x != false
	_ = isEnabled == true
	_ = u.IsActive == true
	_ = x == trueSeen || isEnabled == false
	_ = n > 0 == false
	_ = *p == false
	_ = !x == false
}
`)

	tests := []struct {
		name         string
		line, column int
		expectedOld  string
		expectedNew  string
	}{
		{"x == true", 6, 6, "x == true", "x"},
		{"x == false", 7, 6, "x == false", "!x"},
		{"true == x", 8, 6, "true == x", "x"},
		{"false == x", 9, 6, "false == x", "!x"},
		{"x != true", 10, 6, "x != true", "!x"},
		{"x != false", 11, 6, "x != false", "x"},
		{"isEnabled == true", 12, 6, "isEnabled == true", "isEnabled"},
		{"u.IsActive == true", 13, 6, "u.IsActive == true", "u.IsActive"},
		{"name starting with true", 14, 23, "isEnabled == false", "!isEnabled"},
		{"operator operand", 15, 6, "n > 0 == false", "!(n > 0)"},
		{"dereference", 16, 6, "*p == false", "!*p"},
		{"negation undone", 17, 6, "!x == false", "x"},
	}

	fixer := NewBoolCompareFixer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixes := fixer.GenerateFix(ctx, boolCompareViolation(tt.line, tt.column))
			require.Len(t, fixes, 1)
			assert.Equal(t, tt.expectedOld, fixes[0].OldText)
			assert.Equal(t, tt.expectedNew, fixes[0].NewText)
		})
	}

	// x == trueSeen compares two variables: nothing to simplify.
	assert.Empty(t, fixer.GenerateFix(ctx, boolCompareViolation(14, 6)))
}

func TestRegistry(t *testing.T) {
	registry := NewRegistry()

	// Test empty registry
	if _, ok := registry.Get("interface-any"); ok {
		t.Error("Expected Get to return false for empty registry")
	}

	// Register a fixer
	fixer := NewInterfaceAnyFixer()
	registry.Register(fixer)

	// Test Get
	if got, ok := registry.Get("interface-any"); !ok {
		t.Error("Expected Get to return true after registration")
	} else if got != fixer {
		t.Error("Expected Get to return registered fixer")
	}

	// Test All
	all := registry.All()
	if len(all) != 1 {
		t.Errorf("Expected 1 fixer, got %d", len(all))
	}
}

func TestDefaultRegistry(t *testing.T) {
	// Test that default registry has all fixers registered
	fixers := []string{"interface-any", "deprecated-ioutil", "bool-compare"}

	for _, name := range fixers {
		if _, ok := DefaultRegistry.Get(name); !ok {
			t.Errorf("Expected fixer '%s' to be registered in DefaultRegistry", name)
		}
	}
}

func TestEnginePreview(t *testing.T) {
	engine := NewEngine(DefaultRegistry, true)

	fixes := []*Fix{
		{
			File:      "/test/file.go",
			StartLine: 10,
			OldText:   "interface{}",
			NewText:   "any",
			RuleName:  "interface-any",
		},
		{
			File:      "/test/file.go",
			StartLine: 20,
			OldText:   "ioutil.ReadFile",
			NewText:   "os.ReadFile",
			RuleName:  "deprecated-ioutil",
		},
	}

	preview := engine.Preview(fixes)

	if preview == "" {
		t.Error("Expected non-empty preview")
	}

	// Check that preview contains expected content
	if !contains(preview, "PROPOSED FIXES") {
		t.Error("Expected preview to contain 'PROPOSED FIXES'")
	}
	if !contains(preview, "interface{}") {
		t.Error("Expected preview to contain 'interface{}'")
	}
	if !contains(preview, "any") {
		t.Error("Expected preview to contain 'any'")
	}
}

func TestEnginePreviewEmpty(t *testing.T) {
	engine := NewEngine(DefaultRegistry, true)

	preview := engine.Preview(nil)

	if preview != "No fixes available.\n" {
		t.Errorf("Expected 'No fixes available.\\n', got '%s'", preview)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
