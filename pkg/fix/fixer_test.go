package fix

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestInterfaceAnyFixer(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "simple interface{}",
			line:     "func foo(x interface{}) {}",
			expected: "func foo(x any) {}",
		},
		{
			name:     "map with interface{}",
			line:     "data map[string]interface{}",
			expected: "data map[string]any",
		},
		{
			name:     "return interface{}",
			line:     "func bar() interface{} {",
			expected: "func bar() any {",
		},
		{
			name:     "multiple interface{}",
			line:     "func baz(a interface{}, b interface{}) {}",
			expected: "func baz(a any, b interface{}) {}", // Only first is replaced
		},
	}

	fixer := NewInterfaceAnyFixer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &core.FileContext{
				Path:  "/test/file.go",
				Lines: []string{tt.line},
			}

			v := &core.Violation{
				Rule: "interface-any",
				File: "/test/file.go",
				Line: 1,
			}

			fix := fixer.GenerateFix(ctx, v)
			if fix == nil {
				t.Fatal("Expected fix, got nil")
			}

			if fix.OldText != "interface{}" {
				t.Errorf("Expected OldText 'interface{}', got '%s'", fix.OldText)
			}

			if fix.NewText != "any" {
				t.Errorf("Expected NewText 'any', got '%s'", fix.NewText)
			}
		})
	}
}

func TestInterfaceAnyFixerCanFix(t *testing.T) {
	fixer := NewInterfaceAnyFixer()

	tests := []struct {
		name     string
		rule     string
		expected bool
	}{
		{"interface-any rule", "interface-any", true},
		{"other rule", "other-rule", false},
		{"empty rule", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &core.Violation{Rule: tt.rule}
			if got := fixer.CanFix(v); got != tt.expected {
				t.Errorf("CanFix() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDeprecatedIoutilFixer(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		expectedOld string
		expectedNew string
	}{
		{
			name:        "ioutil.ReadFile",
			line:        "data, err := ioutil.ReadFile(path)",
			expectedOld: "ioutil.ReadFile",
			expectedNew: "os.ReadFile",
		},
		{
			name:        "ioutil.WriteFile",
			line:        "err = ioutil.WriteFile(path, data, 0644)",
			expectedOld: "ioutil.WriteFile",
			expectedNew: "os.WriteFile",
		},
		{
			name:        "ioutil.ReadAll",
			line:        "data, err := ioutil.ReadAll(reader)",
			expectedOld: "ioutil.ReadAll",
			expectedNew: "io.ReadAll",
		},
		{
			name:        "ioutil.NopCloser",
			line:        "rc := ioutil.NopCloser(reader)",
			expectedOld: "ioutil.NopCloser",
			expectedNew: "io.NopCloser",
		},
		{
			name:        "ioutil.TempFile",
			line:        "f, err := ioutil.TempFile(dir, pattern)",
			expectedOld: "ioutil.TempFile",
			expectedNew: "os.CreateTemp",
		},
	}

	fixer := NewDeprecatedIoutilFixer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &core.FileContext{
				Path:  "/test/file.go",
				Lines: []string{tt.line},
			}

			v := &core.Violation{
				Rule: "deprecated-ioutil",
				File: "/test/file.go",
				Line: 1,
			}

			fix := fixer.GenerateFix(ctx, v)
			if fix == nil {
				t.Fatal("Expected fix, got nil")
			}

			if fix.OldText != tt.expectedOld {
				t.Errorf("Expected OldText '%s', got '%s'", tt.expectedOld, fix.OldText)
			}

			if fix.NewText != tt.expectedNew {
				t.Errorf("Expected NewText '%s', got '%s'", tt.expectedNew, fix.NewText)
			}
		})
	}
}

func TestBoolCompareFixer(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		expectedOld string
		expectedNew string
	}{
		{
			name:        "x == true",
			line:        "if x == true {",
			expectedOld: "x == true",
			expectedNew: "x",
		},
		{
			name:        "x == false",
			line:        "if x == false {",
			expectedOld: "x == false",
			expectedNew: "!x",
		},
		{
			name:        "true == x",
			line:        "if true == x {",
			expectedOld: "true == x",
			expectedNew: "x",
		},
		{
			name:        "false == x",
			line:        "if false == x {",
			expectedOld: "false == x",
			expectedNew: "!x",
		},
		{
			name:        "x != true",
			line:        "if x != true {",
			expectedOld: "x != true",
			expectedNew: "!x",
		},
		{
			name:        "x != false",
			line:        "if x != false {",
			expectedOld: "x != false",
			expectedNew: "x",
		},
		{
			name:        "isEnabled == true",
			line:        "if isEnabled == true {",
			expectedOld: "isEnabled == true",
			expectedNew: "isEnabled",
		},
		{
			name:        "user.IsActive == true",
			line:        "if user.IsActive == true {",
			expectedOld: "user.IsActive == true",
			expectedNew: "user.IsActive",
		},
	}

	fixer := NewBoolCompareFixer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &core.FileContext{
				Path:  "/test/file.go",
				Lines: []string{tt.line},
			}

			v := &core.Violation{
				Rule: "bool-compare",
				File: "/test/file.go",
				Line: 1,
			}

			fix := fixer.GenerateFix(ctx, v)
			if fix == nil {
				t.Fatalf("Expected fix for line '%s', got nil", tt.line)
			}

			if fix.OldText != tt.expectedOld {
				t.Errorf("Expected OldText '%s', got '%s'", tt.expectedOld, fix.OldText)
			}

			if fix.NewText != tt.expectedNew {
				t.Errorf("Expected NewText '%s', got '%s'", tt.expectedNew, fix.NewText)
			}
		})
	}
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
	engine := NewEngine(DefaultRegistry, true, false)

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
	engine := NewEngine(DefaultRegistry, true, false)

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
