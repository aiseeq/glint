package fix

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// Fixer interface for rules that support auto-fixing
type Fixer interface {
	// RuleName returns the rule this fixer is for
	RuleName() string

	// CanFix returns true if this fixer can fix the given violation
	CanFix(v *core.Violation) bool

	// GenerateFix returns the fix for a violation (nil if can't fix)
	GenerateFix(ctx *core.FileContext, v *core.Violation) *Fix
}

// Fix represents a single code fix
type Fix struct {
	File      string // File path
	StartLine int    // Start line (1-based)
	EndLine   int    // End line (1-based, same as StartLine for single-line)
	StartCol  int    // Start column (1-based, 0 = entire line)
	EndCol    int    // End column (1-based, 0 = entire line)
	OldText   string // Text to replace
	NewText   string // Replacement text
	Message   string // Description of the fix
	RuleName  string // Rule that triggered this fix
	Violation *core.Violation
}

// FixResult represents the result of applying fixes
type FixResult struct {
	File         string
	FixesApplied int
	Fixes        []*Fix
	Error        error
}

// Registry holds all registered fixers
type Registry struct {
	fixers map[string]Fixer
}

// DefaultRegistry is the global fixer registry
var DefaultRegistry = NewRegistry()

// NewRegistry creates a new fixer registry
func NewRegistry() *Registry {
	return &Registry{
		fixers: make(map[string]Fixer),
	}
}

// Register adds a fixer to the registry
func (r *Registry) Register(f Fixer) {
	r.fixers[f.RuleName()] = f
}

// Get returns a fixer for the given rule name
func (r *Registry) Get(ruleName string) (Fixer, bool) {
	f, ok := r.fixers[ruleName]
	return f, ok
}

// All returns all registered fixers
func (r *Registry) All() map[string]Fixer {
	return r.fixers
}

// Engine applies fixes to files
type Engine struct {
	registry *Registry
	dryRun   bool
	verbose  bool
}

// NewEngine creates a new fix engine
func NewEngine(registry *Registry, dryRun, verbose bool) *Engine {
	return &Engine{
		registry: registry,
		dryRun:   dryRun,
		verbose:  verbose,
	}
}

// CheckGitStatus checks for uncommitted changes
func (e *Engine) CheckGitStatus(projectRoot string) (bool, error) {
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = projectRoot
	output, err := cmd.Output()
	if err != nil {
		// Not a git repo or git not available - skip check
		return false, nil
	}
	return len(strings.TrimSpace(string(output))) > 0, nil
}

// GenerateFixes generates fixes for violations without applying them
func (e *Engine) GenerateFixes(violations []*core.Violation, contexts map[string]*core.FileContext) []*Fix {
	var fixes []*Fix

	for _, v := range violations {
		fixer, ok := e.registry.Get(v.Rule)
		if !ok {
			continue
		}

		if !fixer.CanFix(v) {
			continue
		}

		ctx, ok := contexts[v.File]
		if !ok {
			continue
		}

		if fix := fixer.GenerateFix(ctx, v); fix != nil {
			fixes = append(fixes, fix)
		}
	}

	return fixes
}

// ApplyFixes applies fixes to files
func (e *Engine) ApplyFixes(fixes []*Fix) []FixResult {
	// Group fixes by file
	byFile := make(map[string][]*Fix)
	for _, fix := range fixes {
		byFile[fix.File] = append(byFile[fix.File], fix)
	}

	var results []FixResult

	for file, fileFixes := range byFile {
		result := e.applyToFile(file, fileFixes)
		results = append(results, result)
	}

	return results
}

func (e *Engine) applyToFile(file string, fixes []*Fix) FixResult {
	result := FixResult{
		File:  file,
		Fixes: fixes,
	}

	content, err := os.ReadFile(file)
	if err != nil {
		result.Error = fmt.Errorf("read file: %w", err)
		return result
	}

	lines := strings.Split(string(content), "\n")

	// Sort fixes by line in reverse order (apply from bottom to top)
	sortedFixes := make([]*Fix, len(fixes))
	copy(sortedFixes, fixes)
	for i := 0; i < len(sortedFixes)-1; i++ {
		for j := i + 1; j < len(sortedFixes); j++ {
			if sortedFixes[i].StartLine < sortedFixes[j].StartLine {
				sortedFixes[i], sortedFixes[j] = sortedFixes[j], sortedFixes[i]
			}
		}
	}

	// Apply each fix
	for _, fix := range sortedFixes {
		if fix.StartLine < 1 || fix.StartLine > len(lines) {
			continue
		}

		// Handle multi-line fixes
		if fix.EndLine > fix.StartLine && fix.EndLine <= len(lines) {
			startIdx := fix.StartLine - 1
			endIdx := fix.EndLine - 1

			// Get the old text from file
			oldLines := lines[startIdx : endIdx+1]
			oldText := strings.Join(oldLines, "\n")

			// Verify it matches (or at least starts the same)
			if oldText == fix.OldText || strings.HasPrefix(oldText, strings.Split(fix.OldText, "\n")[0]) {
				// Replace the lines
				newLines := strings.Split(fix.NewText, "\n")
				// Build new lines slice: before + new + after
				newSlice := append([]string{}, lines[:startIdx]...)
				newSlice = append(newSlice, newLines...)
				newSlice = append(newSlice, lines[endIdx+1:]...)
				lines = newSlice
				result.FixesApplied++
			}
			continue
		}

		lineIdx := fix.StartLine - 1
		line := lines[lineIdx]

		// Apply the fix
		if fix.StartCol > 0 && fix.EndCol > 0 {
			// Column-specific replacement
			startIdx := fix.StartCol - 1
			endIdx := fix.EndCol - 1
			if startIdx < len(line) && endIdx <= len(line) {
				newLine := line[:startIdx] + fix.NewText + line[endIdx:]
				lines[lineIdx] = newLine
				result.FixesApplied++
			}
		} else {
			// Full text replacement within line
			if strings.Contains(line, fix.OldText) {
				lines[lineIdx] = strings.Replace(line, fix.OldText, fix.NewText, 1)
				result.FixesApplied++
			}
		}
	}

	if e.dryRun {
		return result
	}

	// Write back to file
	newContent := strings.Join(lines, "\n")
	if err := os.WriteFile(file, []byte(newContent), 0644); err != nil {
		result.Error = fmt.Errorf("write file: %w", err)
		return result
	}

	return result
}

// Preview formats fixes for display
func (e *Engine) Preview(fixes []*Fix) string {
	if len(fixes) == 0 {
		return "No fixes available.\n"
	}

	// Group by file
	byFile := make(map[string][]*Fix)
	for _, fix := range fixes {
		byFile[fix.File] = append(byFile[fix.File], fix)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("PROPOSED FIXES (%d changes in %d files):\n\n", len(fixes), len(byFile)))

	for file, fileFixes := range byFile {
		relPath := file
		if cwd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(cwd, file); err == nil {
				relPath = rel
			}
		}

		for _, fix := range fileFixes {
			sb.WriteString(fmt.Sprintf("  %s:%d [%s]\n", relPath, fix.StartLine, fix.RuleName))
			sb.WriteString(fmt.Sprintf("    - %s\n", fix.OldText))
			sb.WriteString(fmt.Sprintf("    + %s\n", fix.NewText))
			sb.WriteString("\n")
		}
	}

	if e.dryRun {
		sb.WriteString("Run without --dry-run to apply changes.\n")
	}

	return sb.String()
}
