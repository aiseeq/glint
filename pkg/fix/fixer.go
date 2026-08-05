package fix

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// Fixer interface for rules that support auto-fixing
type Fixer interface {
	// RuleName returns the rule this fixer is for
	RuleName() string

	// CanFix returns true if this fixer can fix the given violation
	CanFix(v *core.Violation) bool

	// GenerateFix returns the edits that fix a violation, empty if it cannot.
	// A fix often needs more than one edit: rewriting a call also means adding
	// the import it now needs.
	GenerateFix(ctx *core.FileContext, v *core.Violation) []*Fix
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

// fixedFilePermissions is the mode used when a fixed file has to be created.
const fixedFilePermissions = 0o644

// Result represents the outcome of applying fixes to one file.
type Result struct {
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
}

// NewEngine creates a new fix engine
func NewEngine(registry *Registry, dryRun bool) *Engine {
	return &Engine{
		registry: registry,
		dryRun:   dryRun,
	}
}

// WorkingTreeState describes what can be recovered if a fix goes wrong.
type WorkingTreeState int

const (
	// WorkingTreeClean means every fix can be reverted with git.
	WorkingTreeClean WorkingTreeState = iota
	// WorkingTreeDirty means fixes would mix into uncommitted work.
	WorkingTreeDirty
	// WorkingTreeUntracked means the path is not inside a git repository, so
	// nothing can be reverted.
	WorkingTreeUntracked
)

// CheckWorkingTree reports whether fixes applied under projectRoot could be
// reverted. Being outside a repository is a distinct answer, not an error:
// the caller decides whether to require --force for it.
func (e *Engine) CheckWorkingTree(projectRoot string) (WorkingTreeState, error) {
	inside := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	inside.Dir = projectRoot
	if err := inside.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return WorkingTreeUntracked, nil
		}
		return WorkingTreeUntracked, fmt.Errorf("run git in %q: %w", projectRoot, err)
	}

	status := exec.Command("git", "status", "--porcelain")
	status.Dir = projectRoot
	output, err := status.Output()
	if err != nil {
		return WorkingTreeUntracked, fmt.Errorf("git status in %q: %w", projectRoot, err)
	}
	if len(strings.TrimSpace(string(output))) > 0 {
		return WorkingTreeDirty, nil
	}
	return WorkingTreeClean, nil
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

		for _, fix := range fixer.GenerateFix(ctx, v) {
			if fix != nil {
				fixes = append(fixes, fix)
			}
		}
	}

	return dedupeFixes(fixes)
}

// dedupeFixes drops textually identical edits. Several violations in one file
// legitimately generate the same import edit; applying it twice used to leave
// the file uncompilable.
func dedupeFixes(fixes []*Fix) []*Fix {
	type editKey struct {
		file               string
		startLine, endLine int
		oldText, newText   string
	}
	seen := make(map[editKey]bool, len(fixes))
	deduped := fixes[:0]
	for _, fix := range fixes {
		key := editKey{fix.File, fix.StartLine, fix.EndLine, fix.OldText, fix.NewText}
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, fix)
	}
	return deduped
}

// ApplyFixes applies fixes to files
func (e *Engine) ApplyFixes(fixes []*Fix) []Result {
	// Group fixes by file
	byFile := make(map[string][]*Fix)
	for _, fix := range fixes {
		byFile[fix.File] = append(byFile[fix.File], fix)
	}

	results := make([]Result, 0, len(byFile))
	for _, file := range sortedFileNames(byFile) {
		results = append(results, e.applyToFile(file, byFile[file]))
	}

	return results
}

// sortedFileNames keeps the order of reported files stable: map iteration
// would shuffle both the applied results and the preview between runs.
func sortedFileNames(byFile map[string][]*Fix) []string {
	files := make([]string, 0, len(byFile))
	for file := range byFile {
		files = append(files, file)
	}
	sort.Strings(files)
	return files
}

func (e *Engine) applyToFile(file string, fixes []*Fix) Result {
	result := Result{
		File:  file,
		Fixes: fixes,
	}

	content, err := os.ReadFile(file)
	if err != nil {
		result.Error = fmt.Errorf("read file: %w", err)
		return result
	}

	lines := strings.Split(string(content), "\n")

	// Apply from the bottom up, so that earlier fixes keep their line numbers.
	sortedFixes := make([]*Fix, len(fixes))
	copy(sortedFixes, fixes)
	sort.SliceStable(sortedFixes, func(i, j int) bool {
		return sortedFixes[i].StartLine > sortedFixes[j].StartLine
	})

	// Apply each fix. A fix that does not match the file anymore is collected
	// and reported: silently dropping it made "Applied N fixes" unverifiable.
	var unapplied []*Fix
	for _, fix := range sortedFixes {
		if e.applyFix(fix, &lines) {
			result.FixesApplied++
		} else {
			unapplied = append(unapplied, fix)
		}
	}
	if len(unapplied) > 0 {
		names := make([]string, 0, len(unapplied))
		for _, fix := range unapplied {
			names = append(names, fmt.Sprintf("%s (line %d)", fix.RuleName, fix.StartLine))
		}
		result.Error = fmt.Errorf("%d fix(es) no longer match the file and were not applied: %s",
			len(unapplied), strings.Join(names, ", "))
	}

	if e.dryRun {
		return result
	}

	// Write back to file
	newContent := strings.Join(lines, "\n")
	if err := os.WriteFile(file, []byte(newContent), fixedFilePermissions); err != nil {
		result.Error = fmt.Errorf("write file: %w", err)
		return result
	}

	return result
}

// applyFix applies one fix to the line slice and reports whether it matched.
func (e *Engine) applyFix(fix *Fix, lines *[]string) bool {
	if fix.StartLine < 1 || fix.StartLine > len(*lines) {
		return false
	}

	// Multi-line replacement: only an exact match may be replaced. Matching
	// just the first line allowed overwriting a range another fix had already
	// changed.
	if fix.EndLine > fix.StartLine {
		if fix.EndLine > len(*lines) {
			return false
		}
		startIdx := fix.StartLine - 1
		endIdx := fix.EndLine - 1
		if strings.Join((*lines)[startIdx:endIdx+1], "\n") != fix.OldText {
			return false
		}
		newSlice := append([]string{}, (*lines)[:startIdx]...)
		newSlice = append(newSlice, strings.Split(fix.NewText, "\n")...)
		newSlice = append(newSlice, (*lines)[endIdx+1:]...)
		*lines = newSlice
		return true
	}

	lineIdx := fix.StartLine - 1
	line := (*lines)[lineIdx]

	if fix.StartCol > 0 && fix.EndCol > 0 {
		// Column-specific replacement, verified against OldText when present
		startIdx := fix.StartCol - 1
		endIdx := fix.EndCol - 1
		if startIdx >= len(line) || endIdx > len(line) {
			return false
		}
		if fix.OldText != "" && line[startIdx:endIdx] != fix.OldText {
			return false
		}
		(*lines)[lineIdx] = line[:startIdx] + fix.NewText + line[endIdx:]
		return true
	}

	// Full text replacement within line
	if !strings.Contains(line, fix.OldText) {
		return false
	}
	(*lines)[lineIdx] = strings.Replace(line, fix.OldText, fix.NewText, 1)
	return true
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
	fmt.Fprintf(&sb, "PROPOSED FIXES (%d changes in %d files):\n\n", len(fixes), len(byFile))

	for _, file := range sortedFileNames(byFile) {
		fileFixes := byFile[file]
		relPath := file
		if cwd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(cwd, file); err == nil {
				relPath = rel
			}
		}

		for _, fix := range fileFixes {
			fmt.Fprintf(&sb, "  %s:%d [%s]\n", relPath, fix.StartLine, fix.RuleName)
			fmt.Fprintf(&sb, "    - %s\n", fix.OldText)
			fmt.Fprintf(&sb, "    + %s\n", fix.NewText)
			sb.WriteString("\n")
		}
	}

	if e.dryRun {
		sb.WriteString("Run with --dry-run=false to apply changes.\n")
	}

	return sb.String()
}
