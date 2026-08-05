package duplication

import (
	"strconv"
	"strings"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewCrossFileDuplicateRule())
}

// defaultCrossFileBlockSize is how many consecutive lines have to repeat in
// another file before the copy is reported. Higher than a single line yet lower
// than the within-file threshold: a cross-file copy is significant earlier.
const defaultCrossFileBlockSize = 10

// BlockLocation stores where a code block was found
type BlockLocation struct {
	File      string
	StartLine int
	EndLine   int
	Content   []string
}

// CrossFileDuplicateRule detects duplicate code blocks across different files
type CrossFileDuplicateRule struct {
	*rules.BaseRule
	minBlockSize int

	// Shared state for cross-file detection. Only the first location of each
	// block is kept: it is the one every later file is reported against, and
	// keeping every occurrence made memory grow with the whole project.
	mu        sync.Mutex
	firstSeen map[windowHash]BlockLocation
	reported  map[windowHash]bool
}

// NewCrossFileDuplicateRule creates the rule
func NewCrossFileDuplicateRule() *CrossFileDuplicateRule {
	return &CrossFileDuplicateRule{
		BaseRule: rules.NewBaseRule(
			"cross-file-duplicate",
			"duplication",
			"Detects duplicate code blocks across different files",
			core.SeverityHigh,
		),
		minBlockSize: defaultCrossFileBlockSize,
		firstSeen:    make(map[windowHash]BlockLocation),
		reported:     make(map[windowHash]bool),
	}
}

// Configure configures the rule
func (r *CrossFileDuplicateRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.minBlockSize = r.GetIntSetting("min_block_size", defaultCrossFileBlockSize)
	return nil
}

// ResetState clears the blocks collected so far. The check flow calls it before
// each project root so that findings never depend on a previous run.
func (r *CrossFileDuplicateRule) ResetState() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.firstSeen = make(map[windowHash]BlockLocation)
	r.reported = make(map[windowHash]bool)
}

// AnalyzeFile collects blocks and detects cross-file duplicates
func (r *CrossFileDuplicateRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !isDuplicationCandidate(ctx) || ctx.IsTestFile() {
		return nil
	}

	if len(ctx.Lines) < r.minBlockSize {
		return nil
	}

	// Collect blocks from this file and check for duplicates
	return r.processFile(ctx, normalizeFileLines(ctx.Lines))
}

func (r *CrossFileDuplicateRule) processFile(ctx *core.FileContext, normalized []string) []*core.Violation {
	blocks := r.collectBlocks(ctx, normalized)

	r.mu.Lock()
	defer r.mu.Unlock()

	var violations []*core.Violation
	// -1 rather than 0: a duplicate may legitimately start on the first line.
	reportedThrough := -1
	for _, block := range blocks {
		existing, seen := r.firstSeen[block.hash]
		if !seen {
			r.firstSeen[block.hash] = block.location
			continue
		}
		// Windows slide one line at a time, so a long copied region matches at
		// every offset inside it, and a region longer than the window matches in
		// consecutive pieces. Report the region once, not once per window.
		if block.location.StartLine <= reportedThrough+1 {
			reportedThrough = max(reportedThrough, block.location.EndLine)
			continue
		}
		// A file is analyzed once, so a previously stored block of the same
		// hash always comes from another file.
		if r.reported[block.hash] || !windowsMatch(block.location.Content, existing.Content) {
			continue
		}
		r.reported[block.hash] = true
		reportedThrough = block.location.EndLine

		v := r.CreateViolation(ctx.RelPath, block.location.StartLine,
			"Cross-file duplicate: same as "+existing.File+":"+
				strconv.Itoa(existing.StartLine)+"-"+strconv.Itoa(existing.EndLine))
		v.WithCode(ctx.GetLine(block.location.StartLine))
		v.WithSuggestion("Extract to shared package or utility function")
		v.WithContext("original_file", existing.File)
		v.WithContext("original_start", existing.StartLine)
		v.WithContext("original_end", existing.EndLine)
		v.WithContext("block_size", r.minBlockSize)

		violations = append(violations, v)
	}

	return violations
}

// hashedBlock is one candidate window of the file being analyzed.
type hashedBlock struct {
	hash     windowHash
	location BlockLocation
}

// collectBlocks returns the file's candidate windows in ascending line order,
// keeping the first occurrence of each distinct window. Ordering by line — not
// by map iteration — is what makes the reported findings reproducible.
func (r *CrossFileDuplicateRule) collectBlocks(ctx *core.FileContext, normalized []string) []hashedBlock {
	lineHashes := hashLines(normalized)
	seen := make(map[windowHash]bool)
	var blocks []hashedBlock

	for i := 0; i <= len(normalized)-r.minBlockSize; i++ {
		if isCrossFileTrivialLine(normalized[i]) {
			continue
		}

		window := normalized[i : i+r.minBlockSize]
		minNonTrivial := max(len(window)/2, 4)
		if isWindowTrivial(window, minNonTrivial, isCrossFileTrivialLine) {
			continue
		}

		hash := hashWindow(lineHashes, i, r.minBlockSize)
		if seen[hash] {
			continue
		}
		seen[hash] = true
		blocks = append(blocks, hashedBlock{
			hash: hash,
			location: BlockLocation{
				File:      ctx.RelPath,
				StartLine: i + 1,
				EndLine:   i + r.minBlockSize,
				Content:   window,
			},
		})
	}

	return blocks
}

// isDuplicationCandidate reports whether the file is in a language whose blocks
// this rule compares. TypeScript and JavaScript duplicate as readily as Go, and
// a frontend is where copied components accumulate.
func isDuplicationCandidate(ctx *core.FileContext) bool {
	return ctx.IsGoFile() || ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile()
}

// isCrossFileTrivialLine extends the shared triviality check with lines that
// legitimately repeat across files: imports, type switches, and the standard
// HTTP handler boilerplate.
func isCrossFileTrivialLine(line string) bool {
	if isTrivialLine(line) || isFrontendBoilerplate(line) {
		return true
	}

	// Imports are expected to be similar across files.
	if strings.HasPrefix(line, `"`) || strings.HasPrefix(line, "import") {
		return true
	}

	// Type switches are often duplicated on purpose to avoid import cycles.
	if strings.HasPrefix(line, "switch ") && strings.Contains(line, ".(type)") {
		return true
	}
	if strings.HasPrefix(line, "case ") && strings.Contains(line, ":") {
		return true
	}
	if strings.HasPrefix(line, "return ") &&
		(strings.Contains(line, ", true") || strings.Contains(line, ", false")) {
		return true
	}

	switch line {
	case `return "", false`, `return "", true`:
		return true
	}

	// Common HTTP patterns - expected to repeat across handlers.
	if strings.Contains(line, `Header().Set("Content-Type"`) ||
		strings.Contains(line, "json.NewEncoder") ||
		strings.Contains(line, "json.Unmarshal") ||
		strings.Contains(line, "WriteHeader") {
		return true
	}

	// Common interface/type declarations.
	return strings.HasPrefix(line, "type ") && strings.HasSuffix(line, " interface {")
}

// isFrontendBoilerplate covers the lines a TypeScript or JSX file repeats by
// construction: closing a callback, exporting, opening a component.
func isFrontendBoilerplate(line string) bool {
	switch line {
	case "});", "})", "};", "});)", "return (", ");", "export {", "export default {",
		"} catch (error) {", "} catch (err) {", "} finally {", "'use client';", `"use client";`:
		return true
	}
	if strings.HasPrefix(line, "export ") && strings.HasSuffix(line, "from") {
		return true
	}
	// JSX opening or closing a wrapper element carries no logic of its own.
	if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.Contains(line, "=") {
		return true
	}
	return false
}
