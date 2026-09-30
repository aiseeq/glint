package duplication

import (
	"fmt"
	"path/filepath"
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

// minCrossFileNonTrivial is how many meaningful lines a window must carry at
// least; it is also the smallest block size that can ever be reported.
const minCrossFileNonTrivial = 4

// blockOrigin is where a window was seen first: the file, its 0-based start
// line and the window's verification hash. No text is kept: holding the
// normalized lines of every analyzed file made memory grow with the project.
type blockOrigin struct {
	file  string
	start int
	check windowHash
}

// CrossFileDuplicateRule detects duplicate code blocks across different files
type CrossFileDuplicateRule struct {
	*rules.BaseRule
	minBlockSize int

	// Shared state for cross-file detection. Only the first location of each
	// window is kept: every later copy is reported against it.
	mu        sync.Mutex
	firstSeen map[windowHash]blockOrigin
}

// NewCrossFileDuplicateRule creates the rule
func NewCrossFileDuplicateRule() *CrossFileDuplicateRule {
	return &CrossFileDuplicateRule{
		BaseRule: rules.NewBaseRule(
			"cross-file-duplicate",
			"duplication",
			"Detects duplicate code blocks across different files: every later copy of a block is reported once per copied region against the first file it was seen in",
			core.SeverityHigh,
		),
		minBlockSize: defaultCrossFileBlockSize,
		firstSeen:    make(map[windowHash]blockOrigin),
	}
}

// Configure configures the rule
func (r *CrossFileDuplicateRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	size, err := blockSizeSetting(settings, defaultCrossFileBlockSize, minCrossFileNonTrivial)
	if err != nil {
		return fmt.Errorf("%s: %w", r.Name(), err)
	}
	r.minBlockSize = size
	return nil
}

// ResetState clears the blocks collected so far. The check flow calls it before
// each project root so that findings never depend on a previous run.
func (r *CrossFileDuplicateRule) ResetState() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.firstSeen = make(map[windowHash]blockOrigin)
}

// AnalyzeFile collects blocks and detects cross-file duplicates
func (r *CrossFileDuplicateRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !isDuplicationCandidate(ctx) {
		return nil
	}

	if len(ctx.Lines) < r.minBlockSize {
		return nil
	}

	// Collect blocks from this file and check for duplicates
	return r.processFile(ctx, normalizeFileLines(ownNameMasked(ctx)))
}

// minMaskedNameLen keeps short script names such as "a.sh" unmasked: replacing
// every "a" in the text would compare letters, not code.
const minMaskedNameLen = 4

// ownNameMasked returns the lines of a shell script with the script's own name
// replaced by one placeholder. A wrapper is copied for the next tool by renaming
// the tool throughout, and the file is named after that tool: masking the name
// lets the copy match its original, while other files keep their text.
func ownNameMasked(ctx *core.FileContext) []string {
	if !ctx.IsShellFile() {
		return ctx.Lines
	}
	stem := strings.TrimSuffix(filepath.Base(ctx.Path), ".sh")
	if len(stem) < minMaskedNameLen {
		return ctx.Lines
	}
	masked := make([]string, len(ctx.Lines))
	for i, line := range ctx.Lines {
		masked[i] = strings.ReplaceAll(line, stem, "<script>")
	}
	return masked
}

// processFile compares the file's windows with the first occurrence of each
// window in the files analyzed before it, records the windows seen for the
// first time, and reports each copied region once.
func (r *CrossFileDuplicateRule) processFile(ctx *core.FileContext, normalized []string) []*core.Violation {
	blocks := r.collectBlocks(normalized)

	r.mu.Lock()
	var matches []windowMatch
	for _, block := range blocks {
		origin, seen := r.firstSeen[block.hash]
		if !seen {
			r.firstSeen[block.hash] = blockOrigin{file: ctx.RelPath, start: block.start, check: block.check}
			continue
		}
		// A file is analyzed once, so a stored window of the same hash always
		// comes from another file.
		if origin.check != block.check {
			continue
		}
		matches = append(matches, windowMatch{start: block.start, origFile: origin.file, origStart: origin.start})
	}
	r.mu.Unlock()

	var violations []*core.Violation
	for _, region := range mergeWindowMatches(matches, r.minBlockSize) {
		line := region.start + 1
		v := r.CreateViolation(ctx.RelPath, line,
			"Cross-file duplicate (lines "+strconv.Itoa(line)+"-"+strconv.Itoa(region.end+1)+"): same as "+
				region.origFile+":"+strconv.Itoa(region.origStart+1)+"-"+strconv.Itoa(region.origEnd+1))
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Extract to shared package or utility function")
		v.WithContext("original_file", region.origFile)
		v.WithContext("original_start", region.origStart+1)
		v.WithContext("original_end", region.origEnd+1)
		v.WithContext("block_size", r.minBlockSize)
		violations = append(violations, v)
	}
	return violations
}

// hashedBlock is one candidate window of the file being analyzed: its 0-based
// start line, its hash and its verification hash.
type hashedBlock struct {
	start int
	hash  windowHash
	check windowHash
}

// collectBlocks returns the file's candidate windows in ascending line order,
// keeping the first occurrence of each distinct window. Ordering by line — not
// by map iteration — is what makes the reported findings reproducible.
func (r *CrossFileDuplicateRule) collectBlocks(normalized []string) []hashedBlock {
	lineHashes := hashLines(normalized)
	lineChecks := checkLines(normalized)
	substance := newWindowSubstance(normalized, isCrossFileTrivialLine)
	minNonTrivial := max(r.minBlockSize/2, minCrossFileNonTrivial)
	seen := make(map[windowHash]bool)
	var blocks []hashedBlock

	for i := 0; i <= len(normalized)-r.minBlockSize; i++ {
		if substance.trivial[i] || substance.isTrivial(i, r.minBlockSize, minNonTrivial) {
			continue
		}

		hash := hashWindow(lineHashes, i, r.minBlockSize)
		if seen[hash] {
			continue
		}
		seen[hash] = true
		blocks = append(blocks, hashedBlock{start: i, hash: hash, check: checkWindow(lineChecks, i, r.minBlockSize)})
	}

	return blocks
}

// isDuplicationCandidate reports whether the file is in a language whose blocks
// the duplication rules compare. TypeScript and JavaScript duplicate as readily
// as Go, and a frontend is where copied components accumulate; wrapper scripts
// copy launch blocks that then drift apart. Test files are compared too: a
// fixture copied into several tests is fixed several times.
func isDuplicationCandidate(ctx *core.FileContext) bool {
	return ctx.IsGoFile() || ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile() || ctx.IsShellFile()
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
