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
		minBlockSize: 10, // Higher threshold for cross-file (more significant)
		firstSeen:    make(map[windowHash]BlockLocation),
		reported:     make(map[windowHash]bool),
	}
}

// Configure configures the rule
func (r *CrossFileDuplicateRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.minBlockSize = r.GetIntSetting("min_block_size", 10)
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
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if len(ctx.Lines) < r.minBlockSize {
		return nil
	}

	// Normalize lines
	normalized := make([]string, len(ctx.Lines))
	for i, line := range ctx.Lines {
		normalized[i] = normalizeLine(line)
	}

	// Collect blocks from this file and check for duplicates
	return r.processFile(ctx, normalized)
}

func (r *CrossFileDuplicateRule) processFile(ctx *core.FileContext, normalized []string) []*core.Violation {
	blocks := r.collectBlocks(ctx, normalized)

	r.mu.Lock()
	defer r.mu.Unlock()

	var violations []*core.Violation
	for _, block := range blocks {
		existing, seen := r.firstSeen[block.hash]
		if !seen {
			r.firstSeen[block.hash] = block.location
			continue
		}
		// A file is analyzed once, so a previously stored block of the same
		// hash always comes from another file.
		if r.reported[block.hash] || !windowsMatch(block.location.Content, existing.Content) {
			continue
		}
		r.reported[block.hash] = true

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

// isCrossFileTrivialLine extends the shared triviality check with lines that
// legitimately repeat across files: imports, type switches, and the standard
// HTTP handler boilerplate.
func isCrossFileTrivialLine(line string) bool {
	if isTrivialLine(line) {
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
