package duplication

import (
	"crypto/sha256"
	"encoding/hex"
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

	// Shared state for cross-file detection
	mu           sync.Mutex
	blockHashes  map[string][]BlockLocation // hash -> locations
	reported     map[string]bool            // hash -> already reported
	initialized  bool
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
		blockHashes:  make(map[string][]BlockLocation),
		reported:     make(map[string]bool),
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

// Reset clears the shared state (call before new analysis run)
func (r *CrossFileDuplicateRule) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blockHashes = make(map[string][]BlockLocation)
	r.reported = make(map[string]bool)
	r.initialized = false
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
		normalized[i] = r.normalizeLine(line)
	}

	// Collect blocks from this file and check for duplicates
	return r.processFile(ctx, normalized)
}

func (r *CrossFileDuplicateRule) processFile(ctx *core.FileContext, normalized []string) []*core.Violation {
	var violations []*core.Violation
	localBlocks := make(map[string]BlockLocation)

	// Collect all blocks from this file
	for i := 0; i <= len(normalized)-r.minBlockSize; i++ {
		if r.isTrivialLine(normalized[i]) {
			continue
		}

		window := normalized[i : i+r.minBlockSize]
		if r.isWindowTrivial(window) {
			continue
		}

		hash := r.hashWindow(window)

		// Store block location for this file
		if _, exists := localBlocks[hash]; !exists {
			localBlocks[hash] = BlockLocation{
				File:      ctx.RelPath,
				StartLine: i + 1,
				EndLine:   i + r.minBlockSize,
				Content:   window,
			}
		}
	}

	// Now check against global registry and update it
	r.mu.Lock()
	defer r.mu.Unlock()

	for hash, block := range localBlocks {
		existingLocs := r.blockHashes[hash]

		// Check if this block exists in OTHER files
		for _, existing := range existingLocs {
			if existing.File != ctx.RelPath && !r.reported[hash] {
				// Found duplicate in different file!
				// Verify content matches (hash collision protection)
				if r.windowsMatch(block.Content, existing.Content) {
					r.reported[hash] = true

					v := r.CreateViolation(ctx.RelPath, block.StartLine,
						"Cross-file duplicate: same as "+existing.File+":"+r.itoa(existing.StartLine)+"-"+r.itoa(existing.EndLine))
					v.WithCode(ctx.GetLine(block.StartLine))
					v.WithSuggestion("Extract to shared package or utility function")
					v.WithContext("original_file", existing.File)
					v.WithContext("original_start", existing.StartLine)
					v.WithContext("original_end", existing.EndLine)
					v.WithContext("block_size", r.minBlockSize)

					violations = append(violations, v)
				}
			}
		}

		// Add this block to global registry
		r.blockHashes[hash] = append(existingLocs, block)
	}

	return violations
}

func (r *CrossFileDuplicateRule) windowsMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (r *CrossFileDuplicateRule) hashWindow(window []string) string {
	h := sha256.New()
	for _, line := range window {
		h.Write([]byte(line))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (r *CrossFileDuplicateRule) isWindowTrivial(window []string) bool {
	nonTrivialCount := 0
	totalLength := 0

	for _, line := range window {
		totalLength += len(line)
		if !r.isTrivialLine(line) {
			nonTrivialCount++
		}
	}

	// Need at least half of lines to be non-trivial and decent total length
	minNonTrivial := len(window) / 2
	if minNonTrivial < 4 {
		minNonTrivial = 4
	}
	return nonTrivialCount < minNonTrivial || totalLength < 150
}

func (r *CrossFileDuplicateRule) normalizeLine(line string) string {
	normalized := strings.TrimSpace(line)
	for strings.Contains(normalized, "  ") {
		normalized = strings.ReplaceAll(normalized, "  ", " ")
	}
	return normalized
}

func (r *CrossFileDuplicateRule) isTrivialLine(line string) bool {
	if line == "" {
		return true
	}

	trivial := []string{
		"{", "}", "(", ")", "[", "]",
		"else {", "} else {", "} else if",
		"default:", "break", "continue",
		"return", "return nil", "return false", "return true",
		"return err", "return result", "return v",
		"if err != nil {", "if !ok {", "if ok {",
		"defer func() {", "}()",
	}

	for _, t := range trivial {
		if line == t {
			return true
		}
	}

	if strings.HasSuffix(line, ",") && len(line) < 50 {
		return true
	}

	if strings.Contains(line, "`json:") || strings.Contains(line, "`xml:") {
		return true
	}

	if len(line) < 15 {
		return true
	}

	if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
		return true
	}

	return false
}

func (r *CrossFileDuplicateRule) itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
