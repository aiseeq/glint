package duplication

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDuplicateBlockRule())
}

// DuplicateBlockRule detects duplicate code blocks within the same file
type DuplicateBlockRule struct {
	*rules.BaseRule
	minBlockSize int
}

// NewDuplicateBlockRule creates the rule
func NewDuplicateBlockRule() *DuplicateBlockRule {
	return &DuplicateBlockRule{
		BaseRule: rules.NewBaseRule(
			"duplicate-block",
			"duplication",
			"Detects duplicate code blocks within the same file (copy-paste detection)",
			core.SeverityMedium,
		),
		minBlockSize: 8, // Minimum 8 consecutive lines
	}
}

// Configure configures the rule
func (r *DuplicateBlockRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.minBlockSize = r.GetIntSetting("min_block_size", 6)
	return nil
}

// AnalyzeFile checks for duplicate code blocks
func (r *DuplicateBlockRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.IsTestFile() || len(ctx.Lines) < r.minBlockSize*2 {
		return nil
	}

	// Normalize all lines
	normalized := make([]string, len(ctx.Lines))
	for i, line := range ctx.Lines {
		normalized[i] = r.normalizeLine(line)
	}

	// Find duplicate blocks using sliding window
	return r.findDuplicateWindows(ctx, normalized)
}

func (r *DuplicateBlockRule) findDuplicateWindows(ctx *core.FileContext, normalized []string) []*core.Violation {
	var violations []*core.Violation
	reported := make(map[string]bool) // hash -> reported

	// Use sliding window of minBlockSize lines
	for i := 0; i <= len(normalized)-r.minBlockSize; i++ {
		// Skip if starting on trivial line
		if r.isTrivialLine(normalized[i]) {
			continue
		}

		// Get window hash
		window := normalized[i : i+r.minBlockSize]
		if r.isWindowTrivial(window) {
			continue
		}

		hash := r.hashWindow(window)

		// Look for duplicate windows after this one
		for j := i + r.minBlockSize; j <= len(normalized)-r.minBlockSize; j++ {
			otherWindow := normalized[j : j+r.minBlockSize]
			otherHash := r.hashWindow(otherWindow)

			if hash == otherHash && !reported[hash] {
				// Verify exact match (hash collision protection)
				if r.windowsMatch(window, otherWindow) {
					reported[hash] = true

					v := r.CreateViolation(ctx.RelPath, j+1,
						"Duplicate block ("+r.itoa(r.minBlockSize)+" lines) - same as lines "+
							r.itoa(i+1)+"-"+r.itoa(i+r.minBlockSize))
					v.WithCode(ctx.GetLine(j + 1))
					v.WithSuggestion("Extract duplicate code into a shared function")
					v.WithContext("first_start", i+1)
					v.WithContext("first_end", i+r.minBlockSize)
					v.WithContext("block_size", r.minBlockSize)

					violations = append(violations, v)
				}
			}
		}
	}

	return violations
}

func (r *DuplicateBlockRule) windowsMatch(a, b []string) bool {
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

func (r *DuplicateBlockRule) hashWindow(window []string) string {
	h := sha256.New()
	for _, line := range window {
		h.Write([]byte(line))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (r *DuplicateBlockRule) isWindowTrivial(window []string) bool {
	nonTrivialCount := 0
	totalLength := 0

	for _, line := range window {
		totalLength += len(line)
		if !r.isTrivialLine(line) {
			nonTrivialCount++
		}
	}

	// Window is trivial if:
	// - Less than 6 non-trivial lines
	// - Total content less than 150 characters
	return nonTrivialCount < 6 || totalLength < 150
}

func (r *DuplicateBlockRule) normalizeLine(line string) string {
	normalized := strings.TrimSpace(line)
	for strings.Contains(normalized, "  ") {
		normalized = strings.ReplaceAll(normalized, "  ", " ")
	}
	return normalized
}

func (r *DuplicateBlockRule) isTrivialLine(line string) bool {
	if line == "" {
		return true
	}

	// Common trivial patterns
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

	// Skip lines ending with comma (likely struct fields)
	if strings.HasSuffix(line, ",") && len(line) < 50 {
		return true
	}

	// Skip struct field definitions (have JSON/XML tags)
	if strings.Contains(line, "`json:") || strings.Contains(line, "`xml:") {
		return true
	}

	// Skip short lines
	if len(line) < 15 {
		return true
	}

	// Skip comment lines
	if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
		return true
	}

	return false
}

func (r *DuplicateBlockRule) itoa(n int) string {
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
