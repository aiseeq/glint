package duplication

import (
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDuplicateBlockRule())
}

// minNonTrivialInBlock is how many meaningful lines a window must carry before
// a repeat of it is worth reporting inside a single file.
const minNonTrivialInBlock = 6

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
		minBlockSize: 40,
	}
}

// Configure configures the rule
func (r *DuplicateBlockRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.minBlockSize = r.GetIntSetting("min_block_size", 40)
	return nil
}

// AnalyzeFile checks for duplicate code blocks
func (r *DuplicateBlockRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsGoFile() && !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || ctx.IsTestFile() || len(ctx.Lines) < r.minBlockSize*2 {
		return nil
	}

	rawStringLines := rawStringLineSet(ctx.Lines)

	// Normalize all lines
	normalized := make([]string, len(ctx.Lines))
	for i, line := range ctx.Lines {
		if rawStringLines[i] {
			normalized[i] = ""
			continue
		}
		normalized[i] = normalizeLine(line)
	}

	// Find duplicate blocks using sliding window
	return r.findDuplicateWindows(ctx, normalized)
}

func rawStringLineSet(lines []string) map[int]bool {
	result := make(map[int]bool)
	inRawString := false
	for i, line := range lines {
		if strings.Count(line, "`")%2 == 1 {
			result[i] = true
			inRawString = !inRawString
			continue
		}
		if inRawString {
			result[i] = true
		}
	}
	return result
}

// findDuplicateWindows hashes every candidate window once and groups equal
// windows by hash, so the cost is linear in the number of windows. Comparing
// each window against every later one instead made large files quadratic.
func (r *DuplicateBlockRule) findDuplicateWindows(ctx *core.FileContext, normalized []string) []*core.Violation {
	lineHashes := hashLines(normalized)

	// Starts of equal windows, in ascending order; hashOrder keeps the
	// first-seen order so that findings do not depend on map iteration.
	starts := make(map[windowHash][]int)
	var hashOrder []windowHash

	for i := 0; i <= len(normalized)-r.minBlockSize; i++ {
		if isTrivialLine(normalized[i]) {
			continue
		}
		window := normalized[i : i+r.minBlockSize]
		if isWindowTrivial(window, minNonTrivialInBlock, isTrivialLine) {
			continue
		}

		hash := hashWindow(lineHashes, i, r.minBlockSize)
		if _, seen := starts[hash]; !seen {
			hashOrder = append(hashOrder, hash)
		}
		starts[hash] = append(starts[hash], i)
	}

	var violations []*core.Violation
	for _, hash := range hashOrder {
		group := starts[hash]
		if len(group) < 2 {
			continue
		}
		first := group[0]
		window := normalized[first : first+r.minBlockSize]
		for _, repeat := range group[1:] {
			// Only report non-overlapping repetitions.
			if repeat < first+r.minBlockSize {
				continue
			}
			if !windowsMatch(window, normalized[repeat:repeat+r.minBlockSize]) {
				continue
			}

			v := r.CreateViolation(ctx.RelPath, repeat+1,
				"Duplicate block ("+strconv.Itoa(r.minBlockSize)+" lines) - same as lines "+
					strconv.Itoa(first+1)+"-"+strconv.Itoa(first+r.minBlockSize))
			v.WithCode(ctx.GetLine(repeat + 1))
			v.WithSuggestion("Extract duplicate code into a shared function")
			v.WithContext("first_start", first+1)
			v.WithContext("first_end", first+r.minBlockSize)
			v.WithContext("block_size", r.minBlockSize)

			violations = append(violations, v)
			break
		}
	}

	return violations
}
