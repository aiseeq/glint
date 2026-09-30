package duplication

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDuplicateBlockRule())
}

const (
	// minNonTrivialInBlock is how many meaningful lines a window must carry
	// before a repeat of it is worth reporting inside a single file.
	minNonTrivialInBlock = 6
	// defaultBlockSize is how many consecutive lines have to repeat before a
	// copy-paste inside one file is reported.
	defaultBlockSize = 40
)

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
			"Detects duplicate code blocks within the same file (copy-paste detection), one finding per repeated region",
			core.SeverityMedium,
		),
		minBlockSize: defaultBlockSize,
	}
}

// Configure configures the rule
func (r *DuplicateBlockRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	size, err := blockSizeSetting(settings, defaultBlockSize, minNonTrivialInBlock)
	if err != nil {
		return fmt.Errorf("%s: %w", r.Name(), err)
	}
	r.minBlockSize = size
	return nil
}

// AnalyzeFile checks for duplicate code blocks
func (r *DuplicateBlockRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !isDuplicationCandidate(ctx) || len(ctx.Lines) < r.minBlockSize*2 {
		return nil
	}

	// Find duplicate blocks using sliding window
	return r.findDuplicateWindows(ctx, normalizeFileLines(ctx.Lines))
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

	substance := newWindowSubstance(normalized, isTrivialLine)
	for i := 0; i <= len(normalized)-r.minBlockSize; i++ {
		if substance.trivial[i] || substance.isTrivial(i, r.minBlockSize, minNonTrivialInBlock) {
			continue
		}

		hash := hashWindow(lineHashes, i, r.minBlockSize)
		if _, seen := starts[hash]; !seen {
			hashOrder = append(hashOrder, hash)
		}
		starts[hash] = append(starts[hash], i)
	}

	var matches []windowMatch
	for _, hash := range hashOrder {
		group := starts[hash]
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
			matches = append(matches, windowMatch{start: repeat, origFile: ctx.RelPath, origStart: first})
			break
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].start < matches[j].start })

	var violations []*core.Violation
	for _, region := range mergeWindowMatches(matches, r.minBlockSize) {
		v := r.CreateViolation(ctx.RelPath, region.start+1,
			"Duplicate block ("+strconv.Itoa(region.end-region.start+1)+" lines) - same as lines "+
				strconv.Itoa(region.origStart+1)+"-"+strconv.Itoa(region.origEnd+1))
		v.WithCode(ctx.GetLine(region.start + 1))
		v.WithSuggestion("Extract duplicate code into a shared function")
		v.WithContext("first_start", region.origStart+1)
		v.WithContext("first_end", region.origEnd+1)
		v.WithContext("block_size", r.minBlockSize)

		violations = append(violations, v)
	}

	return violations
}
