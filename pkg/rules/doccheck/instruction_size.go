package doccheck

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewInstructionSizeRule())
}

const (
	defaultInstructionMaxBytes = 16384
	// Claude Code keeps the first 5000 tokens of a skill after compacting
	// the context.
	defaultSkillMaxChars = 12000
)

// InstructionSizeRule limits the size of the Claude Code instruction files:
// CLAUDE.md, CLAUDE.local.md and .claude/rules/*.md are loaded into every
// session, and a skill is cut to its start after the context is compacted.
type InstructionSizeRule struct {
	*rules.BaseRule
	maxBytes int
	maxChars int
}

// NewInstructionSizeRule creates the rule
func NewInstructionSizeRule() *InstructionSizeRule {
	return &InstructionSizeRule{
		BaseRule: rules.NewBaseRule(
			"instruction-size",
			"documentation",
			"Detects a Claude Code instruction file near or over its size limit: CLAUDE.md, CLAUDE.local.md and .claude/rules/*.md from max_bytes (16384) on, skills/*/SKILL.md from max_chars (12000 characters) on, with 80% named as the reference to shrink to; block-level HTML comments are not counted, Claude Code strips them",
			core.SeverityMedium,
		),
		maxBytes: defaultInstructionMaxBytes,
		maxChars: defaultSkillMaxChars,
	}
}

// Configure reads the max_bytes and max_chars thresholds.
func (r *InstructionSizeRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	for _, s := range []struct {
		key    string
		target *int
	}{{"max_bytes", &r.maxBytes}, {"max_chars", &r.maxChars}} {
		value, present, err := rules.IntSetting(settings, r.Name(), s.key)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		if value <= 0 {
			return fmt.Errorf("configure %s: %s must be positive, got %d", r.Name(), s.key, value)
		}
		*s.target = value
	}
	return nil
}

// AnalyzeFile measures an instruction file against its limit. A file is
// reported from the limit on and kept under it; the finding names the
// reference share it is shrunk to.
func (r *InstructionSizeRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	var message string
	switch core.InstructionKindOf(ctx.Path) {
	case core.AlwaysLoaded:
		base := filepath.Base(ctx.Path)
		size := len(withoutBlockComments(ctx.Lines))
		message = sizeMessage(base, size, r.maxBytes, "bytes", "it is loaded into every session")
	case core.Skill:
		size := utf8.RuneCountInString(withoutBlockComments(ctx.Lines))
		message = sizeMessage("SKILL.md", size, r.maxChars, "characters", "after compacting the context Claude Code keeps only the first 5000 tokens of a skill")
	}
	if message == "" {
		return nil
	}
	v := r.CreateViolation(ctx.RelPath, 1, message)
	v.WithSuggestion(fmt.Sprintf("Do not stop at just under the limit, shrink it to the reference of %d%%: move a rule into a mechanism (a check, a hook), a file read on demand (.claude/rules with paths, a reference file of the skill), or drop it", referenceShare))
	return []*core.Violation{v}
}

// referenceShare is the share of the limit, in percent, a file at the limit
// is shrunk to.
const referenceShare = 80

// sizeMessage describes a size at or over the limit, "" below it.
func sizeMessage(name string, size, limit int, unit, why string) string {
	aim := fmt.Sprintf(", the reference is %d%% (%d %s)", referenceShare, limit*referenceShare/100, unit)
	switch {
	case size > limit:
		return fmt.Sprintf("%s is %d %s without comments, over the limit of %d%s: %s", name, size, unit, limit, aim, why)
	case size == limit:
		return fmt.Sprintf("%s is %d %s without comments, 100%% of the limit of %d%s: %s, and the next rules put it over", name, size, unit, limit, aim, why)
	}
	return ""
}

// withoutBlockComments returns the text of a Markdown document without its
// block-level HTML comments: the lines from one starting with <!-- outside a
// code block to the one holding -->. Comments inside code blocks or inside a
// paragraph stay, as Claude Code keeps them.
func withoutBlockComments(lines []string) string {
	scanned := scanMarkdown(lines)
	kept := make([]string, 0, len(lines))
	inComment := false
	for i, line := range lines {
		if !inComment && !scanned[i].code {
			indent, rest := leadingColumns(line)
			inComment = indent < 4 && strings.HasPrefix(rest, "<!--")
			if inComment {
				rest = rest[len("<!--"):]
			}
			line = rest
		}
		if inComment {
			inComment = !strings.Contains(line, "-->")
			continue
		}
		kept = append(kept, lines[i])
	}
	return strings.Join(kept, "\n")
}

// SuppressionExempt reports that no marker in the file silences the rule:
// only the threshold in the configuration moves the limit.
func (r *InstructionSizeRule) SuppressionExempt() bool { return true }

// ReadsExcludedInstructions marks the rule as one that measures the
// instruction files the exclude patterns leave out.
func (r *InstructionSizeRule) ReadsExcludedInstructions() {}
