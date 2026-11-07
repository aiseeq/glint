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
	defaultInstructionMaxBytes = 24576
	// Claude Code keeps the first 5000 tokens of a skill after compacting
	// the context.
	defaultSkillMaxChars = 12000
	// A file from this share of its limit, in percent, is reported as LOW.
	defaultNearPercent = 90
)

// InstructionSizeRule limits the size of the Claude Code instruction files:
// CLAUDE.md, CLAUDE.local.md and .claude/rules/*.md are loaded into every
// session, and a skill is cut to its start after the context is compacted.
type InstructionSizeRule struct {
	*rules.BaseRule
	maxBytes    int
	maxChars    int
	nearPercent int
}

// NewInstructionSizeRule creates the rule
func NewInstructionSizeRule() *InstructionSizeRule {
	return &InstructionSizeRule{
		BaseRule: rules.NewBaseRule(
			"instruction-size",
			"documentation",
			"Detects a Claude Code instruction file near or over its size limit: CLAUDE.md, CLAUDE.local.md and .claude/rules/*.md from max_bytes (24576) on, skills/*/SKILL.md from max_chars (12000 characters) on, as LOW from near_percent (90%) of the limit, with 80% named as the reference to shrink to; block-level HTML comments are not counted, Claude Code strips them",
			core.SeverityMedium,
		),
		maxBytes:    defaultInstructionMaxBytes,
		maxChars:    defaultSkillMaxChars,
		nearPercent: defaultNearPercent,
	}
}

// RequiresFile reports whether path can be measured by this rule.
func (r *InstructionSizeRule) RequiresFile(path string) bool {
	return core.InstructionKindOf(path) != core.NotInstruction
}

// Configure reads the max_bytes and max_chars thresholds and near_percent,
// the share of the limit from which a file is reported as LOW: 1 to 100, 100
// reports a file only at the limit.
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
	value, present, err := rules.IntSetting(settings, r.Name(), "near_percent")
	if err != nil {
		return err
	}
	if present {
		if value < 1 || value > 100 {
			return fmt.Errorf("configure %s: near_percent must be from 1 to 100, got %d", r.Name(), value)
		}
		r.nearPercent = value
	}
	return nil
}

// AnalyzeFile measures an instruction file against its limit. A file is
// reported from the limit on and kept under it, and as LOW from nearPercent
// of the limit, so it is shrunk before it gets there; the finding names the
// reference share it is shrunk to.
func (r *InstructionSizeRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	var m sizeMeasure
	switch core.InstructionKindOf(ctx.Path) {
	case core.AlwaysLoaded:
		m = sizeMeasure{filepath.Base(ctx.Path), len(withoutBlockComments(ctx.Lines)), r.maxBytes, "bytes", "it is loaded into every session"}
	case core.Skill:
		m = sizeMeasure{"SKILL.md", utf8.RuneCountInString(withoutBlockComments(ctx.Lines)), r.maxChars, "characters", "after compacting the context Claude Code keeps only the first 5000 tokens of a skill"}
	default:
		return nil
	}
	message, near := m.message(r.nearPercent)
	if message == "" {
		return nil
	}
	v := r.CreateViolation(ctx.RelPath, 1, message)
	if near {
		v.Severity = core.SeverityLow
	}
	v.WithSuggestion(fmt.Sprintf("Do not stop at just under the limit, shrink it to the reference of %d%%: move a rule into a mechanism (a check, a hook), a file read on demand (.claude/rules with paths, a reference file of the skill), or drop it", referenceShare))
	return []*core.Violation{v}
}

// referenceShare is the share of the limit, in percent, a file at the limit
// is shrunk to.
const referenceShare = 80

// sizeMeasure is the size of an instruction file against its limit.
type sizeMeasure struct {
	name        string
	size, limit int
	unit, why   string
}

// message describes a size from nearPercent of the limit on, "" below it;
// near reports a size under the limit.
func (m sizeMeasure) message(nearPercent int) (message string, near bool) {
	aim := fmt.Sprintf(", the reference is %d%% (%d %s)", referenceShare, m.limit*referenceShare/100, m.unit)
	switch {
	case m.size > m.limit:
		return fmt.Sprintf("%s is %d %s without comments, over the limit of %d%s: %s", m.name, m.size, m.unit, m.limit, aim, m.why), false
	case m.size == m.limit:
		return fmt.Sprintf("%s is %d %s without comments, 100%% of the limit of %d%s: %s, and the next rules put it over", m.name, m.size, m.unit, m.limit, aim, m.why), false
	case m.size*100 >= m.limit*nearPercent:
		return fmt.Sprintf("%s is %d %s without comments, %d%% of the limit of %d%s: %s", m.name, m.size, m.unit, m.size*100/m.limit, m.limit, aim, m.why), true
	}
	return "", false
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
