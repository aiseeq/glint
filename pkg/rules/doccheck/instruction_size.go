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
			"Detects a Claude Code instruction file over its size limit: CLAUDE.md, CLAUDE.local.md and .claude/rules/*.md over max_bytes (16384), skills/*/SKILL.md over max_chars (12000 characters); block-level HTML comments are not counted, Claude Code strips them",
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

// AnalyzeFile measures an instruction file against its limit.
func (r *InstructionSizeRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	path := filepath.ToSlash(ctx.Path)
	base := filepath.Base(path)
	var message string
	switch {
	case base == "CLAUDE.md" || base == "CLAUDE.local.md" ||
		strings.Contains(path, "/.claude/rules/") && strings.HasSuffix(path, ".md"):
		size := len(withoutBlockComments(ctx.Lines))
		if size <= r.maxBytes {
			return nil
		}
		message = fmt.Sprintf("%s is %d bytes without comments, over the limit of %d: it is loaded into every session", base, size, r.maxBytes)
	case base == "SKILL.md" && filepath.Base(filepath.Dir(filepath.Dir(path))) == "skills":
		size := utf8.RuneCountInString(withoutBlockComments(ctx.Lines))
		if size <= r.maxChars {
			return nil
		}
		message = fmt.Sprintf("SKILL.md is %d characters without comments, over the limit of %d: after compacting the context Claude Code keeps only the first 5000 tokens of a skill", size, r.maxChars)
	default:
		return nil
	}
	v := r.CreateViolation(ctx.RelPath, 1, message)
	v.WithSuggestion("Move the rule into a mechanism (a check, a hook), a skill step or .claude/rules with paths, or drop it; do not add it to the always-loaded set")
	return []*core.Violation{v}
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
