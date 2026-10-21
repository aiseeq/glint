package doccheck

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func instructionSizeFindings(t *testing.T, settings map[string]any, path, content string) []*core.Violation {
	t.Helper()
	rule := NewInstructionSizeRule()
	require.NoError(t, rule.Configure(settings))
	root := t.TempDir()
	return rule.AnalyzeFile(core.NewFileContext(filepath.Join(root, path), root, []byte(content), nil))
}

// Instruction files are loaded into every session: CLAUDE.md, CLAUDE.local.md
// and .claude/rules are judged by bytes, a skill by characters, since Claude
// Code keeps only the start of a skill after compacting the context.
func TestInstructionSize(t *testing.T) {
	big := strings.Repeat("a", 101)
	for _, path := range []string{
		"CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", "pkg/CLAUDE.md",
		".claude/rules/api.md", ".claude/rules/backend/db.md",
	} {
		got := instructionSizeFindings(t, map[string]any{"max_bytes": 100}, path, big)
		require.Len(t, got, 1, path)
		require.Contains(t, got[0].Message, "101 bytes without comments")
		require.Equal(t, 1, got[0].Line)
		require.Empty(t, instructionSizeFindings(t, map[string]any{"max_bytes": 127}, path, big), path)
	}
	for _, path := range []string{"docs/guide.md", "README.md", ".claude/notes.md", "rules/api.md", "SKILL.md", "docs/x/SKILL.md"} {
		require.Empty(t, instructionSizeFindings(t, map[string]any{"max_bytes": 1, "max_chars": 1}, path, big), path)
	}

	// Characters, not bytes: 60 Cyrillic letters are 120 bytes.
	cyrillic := strings.Repeat("я", 60)
	for _, path := range []string{".claude/skills/deploy/SKILL.md", "skills/deploy/SKILL.md"} {
		require.Empty(t, instructionSizeFindings(t, map[string]any{"max_chars": 71, "max_bytes": 1}, path, cyrillic), path)
		got := instructionSizeFindings(t, map[string]any{"max_chars": 59}, path, cyrillic)
		require.Len(t, got, 1, path)
		require.Contains(t, got[0].Message, "60 characters without comments")
	}
}

func TestInstructionSizeDefaults(t *testing.T) {
	require.Empty(t, instructionSizeFindings(t, nil, "CLAUDE.md", strings.Repeat("a", 16383)))
	require.Len(t, instructionSizeFindings(t, nil, "CLAUDE.md", strings.Repeat("a", 16384)), 1)
	require.Len(t, instructionSizeFindings(t, nil, "CLAUDE.md", strings.Repeat("a", 16385)), 1)
	require.Empty(t, instructionSizeFindings(t, nil, ".claude/skills/x/SKILL.md", strings.Repeat("я", 10199)))
	require.Len(t, instructionSizeFindings(t, nil, ".claude/skills/x/SKILL.md", strings.Repeat("я", 10200)), 1)
	require.Len(t, instructionSizeFindings(t, nil, ".claude/skills/x/SKILL.md", strings.Repeat("я", 12001)), 1)
}

// A CLAUDE.md is kept under its limit: it is reported from 100% of
// max_bytes, and the finding names 80% as the size to aim for. A skill is
// reported from 85% of max_chars: the next step added to a skill at 99% puts
// it over, and moving steps out takes longer than adding one.
func TestInstructionSizeWarnsNearTheLimit(t *testing.T) {
	limit := map[string]any{"max_bytes": 100, "max_chars": 100}
	for _, size := range []int{80, 99} {
		require.Empty(t, instructionSizeFindings(t, limit, "CLAUDE.md", strings.Repeat("a", size)), size)
	}
	got := instructionSizeFindings(t, limit, "CLAUDE.md", strings.Repeat("a", 100))
	require.Len(t, got, 1)
	require.Contains(t, got[0].Message, "100 bytes without comments, 100% of the limit of 100")
	require.Contains(t, got[0].Message, "the reference is 80% (80 bytes)")
	require.Equal(t, core.SeverityMedium, got[0].Severity)
	over := instructionSizeFindings(t, limit, "CLAUDE.md", strings.Repeat("a", 101))[0].Message
	require.Contains(t, over, "over the limit of 100")
	require.Contains(t, over, "the reference is 80% (80 bytes)")

	require.Empty(t, instructionSizeFindings(t, limit, ".claude/skills/x/SKILL.md", strings.Repeat("я", 84)))
	got = instructionSizeFindings(t, limit, ".claude/skills/x/SKILL.md", strings.Repeat("я", 85))
	require.Len(t, got, 1)
	require.Contains(t, got[0].Message, "85 characters without comments, 85% of the limit of 100")
	require.NotContains(t, got[0].Message, "reference")
}

// Claude Code strips block-level HTML comments from CLAUDE.md before the
// model sees it; a comment inside a code block, or inside a paragraph, stays.
func TestInstructionSizeSkipsBlockComments(t *testing.T) {
	text := "- rule one\n<!-- why: a long reason\nover lines -->\n- rule two\n"
	kept := len("- rule one\n- rule two\n")
	settings := map[string]any{"max_bytes": kept - 1}
	got := instructionSizeFindings(t, settings, "CLAUDE.md", text)
	require.Len(t, got, 1)
	require.Contains(t, got[0].Message, fmt.Sprintf(" %d bytes without comments", kept))
	// Below 80% without the comment, over the limit with it.
	require.Empty(t, instructionSizeFindings(t, map[string]any{"max_bytes": 28}, "CLAUDE.md", text))
	require.Greater(t, len(text), 28)

	fenced := "```\n<!-- shown -->\n```\n"
	require.Len(t, instructionSizeFindings(t, map[string]any{"max_bytes": len(fenced) - 1}, "CLAUDE.md", fenced), 1)
	inline := "text <!-- shown --> text\n"
	require.Len(t, instructionSizeFindings(t, map[string]any{"max_bytes": len(inline) - 1}, "CLAUDE.md", inline), 1)

	skill := "шаг один\n<!-- причина -->\nшаг два\n"
	chars := utf8.RuneCountInString("шаг один\nшаг два\n")
	require.Empty(t, instructionSizeFindings(t, map[string]any{"max_chars": 21}, ".claude/skills/x/SKILL.md", skill))
	require.Greater(t, utf8.RuneCountInString(skill), 21)
	got = instructionSizeFindings(t, map[string]any{"max_chars": chars - 1}, ".claude/skills/x/SKILL.md", skill)
	require.Len(t, got, 1)
	require.Contains(t, got[0].Message, fmt.Sprintf(" %d characters without comments", chars))
}

func TestInstructionSizeRejectsBadThresholds(t *testing.T) {
	for _, settings := range []map[string]any{
		{"max_bytes": "16k"}, {"max_bytes": 0}, {"max_chars": -1}, {"max_chars": 1.5},
	} {
		require.Error(t, NewInstructionSizeRule().Configure(settings), "%v", settings)
	}
}

// Only the threshold in the configuration moves the limit: a marker in the
// file would let any instruction file grow past it.
func TestInstructionSizeIgnoresSuppressionMarkers(t *testing.T) {
	require.False(t, rules.HonorsSuppression(NewInstructionSizeRule()))
}
