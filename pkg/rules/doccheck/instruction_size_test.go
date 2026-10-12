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
		require.Empty(t, instructionSizeFindings(t, map[string]any{"max_bytes": 101}, path, big), path)
	}
	for _, path := range []string{"docs/guide.md", "README.md", ".claude/notes.md", "rules/api.md", "SKILL.md", "docs/x/SKILL.md"} {
		require.Empty(t, instructionSizeFindings(t, map[string]any{"max_bytes": 1, "max_chars": 1}, path, big), path)
	}

	// Characters, not bytes: 60 Cyrillic letters are 120 bytes.
	cyrillic := strings.Repeat("я", 60)
	for _, path := range []string{".claude/skills/deploy/SKILL.md", "skills/deploy/SKILL.md"} {
		require.Empty(t, instructionSizeFindings(t, map[string]any{"max_chars": 60, "max_bytes": 1}, path, cyrillic), path)
		got := instructionSizeFindings(t, map[string]any{"max_chars": 59}, path, cyrillic)
		require.Len(t, got, 1, path)
		require.Contains(t, got[0].Message, "60 characters without comments")
	}
}

func TestInstructionSizeDefaults(t *testing.T) {
	require.Empty(t, instructionSizeFindings(t, nil, "CLAUDE.md", strings.Repeat("a", 16384)))
	require.Len(t, instructionSizeFindings(t, nil, "CLAUDE.md", strings.Repeat("a", 16385)), 1)
	require.Empty(t, instructionSizeFindings(t, nil, ".claude/skills/x/SKILL.md", strings.Repeat("я", 12000)))
	require.Len(t, instructionSizeFindings(t, nil, ".claude/skills/x/SKILL.md", strings.Repeat("я", 12001)), 1)
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
	require.Empty(t, instructionSizeFindings(t, map[string]any{"max_bytes": kept}, "CLAUDE.md", text))

	fenced := "```\n<!-- shown -->\n```\n"
	require.Len(t, instructionSizeFindings(t, map[string]any{"max_bytes": len(fenced) - 1}, "CLAUDE.md", fenced), 1)
	inline := "text <!-- shown --> text\n"
	require.Len(t, instructionSizeFindings(t, map[string]any{"max_bytes": len(inline) - 1}, "CLAUDE.md", inline), 1)

	skill := "шаг один\n<!-- причина -->\nшаг два\n"
	chars := utf8.RuneCountInString("шаг один\nшаг два\n")
	require.Empty(t, instructionSizeFindings(t, map[string]any{"max_chars": chars}, ".claude/skills/x/SKILL.md", skill))
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
