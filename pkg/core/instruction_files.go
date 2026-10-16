package core

import (
	"path/filepath"
	"strings"
)

// InstructionKind is the kind of a Claude Code instruction file.
type InstructionKind int

const (
	// NotInstruction is any other file.
	NotInstruction InstructionKind = iota
	// AlwaysLoaded is CLAUDE.md, CLAUDE.local.md or .claude/rules/*.md:
	// loaded into every session.
	AlwaysLoaded
	// Skill is skills/<name>/SKILL.md: cut to its start after the context is
	// compacted.
	Skill
)

// InstructionKindOf tells a Claude Code instruction file by its path.
func InstructionKindOf(path string) InstructionKind {
	path = filepath.ToSlash(path)
	base := filepath.Base(path)
	switch {
	case base == "CLAUDE.md" || base == "CLAUDE.local.md" ||
		strings.Contains("/"+path, "/.claude/rules/") && strings.HasSuffix(path, ".md"):
		return AlwaysLoaded
	case base == "SKILL.md" && filepath.Base(filepath.Dir(filepath.Dir(path))) == "skills":
		return Skill
	}
	return NotInstruction
}
