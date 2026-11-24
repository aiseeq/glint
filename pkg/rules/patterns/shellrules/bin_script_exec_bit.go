package shellrules

import (
	"bytes"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewBinScriptExecBitRule())
}

// binPathspec selects the files git keeps right in a bin directory, at any
// depth: bin/run and services/bin/start, not bin/lib/common.sh.
const binPathspec = ":(glob)**/bin/*"

// executableMode and plainMode are the modes git records for a regular file.
const (
	executableMode = "100755"
	plainMode      = "100644"
)

// BinScriptExecBitRule detects a script in a bin directory that git records
// without the executable bit:
//
//	$ git ls-files -s bin/run
//	100644 3b18e512dba79e4c8300dd08aeb37f8e728b8dad 0	bin/run
//
// The clone it was written in may have the bit on disk, but every other one
// checks the file out as git records it, and ./bin/run fails with permission
// denied. A file starts as a script with #!; the mode is read from the git
// index, not from the disk. A file git does not track, or a project outside
// git, has no recorded mode and is not reported.
type BinScriptExecBitRule struct {
	*rules.BaseRule
}

// NewBinScriptExecBitRule creates the rule
func NewBinScriptExecBitRule() *BinScriptExecBitRule {
	return &BinScriptExecBitRule{BaseRule: rules.NewBaseRule(
		"bin-script-exec-bit",
		"patterns",
		"Detects a script in bin/ (it starts with #!) that the git index records as 100644 — every other clone checks it out not executable, and running it fails with permission denied",
		core.SeverityMedium,
	)}
}

// ReadsOtherFiles reports that findings depend on the git index, not only on
// the script.
func (r *BinScriptExecBitRule) ReadsOtherFiles() bool { return true }

// CacheInputs returns the modes the git index records for the files in bin
// directories: a change of a mode alone reruns the rule.
func (r *BinScriptExecBitRule) CacheInputs(root string) (string, error) {
	modes, err := core.GitIndexModes(root, binPathspec)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, path := range slices.Sorted(maps.Keys(modes)) {
		b.WriteString(modes[path] + " " + path + "\n")
	}
	return b.String(), nil
}

// RequiresFile selects a file right in a bin directory.
func (r *BinScriptExecBitRule) RequiresFile(path string) bool {
	return filepath.Base(filepath.Dir(path)) == "bin"
}

// RequiresAdditionalFile includes a script in a bin directory that the
// walker would skip by its kind (#!/usr/bin/env python3 without an
// extension); a compiled program there is not read.
func (r *BinScriptExecBitRule) RequiresAdditionalFile(path string) bool {
	return r.RequiresFile(path) && hasShebangFile(path)
}

// hasShebangFile reports a regular file whose first bytes are #!. A file
// that cannot be read is no script for the walk, as for the walker's own
// hasShellShebangFile; a FIFO is never opened, it would block the walk.
func hasShebangFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }() // read only
	head := make([]byte, 2)
	if _, err := io.ReadFull(file, head); err != nil {
		return false // shorter than #!, or unreadable: the walk reads no script
	}
	return string(head) == "#!"
}

// AnalyzeFile reports a script in a bin directory that the git index records
// as a plain file.
func (r *BinScriptExecBitRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !r.RequiresFile(ctx.Path) || !bytes.HasPrefix(ctx.Content, []byte("#!")) {
		return nil
	}
	rel := filepath.ToSlash(ctx.RelPath)
	modes, err := core.GitIndexModes(ctx.ProjectRoot, binPathspec)
	if err != nil {
		return []*core.Violation{r.CreateViolation(ctx.RelPath, 1,
			"could not read the mode of script "+rel+" from the git index: "+err.Error())}
	}
	if modes[rel] != plainMode {
		return nil
	}
	v := r.CreateViolation(ctx.RelPath, 1,
		"script "+rel+" starts with #! but git records it as "+plainMode+", not "+executableMode+
			" — every other clone checks it out not executable, and running it fails with permission denied")
	v.WithCode(strings.TrimSpace(ctx.GetLine(1)))
	v.WithSuggestion("Record the executable bit in git: git update-index --chmod=+x " + rel)
	return []*core.Violation{v}
}
