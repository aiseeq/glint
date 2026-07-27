package fix

import (
	"fmt"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// ensureImports returns the edit that adds the missing standard-library imports
// to a Go file, or nil when they are all present. A fix that rewrites code into
// a library call is only a fix if the file can still compile.
func ensureImports(ctx *core.FileContext, packages ...string) *Fix {
	missing := missingImports(ctx, packages)
	if len(missing) == 0 {
		return nil
	}

	line, ok := importInsertionLine(ctx, missing[0])
	if !ok {
		return nil
	}

	var added strings.Builder
	for _, pkg := range missing {
		fmt.Fprintf(&added, "\t%q\n", pkg)
	}
	added.WriteString(ctx.Lines[line-1])

	return &Fix{
		File:      ctx.Path,
		StartLine: line,
		EndLine:   line,
		OldText:   ctx.Lines[line-1],
		NewText:   added.String(),
		Message:   "Add " + strings.Join(missing, ", ") + " to the imports",
	}
}

// missingImports returns the requested packages the file does not import yet,
// keeping the caller's order.
func missingImports(ctx *core.FileContext, packages []string) []string {
	var missing []string
	for _, pkg := range packages {
		quoted := `"` + pkg + `"`
		imported := false
		for _, line := range ctx.Lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == quoted || strings.HasPrefix(trimmed, quoted+" ") || trimmed == "import "+quoted {
				imported = true
				break
			}
			if trimmed == ")" && imported {
				break
			}
		}
		if !imported {
			missing = append(missing, pkg)
		}
	}
	return missing
}

// importInsertionLine returns the line the new imports go before, keeping the
// group sorted: the first import that sorts after them, or the closing brace.
// A file with a single unparenthesized import or none at all is left alone —
// restructuring the declaration is gofmt's job, not a line edit's.
func importInsertionLine(ctx *core.FileContext, first string) (int, bool) {
	inGroup := false
	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "import (":
			inGroup = true
		case !inGroup:
			continue
		case trimmed == ")":
			return i + 1, true
		case strings.HasPrefix(trimmed, `"`):
			if strings.Trim(trimmed, `"`) > first {
				return i + 1, true
			}
		}
	}
	return 0, false
}
