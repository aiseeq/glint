package doccheck

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMdBrokenLinkRule())
}

// markdownLinkPattern matches inline links and images: [text](target) and
// ![alt](target). Reference-style links are resolved elsewhere in the document
// and are left alone.
var markdownLinkPattern = regexp.MustCompile(`!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)

// externalSchemes name a target this rule cannot verify from the file system.
var externalSchemes = []string{"http://", "https://", "mailto:", "tel:", "ftp://", "//", "data:"}

// MdBrokenLinkRule detects links in Markdown documents that point at files which
// do not exist:
//
//	See [configuration reference](docs/configuration.md)   // never written
//
// Documentation rots silently: the file gets renamed or never created, the link
// keeps rendering, and the reader finds out by clicking. Nothing in the build
// notices, because Markdown has no compiler.
//
// Not flagged: external links, anchors within the page, and links inside fenced
// code blocks, which are examples rather than references.
type MdBrokenLinkRule struct {
	*rules.BaseRule
}

// NewMdBrokenLinkRule creates the rule
func NewMdBrokenLinkRule() *MdBrokenLinkRule {
	return &MdBrokenLinkRule{
		BaseRule: rules.NewBaseRule(
			"md-broken-link",
			"documentation",
			"Detects Markdown links pointing at files that do not exist",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks every local link of a Markdown document.
func (r *MdBrokenLinkRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !strings.HasSuffix(ctx.Path, ".md") {
		return nil
	}

	docDir := filepath.Dir(ctx.Path)
	var violations []*core.Violation
	inFence := false

	for i, line := range ctx.Lines {
		if isFenceDelimiter(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}

		for _, match := range markdownLinkPattern.FindAllStringSubmatch(line, -1) {
			target, ok := localTarget(match[1])
			if !ok {
				continue
			}
			if _, err := os.Stat(filepath.Join(docDir, target)); err == nil {
				continue
			}
			violations = append(violations, r.report(ctx, i+1, target))
		}
	}

	return violations
}

func (r *MdBrokenLinkRule) report(ctx *core.FileContext, line int, target string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, line,
		fmt.Sprintf("Link points to %q, which does not exist — the reader finds out by clicking", target))
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Fix the path, or write %s, or drop the link", target))
	v.WithContext("pattern", "md_broken_link")
	v.WithContext("target", target)
	return v
}

// localTarget returns the file part of a link target when the link addresses
// something in this repository.
func localTarget(target string) (string, bool) {
	for _, scheme := range externalSchemes {
		if strings.HasPrefix(target, scheme) {
			return "", false
		}
	}
	if strings.HasPrefix(target, "#") {
		return "", false // an anchor within the same document
	}
	// The anchor addresses a place inside the file and the query string is a
	// cache-buster; the file is what must exist.
	target, _, _ = strings.Cut(target, "#")
	target, _, _ = strings.Cut(target, "?")
	target = strings.TrimSpace(target)
	if target == "" {
		return "", false
	}
	return target, true
}

// isFenceDelimiter reports whether the line opens or closes a fenced code block.
func isFenceDelimiter(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")
}
