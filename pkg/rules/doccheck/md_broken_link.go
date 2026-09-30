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

// markdownLinkOpen matches the start of an inline link or image, [text]( or
// ![alt](; the destination after it is parsed by linkDestination.
// Reference-style links are resolved elsewhere in the document and are left
// alone.
var markdownLinkOpen = regexp.MustCompile(`!?\[[^\]]*\]\(`)

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
// Not flagged: external links, anchors within the page, and links inside code
// (fenced and indented blocks, inline code spans) or HTML comments, which are
// examples or hidden text rather than references. A target is URL-decoded
// (%20) and may hold balanced parentheses, as CommonMark reads it.
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

	for i, line := range scanMarkdown(ctx.Lines) {
		if line.code {
			continue
		}
		for _, loc := range markdownLinkOpen.FindAllStringIndex(line.prose, -1) {
			destination, ok := linkDestination(line.prose[loc[1]:])
			if !ok {
				continue
			}
			target, ok := localTarget(destination)
			if !ok {
				continue
			}
			// A root-relative target resolves from the repository root, as
			// GitHub renders it; everything else from the document's directory.
			base := docDir
			if strings.HasPrefix(target, "/") {
				base = ctx.ProjectRoot
			}
			if _, err := os.Stat(filepath.Join(base, filePathOf(target))); err == nil {
				continue
			}
			violations = append(violations, r.report(ctx, i+1, target))
		}
	}

	return violations
}

// linkDestination parses the destination at the start of s, the text after
// "](": <...> in angle brackets, or a run without spaces whose parentheses
// balance, followed by an optional title and the closing parenthesis.
func linkDestination(s string) (string, bool) {
	if strings.HasPrefix(s, "<") {
		end := strings.IndexByte(s, '>')
		if end < 0 {
			return "", false
		}
		return s[1:end], true
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			i++
		case c == '(':
			depth++
		case c == ')' && depth == 0:
			return s[:i], i > 0
		case c == ')':
			depth--
		case c == ' ' || c == '\t':
			// A title may follow; the destination ends here either way.
			return s[:i], i > 0
		}
	}
	return "", false
}

// filePathOf decodes the percent escapes of a link target (docs/my%20file.md)
// into the file name it addresses. A % that starts no valid escape stays a
// literal percent sign, as the WHATWG URL parser leaves it.
func filePathOf(target string) string {
	if !strings.Contains(target, "%") {
		return target
	}
	var b strings.Builder
	for i := 0; i < len(target); i++ {
		if target[i] == '%' && i+2 < len(target) && isHexDigit(target[i+1]) && isHexDigit(target[i+2]) {
			b.WriteByte(hexValue(target[i+1])<<4 | hexValue(target[i+2]))
			i += 2
			continue
		}
		b.WriteByte(target[i])
	}
	return b.String()
}

func isHexDigit(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func hexValue(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
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
