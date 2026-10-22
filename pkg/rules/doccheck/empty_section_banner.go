package doccheck

import (
	"fmt"
	"go/scanner"
	"go/token"
	"regexp"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewEmptySectionBannerRule())
}

var (
	// bannerLine is a comment line drawn as a rule: four or more =, -, # or *.
	bannerLine = regexp.MustCompile(`^//\s*[=\-#*]{4,}`)
	// closingBanner titles the end of a section: END, END OF X, КОНЕЦ.
	closingBanner = regexp.MustCompile(`(?i)^(?:end\b|конец\b)`)
)

// EmptySectionBannerRule detects a section banner with no code under it:
//
//	// ==========================================
//	// SQL BUILDER INTERFACES
//	// ==========================================
//
//	// BuildQuery moved to the query package
//
//	// ==========================================
//	// SESSION INTERFACES
//	// ==========================================
//
// The code the section titled was deleted or moved, and the banner stayed
// with the notes about it: a reader looks for the section's code and finds
// a heading over nothing. A section ends at the next banner, at the brace
// closing the block it sits in, or at the end of the file. A banner titled
// END closes the section above it and heads none.
type EmptySectionBannerRule struct {
	*rules.BaseRule
}

// NewEmptySectionBannerRule creates the rule
func NewEmptySectionBannerRule() *EmptySectionBannerRule {
	return &EmptySectionBannerRule{
		BaseRule: rules.NewBaseRule(
			"empty-section-banner",
			"documentation",
			"Detects a section banner comment (// ==== TITLE ====) with no code under it up to the next banner, the closing brace or the end of the file — the code it titled is gone",
			core.SeverityLow,
		),
	}
}

// sectionBanner is a group of comment lines with a rule line among them.
type sectionBanner struct {
	start, end int // first and last line
	title      string
}

// AnalyzeFile reports the banners of a Go, TypeScript or JavaScript file
// that head no code.
func (r *EmptySectionBannerRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.IsGenerated() {
		return nil
	}
	var code []int // the lines with code, in order
	var closers map[int]bool
	switch {
	case ctx.IsGoFile():
		code, closers = goCodeLines(ctx.Content)
	case ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile():
		code, closers = scriptCodeLines(ctx.Lines)
	default:
		return nil
	}
	banners := sectionBanners(ctx.Lines, code)
	var violations []*core.Violation
	for i, b := range banners {
		if closingBanner.MatchString(b.title) {
			continue
		}
		next := len(ctx.Lines) + 1
		if i+1 < len(banners) {
			next = banners[i+1].start
		}
		if headsCode(code, closers, b.end, next) || ctx.IsSuppressed(b.start, r.Name()) {
			continue
		}
		title := b.title
		if title == "" {
			title = strings.TrimSpace(ctx.GetLine(b.start))
		}
		v := r.CreateViolation(ctx.RelPath, b.start, fmt.Sprintf(
			"Section banner %q heads no code — only comments follow up to the next section, the closing brace or the end of the file", title))
		v.WithCode(strings.TrimSpace(ctx.GetLine(b.start)))
		v.WithSuggestion("Remove the banner together with the notes under it, or put the code it titles back under it")
		violations = append(violations, v)
	}
	return violations
}

// headsCode reports code between the banner ending at line end and the line
// next: the first code line after the banner comes before next and does not
// close the block the banner sits in.
func headsCode(code []int, closers map[int]bool, end, next int) bool {
	for _, line := range code {
		if line <= end {
			continue
		}
		return line < next && !closers[line]
	}
	return false
}

// sectionBanners groups the comment lines that hold no code into runs and
// keeps the runs with a rule line, titled by their first line with letters.
func sectionBanners(lines []string, code []int) []sectionBanner {
	hasCode := make(map[int]bool, len(code))
	for _, line := range code {
		hasCode[line] = true
	}
	var banners []sectionBanner
	var cur *sectionBanner
	banner := false
	flush := func() {
		if cur != nil && banner {
			banners = append(banners, *cur)
		}
		cur, banner = nil, false
	}
	for i, raw := range lines {
		line := i + 1
		text := strings.TrimSpace(raw)
		if !strings.HasPrefix(text, "//") || hasCode[line] {
			flush()
			continue
		}
		if cur == nil {
			cur = &sectionBanner{start: line}
		}
		cur.end = line
		if bannerLine.MatchString(text) {
			banner = true
		}
		if title := strings.TrimFunc(strings.TrimPrefix(text, "//"), func(r rune) bool {
			return unicode.IsSpace(r) || strings.ContainsRune("=-#*", r)
		}); cur.title == "" && strings.ContainsFunc(title, unicode.IsLetter) {
			cur.title = title
		}
	}
	flush()
	return banners
}

// goCodeLines returns the lines of Go source that hold a token or a part of
// one, and those whose first token closes a block.
func goCodeLines(src []byte) ([]int, map[int]bool) {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, nil, 0)
	var code []int
	closers := map[int]bool{}
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return code, closers
		}
		if tok == token.SEMICOLON && lit == "\n" {
			continue
		}
		// A raw string spans lines: each of them is code, comment-like or not.
		first := file.Line(pos)
		for line := first; line <= first+strings.Count(lit, "\n"); line++ {
			if len(code) > 0 && code[len(code)-1] >= line {
				continue
			}
			code = append(code, line)
			if tok == token.RBRACE || tok == token.RPAREN || tok == token.RBRACK {
				closers[line] = true
			}
		}
	}
}

// scriptCodeLines returns the lines of TypeScript or JavaScript that hold
// code outside comments, and those that only close a block.
func scriptCodeLines(lines []string) ([]int, map[int]bool) {
	var code []int
	closers := map[int]bool{}
	inBlock := false
	for i, raw := range lines {
		text := strings.TrimSpace(raw)
		if inBlock {
			end := strings.Index(text, "*/")
			if end < 0 {
				continue
			}
			inBlock = false
			text = strings.TrimSpace(text[end+2:])
		}
		if strings.HasPrefix(text, "/*") {
			end := strings.Index(text[2:], "*/")
			if end < 0 {
				inBlock = true
				continue
			}
			text = strings.TrimSpace(text[2+end+2:])
		}
		if text == "" || strings.HasPrefix(text, "//") {
			continue
		}
		code = append(code, i+1)
		if strings.Trim(text, "})];, ") == "" {
			closers[i+1] = true
		}
	}
	return code, closers
}
