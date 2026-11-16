package httprules

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() { rules.Register(NewBlockElementInsidePRule()) }

// blockElementsCloseP are the HTML elements whose in-body start-tag handling
// closes a p element in button scope.
var blockElementsCloseP = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true, "center": true,
	"details": true, "dialog": true, "dir": true, "div": true, "dl": true, "fieldset": true,
	"figcaption": true, "figure": true, "footer": true, "form": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"header": true, "hgroup": true, "hr": true, "listing": true, "main": true, "menu": true,
	"nav": true, "ol": true, "p": true, "plaintext": true, "pre": true, "search": true,
	"section": true, "summary": true, "table": true, "ul": true, "xmp": true,
}

// BlockElementInsidePRule reports a block start tag that implicitly closes an
// open paragraph in a template.
type BlockElementInsidePRule struct{ *rules.BaseRule }

// NewBlockElementInsidePRule creates block-element-inside-p.
func NewBlockElementInsidePRule() *BlockElementInsidePRule {
	return &BlockElementInsidePRule{BaseRule: rules.NewBaseRule(
		"block-element-inside-p", "patterns",
		"Detects a block element such as <div>, <form> or <ul> inside an open <p> in an HTML template — the browser closes the paragraph before it, leaving an empty <p> and markup that styles and selectors do not match",
		core.SeverityLow,
	)}
}

type htmlOpenElement struct {
	name      string
	uncertain bool
}

type blockElementInsidePScanner struct {
	rule       *BlockElementInsidePRule
	ctx        *core.FileContext
	source     string
	lower      string
	stack      []htmlOpenElement
	violations []*core.Violation
	line       int
	i          int
}

const htmlVoidTagNames = "|area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr|"

// AnalyzeFile scans template markup once, keeping enough of the open-element
// stack to model paragraph closure and button scope.
func (r *BlockElementInsidePRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTemplate() {
		return nil
	}
	s := blockElementInsidePScanner{
		rule: r, ctx: ctx, source: string(ctx.Content), line: 1,
		stack: make([]htmlOpenElement, 0, 16),
	}
	s.lower = strings.ToLower(s.source)
	for s.i < len(s.source) {
		switch {
		case strings.HasPrefix(s.source[s.i:], "<!--"):
			if !s.skipHTMLComment() {
				return s.violations
			}
		case strings.HasPrefix(s.source[s.i:], "{{"):
			if !s.scanTemplateAction() {
				return s.violations
			}
		case s.source[s.i] != '<':
			if s.source[s.i] == '\n' {
				s.line++
			}
			s.i++
		default:
			if !s.scanTag() {
				return s.violations
			}
		}
	}
	return s.violations
}

func (s *blockElementInsidePScanner) advance(to int) {
	s.line += strings.Count(s.source[s.i:to], "\n")
	s.i = to
}

func (s *blockElementInsidePScanner) skipHTMLComment() bool {
	end := strings.Index(s.source[s.i+4:], "-->")
	if end < 0 {
		return false
	}
	s.advance(s.i + 4 + end + 3)
	return true
}

func (s *blockElementInsidePScanner) scanTemplateAction() bool {
	if strings.HasPrefix(s.source[s.i:], "{{/*") {
		end := strings.Index(s.source[s.i+4:], "*/}}")
		if end < 0 {
			return false
		}
		s.advance(s.i + 4 + end + 4)
		return true
	}
	end := strings.Index(s.source[s.i+2:], "}}")
	if end < 0 {
		return false
	}
	end += s.i + 2
	if isTemplateControl(strings.TrimSpace(s.source[s.i+2 : end])) {
		if p := openParagraphIndex(s.stack); p >= 0 {
			s.stack[p].uncertain = true
		}
	}
	s.advance(end + 2)
	return true
}

func (s *blockElementInsidePScanner) scanTag() bool {
	name, closing, tagEnd, ok := scanHTMLTag(s.source, s.i)
	if !ok {
		if tagEnd > s.i {
			s.advance(tagEnd)
			return false
		}
		s.i++
		return true
	}
	s.advance(tagEnd)
	if name == "" {
		return true
	}
	if closing {
		for j := len(s.stack) - 1; j >= 0; j-- {
			if s.stack[j].name == name {
				s.stack = s.stack[:j]
				break
			}
		}
		return true
	}
	if name == "p" || blockElementsCloseP[name] {
		if p := paragraphInButtonScope(s.stack); p >= 0 {
			if !s.stack[p].uncertain && !s.ctx.IsSuppressed(s.line, s.rule.Name()) {
				v := s.rule.CreateViolation(s.ctx.RelPath, s.line, "A <"+name+"> start tag implicitly closes the open <p> element")
				v.WithCode(strings.TrimSpace(s.ctx.GetLine(s.line)))
				v.WithSuggestion("Move the block element outside the <p>, or close the paragraph before it")
				s.violations = append(s.violations, v)
			}
			s.stack = s.stack[:p]
		}
	}
	selfClosing := tagEnd >= 2 && s.source[tagEnd-2] == '/'
	if !selfClosing && !isHTMLVoidTag(name) {
		s.stack = append(s.stack, htmlOpenElement{name: name})
		if isRawHTMLTextElement(name) && !s.skipRawText(name) {
			return false
		}
	}
	return true
}

func isRawHTMLTextElement(name string) bool {
	switch name {
	case "script", "style", "textarea", "xmp", "plaintext":
		return true
	default:
		return false
	}
}

func (s *blockElementInsidePScanner) skipRawText(name string) bool {
	if name == "plaintext" {
		s.advance(len(s.source))
		return false
	}
	if rawEnd := strings.Index(s.lower[s.i:], "</"+name); rawEnd >= 0 {
		s.advance(s.i + rawEnd)
		return true
	}
	return false
}

func isTemplateControl(action string) bool {
	if action == "" {
		return false
	}
	action = strings.TrimLeft(action, "- \t\r\n")
	word := action
	if n := strings.IndexAny(word, " \t\r\n"); n >= 0 {
		word = word[:n]
	}
	switch word {
	case "if", "else", "end", "range", "with", "template", "block", "define":
		return true
	default:
		return false
	}
}

func openParagraphIndex(stack []htmlOpenElement) int {
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].name == "p" {
			return i
		}
		if htmlScopeBoundary(stack[i].name) {
			return -1
		}
	}
	return -1
}

func paragraphInButtonScope(stack []htmlOpenElement) int {
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].name == "p" {
			return i
		}
		if stack[i].name == "button" || htmlScopeBoundary(stack[i].name) {
			return -1
		}
	}
	return -1
}

func htmlScopeBoundary(name string) bool {
	switch name {
	case "html", "table", "td", "th", "template", "applet", "caption", "marquee", "object":
		return true
	default:
		return false
	}
}

// scanHTMLTag returns the normalized tag name and the offset after its closing
// angle bracket. Quoted attribute values may contain angle brackets.
func scanHTMLTag(source string, start int) (name string, closing bool, end int, ok bool) {
	if start+1 >= len(source) || source[start+1] == '!' || source[start+1] == '?' {
		return "", false, 0, false
	}
	i := start + 1
	if source[i] == '/' {
		closing = true
		i++
	}
	nameStart := i
	for i < len(source) && isHTMLNameByte(source[i]) {
		i++
	}
	if i == nameStart {
		return "", false, 0, false
	}
	name = strings.ToLower(source[nameStart:i])
	quote := byte(0)
	for ; i < len(source); i++ {
		c := source[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '>':
			return name, closing, i + 1, true
		}
	}
	return "", false, len(source), false
}

func isHTMLNameByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ':' || c == '-'
}

func isHTMLVoidTag(name string) bool {
	return strings.Contains(htmlVoidTagNames, "|"+name+"|")
}
