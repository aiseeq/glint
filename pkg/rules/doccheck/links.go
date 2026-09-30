package doccheck

import (
	"go/ast"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDocLinksRule())
}

// DocLinksRule detects broken or suspicious links in documentation
type DocLinksRule struct {
	*rules.BaseRule
	urlPattern     *regexp.Regexp
	fileRefPattern *regexp.Regexp
	brokenURLHints []string
	// placeholderWord finds a placeholder marker as a whole word: "todomvc"
	// holds no TODO.
	placeholderWord *regexp.Regexp
}

// NewDocLinksRule creates the rule
func NewDocLinksRule() *DocLinksRule {
	return &DocLinksRule{
		BaseRule: rules.NewBaseRule(
			"doc-links",
			"documentation",
			"Detects broken or suspicious links in documentation comments",
			core.SeverityLow,
		),
		// Match URLs in comments
		urlPattern: regexp.MustCompile(`https?://[^\s\)>\]"']+`),
		// Match file references like "see file.go" or "in path/to/file.go"
		fileRefPattern: regexp.MustCompile(`(?:see|in|from|file)\s+["']?([a-zA-Z0-9_\-./]+\.(?:go|md|yaml|json|txt))["']?`),
		// Match package/function references like "see Package.Function"
		// URL patterns that often indicate broken links
		// Note: localhost/127.0.0.1 are valid for local development documentation
		brokenURLHints: []string{
			"your-",
			"<your",
			"${",
			"{{",
		},
		placeholderWord: regexp.MustCompile(`(?i)\b(?:TODO|FIXME|XXX)\b`),
	}
}

// ReadsOtherFiles reports that findings depend on whether the files a comment links to
// exist on disk.
func (r *DocLinksRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile checks for broken links in documentation
func (r *DocLinksRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	// Skip test files
	if ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	// Track checked comments to avoid duplicates
	checked := make(map[*ast.Comment]bool)

	// Check all comments in the file (includes all doc comments)
	for _, cg := range ctx.GoAST.Comments {
		for _, comment := range cg.List {
			if !checked[comment] {
				checked[comment] = true
				violations = append(violations, r.checkComment(ctx, comment)...)
			}
		}
	}

	return violations
}

// checkComment checks a single comment for broken links
func (r *DocLinksRule) checkComment(ctx *core.FileContext, comment *ast.Comment) []*core.Violation {
	var violations []*core.Violation
	text := comment.Text
	pos := ctx.PositionFor(comment)

	// Check URLs. Sentence punctuation after a URL ends the sentence, not
	// the URL.
	for _, found := range r.urlPattern.FindAllString(text, -1) {
		if v := r.checkURL(ctx, pos.Line, strings.TrimRight(found, ".,;:!?")); v != nil {
			violations = append(violations, v)
		}
	}

	// Check file references
	for _, match := range r.fileRefPattern.FindAllStringSubmatchIndex(text, -1) {
		if len(match) < 4 || match[2] < 0 {
			continue
		}
		if isIllustration(text[:match[0]]) {
			continue // "like \"file.go\"" names a shape, not a real file
		}
		if v := r.checkFileRef(ctx, pos.Line, text[match[2]:match[3]]); v != nil {
			violations = append(violations, v)
		}
	}

	return violations
}

// checkURL checks if a URL looks suspicious or broken. It judges the URL by
// its parts: the host for example.com, whole words for TODO-like markers, whole
// path segments for "..", and empty segments for "//" - but not the "//" of a
// URL embedded in the path (an archive link), nor "..." inside a segment (a
// compare range).
func (r *DocLinksRule) checkURL(ctx *core.FileContext, line int, rawURL string) *core.Violation {
	if hint, ok := r.placeholderHint(rawURL); ok {
		v := r.CreateViolation(ctx.RelPath, line,
			"Documentation contains placeholder or suspicious URL: "+truncateURL(rawURL))
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Replace placeholder URL with actual documentation link")
		v.WithContext("url", rawURL)
		v.WithContext("hint", hint)
		return v
	}

	if isMalformedURLPath(rawURL) {
		v := r.CreateViolation(ctx.RelPath, line,
			"Documentation contains malformed URL: "+truncateURL(rawURL))
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Fix the URL format")
		v.WithContext("url", rawURL)
		return v
	}

	return nil
}

// placeholderHint returns the placeholder marker a URL carries: an
// example.com host, a TODO/FIXME/XXX word, or a template fragment.
func (r *DocLinksRule) placeholderHint(rawURL string) (string, bool) {
	if parsed, err := url.Parse(rawURL); err == nil {
		host := strings.ToLower(parsed.Hostname())
		if host == "example.com" || strings.HasSuffix(host, ".example.com") {
			return "example.com", true
		}
	}
	if word := r.placeholderWord.FindString(rawURL); word != "" {
		return word, true
	}
	lower := strings.ToLower(rawURL)
	for _, hint := range r.brokenURLHints {
		if strings.Contains(lower, strings.ToLower(hint)) {
			return hint, true
		}
	}
	return "", false
}

// isMalformedURLPath reports a host with an empty label ("docs..example.org"),
// a path with a ".." segment or an empty segment ("a//b"). A "//" right
// after a scheme's colon starts an embedded URL.
func isMalformedURLPath(rawURL string) bool {
	_, rest, found := strings.Cut(rawURL, "://")
	if !found {
		return false
	}
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")
	segments := strings.Split(rest, "/")
	if strings.Contains(segments[0], "..") {
		return true
	}
	// segments[0] is the host; a trailing "/" leaves one empty last segment.
	for i := 1; i < len(segments); i++ {
		segment := segments[i]
		if segment == ".." {
			return true
		}
		if segment != "" || i == len(segments)-1 {
			continue
		}
		if strings.HasSuffix(segments[i-1], ":") {
			continue // "https:" + "" + host: an embedded URL
		}
		return true
	}
	return false
}

// checkFileRef checks if a file reference exists
// illustrationLead marks a file reference that introduces an example rather
// than pointing at a real file.
var illustrationLead = regexp.MustCompile(`(?i)(?:\blike\b|\be\.g\.|\bsuch as\b|\bfor example\b|\bexample\b|\bformat\b)[^.]*$`)

func isIllustration(before string) bool {
	return illustrationLead.MatchString(before)
}

func (r *DocLinksRule) checkFileRef(ctx *core.FileContext, line int, fileRef string) *core.Violation {
	// "path/to/..." is the conventional placeholder for "any path".
	if strings.HasPrefix(fileRef, "path/to/") || strings.Contains(fileRef, "/path/to/") {
		return nil
	}

	// Common config file names that exist in standard locations
	// These are often referenced without full path in documentation
	wellKnownConfigs := map[string]bool{
		"config.yaml":         true,
		"config.yml":          true,
		"config.json":         true,
		".env":                true,
		"Makefile":            true,
		"Dockerfile":          true,
		"docker-compose.yaml": true,
		"docker-compose.yml":  true,
	}
	if wellKnownConfigs[fileRef] {
		return nil // Skip well-known config files
	}

	// Try to resolve the file path relative to the current file
	dir := filepath.Dir(ctx.Path)
	fullPath := filepath.Join(dir, fileRef)

	// Also try relative to project root
	projectPath := filepath.Join(ctx.ProjectRoot, fileRef)

	// Check if file exists
	if !fileExists(fullPath) && !fileExists(projectPath) {
		v := r.CreateViolation(ctx.RelPath, line,
			"Documentation references non-existent file: "+fileRef)
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Update the file reference to point to an existing file")
		v.WithContext("file_ref", fileRef)
		return v
	}

	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// truncateURL truncates long URLs for display
func truncateURL(rawURL string) string {
	if len(rawURL) > 60 {
		return rawURL[:57] + "..."
	}
	return rawURL
}
