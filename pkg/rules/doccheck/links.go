package doccheck

import (
	"go/ast"
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
	pkgRefPattern  *regexp.Regexp
	brokenURLHints []string
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
		pkgRefPattern: regexp.MustCompile(`(?:see|use|call)\s+([A-Z][a-zA-Z0-9]*(?:\.[A-Z][a-zA-Z0-9]*)?)`),
		// URL patterns that often indicate broken links
		// Note: localhost/127.0.0.1 are valid for local development documentation
		brokenURLHints: []string{
			"example.com",
			"TODO",
			"FIXME",
			"XXX",
			"your-",
			"<your",
			"${",
			"{{",
		},
	}
}

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

	// Check URLs
	urls := r.urlPattern.FindAllString(text, -1)
	for _, url := range urls {
		if v := r.checkURL(ctx, pos.Line, url); v != nil {
			violations = append(violations, v)
		}
	}

	// Check file references
	fileRefs := r.fileRefPattern.FindAllStringSubmatch(text, -1)
	for _, match := range fileRefs {
		if len(match) > 1 {
			if v := r.checkFileRef(ctx, pos.Line, match[1]); v != nil {
				violations = append(violations, v)
			}
		}
	}

	return violations
}

// checkURL checks if a URL looks suspicious or broken
func (r *DocLinksRule) checkURL(ctx *core.FileContext, line int, url string) *core.Violation {
	// Check for placeholder/broken URL hints
	urlLower := strings.ToLower(url)
	for _, hint := range r.brokenURLHints {
		if strings.Contains(urlLower, strings.ToLower(hint)) {
			v := r.CreateViolation(ctx.RelPath, line,
				"Documentation contains placeholder or suspicious URL: "+truncateURL(url))
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Replace placeholder URL with actual documentation link")
			v.WithContext("url", url)
			v.WithContext("hint", hint)
			return v
		}
	}

	// Check for incomplete URLs
	if strings.HasSuffix(url, "/") && strings.Count(url, "/") <= 3 {
		// Just a domain with trailing slash, might be incomplete
		return nil
	}

	// Check for obviously malformed URLs
	if strings.Contains(url, "..") || strings.Contains(url, "//") && strings.Count(url, "//") > 1 {
		v := r.CreateViolation(ctx.RelPath, line,
			"Documentation contains malformed URL: "+truncateURL(url))
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Fix the URL format")
		v.WithContext("url", url)
		return v
	}

	return nil
}

// checkFileRef checks if a file reference exists
func (r *DocLinksRule) checkFileRef(ctx *core.FileContext, line int, fileRef string) *core.Violation {
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
func truncateURL(url string) string {
	if len(url) > 60 {
		return url[:57] + "..."
	}
	return url
}
