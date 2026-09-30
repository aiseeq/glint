package doccheck

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMdFrontmatterRule())
}

// MdFrontmatterRule validates YAML frontmatter in Markdown documents: the
// block must parse as YAML, a date field must be a date, a version field a
// semantic version.
type MdFrontmatterRule struct {
	*rules.BaseRule
	// Pattern for semver version
	versionPattern *regexp.Regexp
}

// NewMdFrontmatterRule creates the rule
func NewMdFrontmatterRule() *MdFrontmatterRule {
	return &MdFrontmatterRule{
		BaseRule: rules.NewBaseRule(
			"md-frontmatter",
			"documentation",
			"Validates YAML frontmatter in Markdown documents: valid YAML, date as YYYY-MM-DD or RFC 3339, version as semver (skips README.md and files under generated/ and templates/)",
			core.SeverityMedium,
		),
		// Semver: major.minor.patch with optional pre-release
		versionPattern: regexp.MustCompile(`^\d+\.\d+\.\d+(-[\w.]+)?$`),
	}
}

// AnalyzeFile checks frontmatter in Markdown files
func (r *MdFrontmatterRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	// Only process Markdown files
	if !strings.HasSuffix(ctx.Path, ".md") {
		return nil
	}

	// Skip certain directories and files
	if strings.Contains(ctx.Path, "/generated/") ||
		strings.Contains(ctx.Path, "/templates/") ||
		strings.HasSuffix(ctx.Path, "README.md") {
		return nil
	}

	hasFrontmatter, fields, err := r.parseFrontmatter(ctx.Lines)
	if !hasFrontmatter {
		return nil
	}
	if err != nil {
		v := r.CreateViolation(ctx.RelPath, 1, "Frontmatter is not valid YAML: "+err.Error())
		v.WithSuggestion("Fix the YAML between the --- lines")
		return []*core.Violation{v}
	}

	var violations []*core.Violation
	if date, ok := fields["date"]; ok && !isFrontmatterDate(date) {
		v := r.CreateViolation(ctx.RelPath, 1,
			"Invalid date format in frontmatter: "+frontmatterText(date)+"; expected YYYY-MM-DD or an RFC 3339 timestamp")
		v.WithSuggestion("Use ISO 8601 date format: YYYY-MM-DD")
		violations = append(violations, v)
	}
	if version, ok := fields["version"]; ok {
		text, isString := version.(string)
		if !isString || !r.versionPattern.MatchString(strings.TrimSpace(text)) {
			v := r.CreateViolation(ctx.RelPath, 1,
				"Invalid version format in frontmatter: "+frontmatterText(version)+"; expected semver (X.Y.Z)")
			v.WithSuggestion("Use semantic versioning: major.minor.patch")
			violations = append(violations, v)
		}
	}

	return violations
}

// parseFrontmatter finds the frontmatter block - a first line "---" and the
// next "---" line - and decodes it as YAML. A document without a closed block
// has no frontmatter.
func (r *MdFrontmatterRule) parseFrontmatter(lines []string) (bool, map[string]any, error) {
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return false, nil, nil
	}
	endLine := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			endLine = i
			break
		}
	}
	if endLine == -1 {
		return false, nil, nil
	}

	fields := make(map[string]any)
	if err := yaml.Unmarshal([]byte(strings.Join(lines[1:endLine], "\n")), &fields); err != nil {
		return true, nil, fmt.Errorf("decode frontmatter: %w", err)
	}
	return true, fields, nil
}

// isFrontmatterDate reports whether a decoded date field is a date: a YAML
// timestamp, or a string holding YYYY-MM-DD or an RFC 3339 timestamp.
func isFrontmatterDate(value any) bool {
	switch v := value.(type) {
	case time.Time:
		return true
	case string:
		text := strings.TrimSpace(v)
		if _, err := time.Parse(time.DateOnly, text); err == nil {
			return true
		}
		_, err := time.Parse(time.RFC3339, text)
		return err == nil
	}
	return false
}

// frontmatterText renders a decoded field for a message.
func frontmatterText(value any) string {
	if value == nil {
		return "(empty)"
	}
	return fmt.Sprint(value)
}
