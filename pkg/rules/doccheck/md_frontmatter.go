package doccheck

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMdFrontmatterRule())
}

// MdFrontmatterRule validates YAML frontmatter in Markdown documents
type MdFrontmatterRule struct {
	*rules.BaseRule
	// Required fields
	requiredFields []string
	// Pattern for old-style metadata (bold labels at start)
	oldMetadataPattern *regexp.Regexp
	// Known metadata keywords (case-insensitive)
	metadataKeywords []string
	// Pattern for valid date format YYYY-MM-DD
	datePattern *regexp.Regexp
	// Pattern for semver version
	versionPattern *regexp.Regexp
}

// NewMdFrontmatterRule creates the rule
func NewMdFrontmatterRule() *MdFrontmatterRule {
	return &MdFrontmatterRule{
		BaseRule: rules.NewBaseRule(
			"md-frontmatter",
			"documentation",
			"Validates YAML frontmatter presence and format in Markdown documents",
			core.SeverityMedium,
		),
		requiredFields: nil,
		// Match lines like **Label:** value (colon inside bold markers)
		oldMetadataPattern: regexp.MustCompile(`^\*\*[^*]+:\*\*`),
		// Known metadata keywords (EN and RU) - only these trigger old-style detection
		metadataKeywords: []string{
			// English
			"version", "date", "updated", "audience", "status", "author",
			"architecture", "priority", "document", "last update",
			// Russian
			"версия", "дата", "обновлено", "обновление", "аудитория", "статус",
			"автор", "архитектура", "приоритет", "документ", "последнее обновление",
		},
		// YYYY-MM-DD format
		datePattern: regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`),
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

	var violations []*core.Violation
	lines := ctx.Lines

	// Check for YAML frontmatter
	hasFrontmatter, _, frontmatterFields := r.parseFrontmatter(lines)

	if hasFrontmatter {
		// Validate date format
		if date, ok := frontmatterFields["date"]; ok {
			if !r.datePattern.MatchString(strings.TrimSpace(date)) {
				v := r.CreateViolation(ctx.RelPath, 1,
					"Invalid date format in frontmatter: "+date+"; expected YYYY-MM-DD")
				v.WithSuggestion("Use ISO 8601 date format: YYYY-MM-DD")
				violations = append(violations, v)
			}
		}

		// Validate version format
		if version, ok := frontmatterFields["version"]; ok {
			if !r.versionPattern.MatchString(strings.TrimSpace(version)) {
				v := r.CreateViolation(ctx.RelPath, 1,
					"Invalid version format in frontmatter: "+version+"; expected semver (X.Y.Z)")
				v.WithSuggestion("Use semantic versioning: major.minor.patch")
				violations = append(violations, v)
			}
		}
	}

	return violations
}

// parseFrontmatter extracts YAML frontmatter from lines
func (r *MdFrontmatterRule) parseFrontmatter(lines []string) (bool, int, map[string]string) {
	fields := make(map[string]string)

	if len(lines) == 0 {
		return false, 0, fields
	}

	// First line must be ---
	if strings.TrimSpace(lines[0]) != "---" {
		return false, 0, fields
	}

	// Find closing ---
	endLine := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			endLine = i
			break
		}
	}

	if endLine == -1 {
		return false, 0, fields
	}

	// Parse YAML fields (simple key: value parsing)
	for i := 1; i < endLine; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first colon
		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			// Remove quotes if present
			value = strings.Trim(value, "\"'")
			fields[key] = value
		}
	}

	return true, endLine, fields
}

// isMetadataKeyword checks if the line contains a known metadata keyword
func (r *MdFrontmatterRule) isMetadataKeyword(line string) bool {
	lower := strings.ToLower(line)
	for _, keyword := range r.metadataKeywords {
		// Check if keyword appears after ** and before :
		if strings.Contains(lower, "**"+keyword+":") ||
			strings.Contains(lower, "**"+keyword+" ") && strings.Contains(lower, ":") {
			return true
		}
	}
	return false
}
