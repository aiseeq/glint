package dbrules

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewSQLConceptTableOwnerRule())
}

// SQLConceptTableOwnerRule detects a query outside a concept's owner that
// reads the concept's table and applies its membership predicate itself:
//
//	// consts/staff.go owns the staff concept.
//	const IsStaffExpr = "EXISTS (SELECT 1 FROM staff s WHERE s.user_id = %s)"
//
//	// alerts/bot.go duplicates the concept.
//	db.Query(`SELECT u.id FROM users u JOIN staff s ON s.user_id = u.id`)
//
// Configure concepts with a table and owner file globs, relative to the
// project root. A concept may also specify a WHERE conjunct that identifies
// membership:
//
//	categories:
//	  patterns:
//	    rules:
//	      sql-concept-table-outside-owner:
//	        settings:
//	          concepts:
//	            - name: staff
//	              table: staff
//	              where: "kind = 'internal'"
//	              files: [consts/staff.go, "repo/**/staff*.go"]
//
// UPDATE, DELETE, and INSERT targets are writes, not reads. An outer join
// without a WHERE null check only fetches columns and is not a finding.
type SQLConceptTableOwnerRule struct {
	*rules.BaseRule
	concepts []sqlConceptOwner
}

type sqlConceptOwner struct {
	name       string
	table      string
	where      string
	whereNorms map[string]bool
	files      []string
}

// NewSQLConceptTableOwnerRule creates the rule.
func NewSQLConceptTableOwnerRule() *SQLConceptTableOwnerRule {
	return &SQLConceptTableOwnerRule{BaseRule: rules.NewBaseRule(
		"sql-concept-table-outside-owner",
		"patterns",
		"Detects SQL that reads a configured concept table outside its owner, duplicating where concept membership is decided",
		core.SeverityMedium,
	)}
}

// Configure reads concept names, tables, optional membership predicates, and owner globs.
func (r *SQLConceptTableOwnerRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.concepts = nil
	raw, ok := settings["concepts"]
	if !ok {
		return nil
	}
	items, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("configure %s: concepts must be a list, got %T", r.Name(), raw)
	}
	for i, item := range items {
		values, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("configure %s: concepts[%d] must be a mapping, got %T", r.Name(), i, item)
		}
		name, _ := values["name"].(string)
		table, _ := values["table"].(string)
		if strings.TrimSpace(table) == "" {
			return fmt.Errorf("configure %s: concepts[%d].table is required", r.Name(), i)
		}
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("configure %s: concepts[%d].name is required", r.Name(), i)
		}
		files, err := conceptOwnerFiles(values["files"])
		if err != nil {
			return fmt.Errorf("configure %s: concepts[%d].files: %w", r.Name(), i, err)
		}
		for _, file := range files {
			if !core.ValidateGlobPattern(file) {
				return fmt.Errorf("configure %s: concepts[%d].files: invalid glob pattern %q", r.Name(), i, file)
			}
		}
		where := ""
		if value, exists := values["where"]; exists {
			var valid bool
			where, valid = value.(string)
			if !valid {
				return fmt.Errorf("configure %s: concepts[%d].where must be a string, got %T", r.Name(), i, value)
			}
		}
		concept := sqlConceptOwner{
			name: name, table: strings.ToLower(strings.TrimSpace(table)), where: where,
			whereNorms: make(map[string]bool), files: files,
		}
		if where != "" {
			for _, conjunct := range sqlschema.ConditionConjuncts(where) {
				concept.whereNorms[conjunct.Norm] = true
			}
			if len(concept.whereNorms) == 0 {
				return fmt.Errorf("configure %s: concepts[%d].where is not a valid SQL condition", r.Name(), i)
			}
		}
		r.concepts = append(r.concepts, concept)
	}
	return nil
}

func conceptOwnerFiles(raw any) ([]string, error) {
	var values []any
	switch files := raw.(type) {
	case []any:
		values = files
	case []string:
		for _, file := range files {
			values = append(values, file)
		}
	default:
		return nil, fmt.Errorf("must be a list of file globs, got %T", raw)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("must be a non-empty list of file globs")
	}
	files := make([]string, 0, len(values))
	for _, value := range values {
		file, ok := value.(string)
		if !ok || strings.TrimSpace(file) == "" {
			return nil, fmt.Errorf("each file glob must be a non-empty string")
		}
		files = append(files, filepath.ToSlash(file))
	}
	return files, nil
}

// AnalyzeFile reports concept table reads in production Go SQL literals.
func (r *SQLConceptTableOwnerRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if len(r.concepts) == 0 || !patternkit.ProductionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	reported := make(map[string]bool)
	for _, literal := range patternkit.SqlLiterals(ctx.GoAST) {
		conjuncts := sqlschema.Conjuncts(literal.Text)
		for _, read := range sqlschema.ReadTables(literal.Text) {
			for _, concept := range r.concepts {
				if !conceptTableMatches(concept.table, read.Table) || isConceptOwner(ctx.RelPath, concept.files) {
					continue
				}
				if read.OuterJoin && !read.NullChecked {
					continue
				}
				if concept.where != "" && !hasConceptPredicate(conjuncts, concept.whereNorms) {
					continue
				}
				line := literal.LineAt(ctx, read.Offset)
				key := fmt.Sprintf("%s:%d:%s", concept.name, line, read.Table)
				if reported[key] || ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				reported[key] = true
				message := fmt.Sprintf("SQL reads the table %s of the concept %s outside its owner (%s) — take the concept from its owner",
					concept.table, concept.name, strings.Join(concept.files, ", "))
				violations = append(violations, patternkit.SqlViolation(r.BaseRule, ctx, line, message,
					"Use the concept's owner to decide membership"))
			}
		}
	}
	return violations
}

func conceptTableMatches(configured, actual string) bool {
	if strings.Contains(configured, ".") {
		return actual == configured
	}
	return actual == configured || strings.HasSuffix(actual, "."+configured)
}

func isConceptOwner(file string, globs []string) bool {
	file = filepath.ToSlash(file)
	for _, glob := range globs {
		if core.MatchGlob(glob, file) {
			return true
		}
	}
	return false
}

func hasConceptPredicate(where []sqlschema.Conjunct, expected map[string]bool) bool {
	for _, conjunct := range where {
		if expected[conjunct.Norm] {
			return true
		}
	}
	return false
}
