package patterns

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDeterministicUUIDRule())
}

// DeterministicUUIDRule detects patterns where UUIDs are generated from strings
// (email, namespace) instead of using real UUIDs from the database.
// Principle: "ID always comes from DB, never computed"
type DeterministicUUIDRule struct {
	*rules.BaseRule
	funcNamePatterns []*regexp.Regexp
	codePatterns     []*regexp.Regexp
	stringIDPatterns []*regexp.Regexp
}

// NewDeterministicUUIDRule creates the rule
func NewDeterministicUUIDRule() *DeterministicUUIDRule {
	r := &DeterministicUUIDRule{
		BaseRule: rules.NewBaseRule(
			"deterministic-uuid",
			"patterns",
			"Detects deterministic/synthetic UUID generation from strings instead of using real DB UUIDs",
			core.SeverityHigh,
		),
	}
	r.funcNamePatterns = r.initFuncNamePatterns()
	r.codePatterns = r.initCodePatterns()
	r.stringIDPatterns = r.initStringIDPatterns()
	return r
}

// initFuncNamePatterns detects function names that generate deterministic UUIDs
func (r *DeterministicUUIDRule) initFuncNamePatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`generateDeterministic(?:Admin)?UUID`),
		regexp.MustCompile(`deterministicUUID`),
		regexp.MustCompile(`(?i)uuid.*from.*(?:email|string|hash)`),
	}
}

// initCodePatterns detects code that computes UUIDs from hashes
func (r *DeterministicUUIDRule) initCodePatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// uuid.FromBytes(hash...) — UUID from hash bytes
		regexp.MustCompile(`uuid\.FromBytes\(\s*hash`),
		// sha256.Sum256([]byte( — SHA256 of string for UUID generation
		regexp.MustCompile(`sha256\.Sum256\(\[\]byte\(`),
	}
}

// initStringIDPatterns detects string concatenation as ID
func (r *DeterministicUUIDRule) initStringIDPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// fmt.Sprintf("admin-%s" or "user-%s" — string template as ID
		regexp.MustCompile(`fmt\.Sprintf\(\s*"(?:admin|user)-%s"`),
		// "admin-" + email / "admin-" + variable — string concat as ID
		regexp.MustCompile(`"(?:admin|user)-"\s*\+\s*\w+`),
	}
}

// AnalyzeFile checks for deterministic UUID generation patterns
func (r *DeterministicUUIDRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() {
		return nil
	}
	if r.shouldSkipFile(ctx) {
		return nil
	}

	var violations []*core.Violation

	// AST-based: detect function declarations with deterministic UUID names
	if ctx.HasGoAST() {
		violations = append(violations, r.analyzeAST(ctx)...)
	}

	// Regex-based: detect code patterns
	violations = append(violations, r.analyzeRegex(ctx)...)

	return violations
}

func (r *DeterministicUUIDRule) shouldSkipFile(ctx *core.FileContext) bool {
	path := ctx.RelPath
	// Skip vendor, node_modules, generated
	if strings.Contains(path, "vendor/") || strings.Contains(path, "node_modules/") ||
		strings.Contains(path, "generated") || strings.Contains(path, ".gen.") {
		return true
	}
	return false
}

// analyzeAST detects function declarations with deterministic UUID names
func (r *DeterministicUUIDRule) analyzeAST(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		funcName := funcDecl.Name.Name
		for _, pattern := range r.funcNamePatterns {
			if pattern.MatchString(funcName) {
				pos := ctx.GoFileSet.Position(funcDecl.Pos())
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Function '"+funcName+"' generates deterministic UUID from strings — use real UUID from DB")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Replace with DB lookup: SELECT id FROM users WHERE email = $1")
				violations = append(violations, v)
				break
			}
		}

		return true
	})

	return violations
}

// analyzeRegex detects code patterns via regex
func (r *DeterministicUUIDRule) analyzeRegex(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	seen := make(map[int]bool) // avoid duplicate violations on same line

	for lineNum, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check code patterns (sha256→UUID, uuid.FromBytes)
		for _, pattern := range r.codePatterns {
			if pattern.MatchString(line) && !seen[lineNum] {
				if r.isInUUIDGenerationContext(ctx.Lines, lineNum) {
					v := r.CreateViolation(ctx.RelPath, lineNum+1,
						"Deterministic UUID generation from hash — use real UUID from DB")
					v.WithCode(trimmed)
					v.WithSuggestion("IDs must come from database, never be computed from strings")
					violations = append(violations, v)
					seen[lineNum] = true
				}
			}
		}

		// Check string ID patterns ("admin-" + email)
		for _, pattern := range r.stringIDPatterns {
			if pattern.MatchString(line) && !seen[lineNum] {
				v := r.CreateViolation(ctx.RelPath, lineNum+1,
					"String concatenation used as ID — use real UUID from DB")
				v.WithCode(trimmed)
				v.WithSuggestion("IDs must be real UUIDs from database, not constructed strings")
				violations = append(violations, v)
				seen[lineNum] = true
			}
		}
	}

	return violations
}

// isInUUIDGenerationContext checks if sha256/hash code is related to UUID generation
func (r *DeterministicUUIDRule) isInUUIDGenerationContext(lines []string, lineNum int) bool {
	// Check surrounding 10 lines for UUID-related code
	start := lineNum - 5
	if start < 0 {
		start = 0
	}
	end := lineNum + 5
	if end >= len(lines) {
		end = len(lines) - 1
	}

	uuidIndicators := []string{
		"uuid", "UUID", "FromBytes", "adminUUID", "userID",
		"realUserID", "deterministic", "Deterministic",
	}

	for i := start; i <= end; i++ {
		for _, indicator := range uuidIndicators {
			if strings.Contains(lines[i], indicator) {
				return true
			}
		}
	}

	return false
}
