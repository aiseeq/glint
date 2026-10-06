package patterns

import (
	"go/ast"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewOneTimeCodeStoredPlaintextRule())
}

// OneTimeCodeStoredPlaintextRule detects a one-time code inserted into a
// table as it was sent:
//
//	INSERT INTO link_codes (code, user_id, expires_at) VALUES ($1, $2, $3)  -- code, userID, expiresAt
//
// A table with a code and its expiry holds credentials: whoever reads the
// table, a dump of it or a backup can use a live code until it expires, and
// a lookup by equality is open to guessing unless wrong entries are counted.
// Store a digest of the code (sha256 of it) and look it up by the digest.
type OneTimeCodeStoredPlaintextRule struct {
	*rules.BaseRule
}

// NewOneTimeCodeStoredPlaintextRule creates the rule
func NewOneTimeCodeStoredPlaintextRule() *OneTimeCodeStoredPlaintextRule {
	return &OneTimeCodeStoredPlaintextRule{BaseRule: rules.NewBaseRule(
		"one-time-code-stored-plaintext",
		"security",
		"Detects a one-time code or token inserted with its expiry as it was sent — the table, its dumps and backups hold live codes",
		core.SeverityMedium,
	)}
}

var (
	// insertColumnsValues is an INSERT with a column list and one row of values.
	insertColumnsValues = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+[\w."]+\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)`)
	// oneTimeCodeColumn names a column holding a code or token sent to someone.
	oneTimeCodeColumn = regexp.MustCompile(`(?i)^(?:(?:link|login|verification|confirm(?:ation)?|reset|invite|magic|auth|otp|one_?time)_)?(?:code|otp|token|pin)$`)
	// expiryColumn names the column that limits how long the code works.
	expiryColumn = regexp.MustCompile(`(?i)^(?:expires?_at|expiry|expires_on|valid_until|expiration(?:_at)?)$`)
	// sqlParameter is a positional parameter: $1.
	sqlParameter = regexp.MustCompile(`^\$(\d{1,4})$`)
)

// AnalyzeFile reports the INSERTs of a Go file that store a one-time code as
// it came.
func (r *OneTimeCodeStoredPlaintextRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, sc := range sqlCalls(ctx.GoAST) {
		m := insertColumnsValues.FindStringSubmatch(sc.literal.text)
		if m == nil {
			continue
		}
		columns, values := splitSQLList(m[1]), splitSQLList(m[2])
		if len(columns) != len(values) || !hasColumn(columns, expiryColumn) {
			continue
		}
		for i, column := range columns {
			if !oneTimeCodeColumn.MatchString(column) {
				continue
			}
			arg := parameterArgument(sc, values[i])
			if arg == nil {
				continue
			}
			if _, raw := ast.Unparen(arg).(*ast.Ident); !raw {
				continue
			}
			line := ctx.LineFor(sc.call)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line, "One-time code column "+column+" is written as it was sent — the table, its dumps and backups hold live codes")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Store a digest of the code (sha256) and look it up by the digest; count wrong entries and void the code after a few")
			violations = append(violations, v)
		}
	}
	return violations
}

// splitSQLList splits a column or value list on commas, trimmed and unquoted.
func splitSQLList(list string) []string {
	var items []string
	for _, item := range strings.Split(list, ",") {
		items = append(items, strings.Trim(strings.TrimSpace(item), `"`))
	}
	return items
}

func hasColumn(columns []string, name *regexp.Regexp) bool {
	for _, column := range columns {
		if name.MatchString(column) {
			return true
		}
	}
	return false
}

// parameterArgument returns the call argument a $n value binds, or nil.
func parameterArgument(sc sqlCall, value string) ast.Expr {
	m := sqlParameter.FindStringSubmatch(value)
	if m == nil {
		return nil
	}
	if n, err := strconv.Atoi(m[1]); err == nil && !sc.call.Ellipsis.IsValid() && sc.queryArg+n < len(sc.call.Args) {
		return sc.call.Args[sc.queryArg+n]
	}
	return nil
}
