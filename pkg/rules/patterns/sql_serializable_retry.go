package patterns

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSQLSerializableNoRetryRule())
}

// SQLSerializableNoRetryRule detects a transaction at SERIALIZABLE or
// REPEATABLE READ in a package that never recognizes a serialization
// failure:
//
//	tx, err := db.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
//
// At these levels PostgreSQL aborts one of two transactions that overlap
// with SQLSTATE 40001 instead of waiting, and expects the application to run
// it again. Without a retry two users signing in at once get an error for
// no fault of theirs. A package retries when some code of its directory
// names the failure: "40001", SerializationFailure, "could not serialize".
// A read-only REPEATABLE READ transaction is not reported: it reads one
// snapshot and has nothing to conflict on.
type SQLSerializableNoRetryRule struct {
	*rules.BaseRule
	// retrying are the directories whose code recognizes the failure.
	retrying map[string]bool
}

// NewSQLSerializableNoRetryRule creates the rule
func NewSQLSerializableNoRetryRule() *SQLSerializableNoRetryRule {
	return &SQLSerializableNoRetryRule{BaseRule: rules.NewBaseRule(
		"sql-serializable-no-retry",
		"patterns",
		"Detects SERIALIZABLE or REPEATABLE READ transactions in a package with no retry on serialization failure (40001)",
		core.SeverityMedium,
	)}
}

var (
	strictIsolation      = map[string]bool{"sql.LevelSerializable": true, "sql.LevelRepeatableRead": true, "pgx.Serializable": true, "pgx.RepeatableRead": true}
	strictIsolationText  = regexp.MustCompile(`(?i)isolation\s+level\s+(?:serializable|repeatable\s+read)`)
	serializationFailure = regexp.MustCompile(`(?i)"40001"|could not serialize|serialization.?failure`)
)

// UseProjectFiles finds the directories whose code recognizes a
// serialization failure.
func (r *SQLSerializableNoRetryRule) UseProjectFiles(files []*core.FileContext) {
	r.retrying = make(map[string]bool)
	for _, ctx := range files {
		if ctx.IsGoFile() && serializationFailure.Match(ctx.Content) {
			r.retrying[filepath.Dir(ctx.RelPath)] = true
		}
	}
}

// ResetState drops the directories of the previous root.
func (r *SQLSerializableNoRetryRule) ResetState() { r.retrying = nil }

// AnalyzeFile reports the strict isolation levels of a package without a retry.
func (r *SQLSerializableNoRetryRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) || r.retrying[filepath.Dir(ctx.RelPath)] {
		return nil
	}
	readOnly := readOnlyRepeatableReads(ctx.GoAST)
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		strict := false
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := node.X.(*ast.Ident); ok {
				strict = strictIsolation[pkg.Name+"."+node.Sel.Name] && !readOnly[node]
			}
		case *ast.BasicLit:
			strict = node.Kind == token.STRING && strictIsolationText.MatchString(node.Value)
		}
		if !strict {
			return true
		}
		line := ctx.LineFor(n)
		if ctx.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(ctx.RelPath, line, "Transaction at SERIALIZABLE/REPEATABLE READ with no retry on serialization failure — PostgreSQL aborts one of two overlapping transactions with 40001 and expects it run again")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Retry the whole transaction a few times when the error has SQLSTATE 40001, or use READ COMMITTED with row locks (SELECT ... FOR UPDATE)")
		violations = append(violations, v)
		return true
	})
	return violations
}

// readOnlyRepeatableReads returns the REPEATABLE READ levels of options that
// also make the transaction read-only: such a transaction reads one snapshot
// and never fails on a serialization conflict.
func readOnlyRepeatableReads(file *ast.File) map[*ast.SelectorExpr]bool {
	exempt := make(map[*ast.SelectorExpr]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		var level *ast.SelectorExpr
		readOnly := false
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			switch value := kv.Value.(type) {
			case *ast.SelectorExpr:
				switch value.Sel.Name {
				case "LevelRepeatableRead", "RepeatableRead":
					level = value
				case "ReadOnly":
					readOnly = true
				}
			case *ast.Ident:
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "ReadOnly" && value.Name == "true" {
					readOnly = true
				}
			}
		}
		if level != nil && readOnly {
			exempt[level] = true
		}
		return true
	})
	return exempt
}
