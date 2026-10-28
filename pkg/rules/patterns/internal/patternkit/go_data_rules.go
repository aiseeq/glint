package patternkit

import (
	"go/ast"
	"go/constant"
	"go/types"
	"regexp"
	"strings"
)

// GoConstantString returns the value of a constant string expression: with
// type information any constant, without it a string literal.
func GoConstantString(expr ast.Expr, info *types.Info) (string, bool) {
	expr = ast.Unparen(expr)
	if info != nil {
		if tv, ok := info.Types[expr]; ok && tv.Value != nil {
			if tv.Value.Kind() != constant.String {
				return "", false
			}
			return constant.StringVal(tv.Value), true
		}
	}
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return "", false
	}
	return GoStringLiteral(lit)
}

// PrintfVerb is a printf verb with its letter; %% is removed before.
var PrintfVerb = regexp.MustCompile(`%[-+# 0-9.]*([a-zA-Z])`)

// sqlDriverImports are the packages through which Go code runs queries with
// bind parameters.
var sqlDriverImports = []string{"database/sql", "github.com/jmoiron/sqlx", "github.com/jackc/pgx", "gorm.io/gorm"}

// SqlDriverPackage reports a package path of sqlDriverImports or below one.
func SqlDriverPackage(path string) bool {
	for _, driver := range sqlDriverImports {
		if path == driver || strings.HasPrefix(path, driver+"/") {
			return true
		}
	}
	return false
}

var (
	SqlSelectWord   = regexp.MustCompile(`(?i)\bSELECT\b`)
	SqlUnionWord    = regexp.MustCompile(`(?i)\bUNION\b`)
	SqlZeroAsColumn = regexp.MustCompile(`(?i)(?:\bSELECT|,)\s*0(?:\.0+)?(?:\s*::\s*[a-z]+(?:\s*\([\d,\s]+\))?)?\s+AS\s+"?([a-z_][a-z0-9_]*)`)
	SqlMetricWords  = []string{"return", "returns", "profit", "yield", "value", "balance", "amount", "pnl", "gain", "earnings", "income", "revenue", "fee", "fees", "interest"}
)
