package patternkit

import (
	"go/ast"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// IsDataAccessReceiver распознаёт имена receiver'ов, почти всегда означающих доступ к БД
// (поля/переменные-репозитории/БД). Вызов их методов в цикле — классический N+1.
// Точные короткие имена + camelCase-суффиксы; ctx исключён явно (чтобы ctx.Done/Err не ловить).
func IsDataAccessReceiver(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	if lower == "ctx" {
		return false
	}
	switch lower { // короткие well-known data-access переменные
	case "db", "dbx", "repo", "store", "dao", "querier":
		return true
	}
	for _, suf := range []string{"repository", "repo", "store", "dao", "querier"} {
		if strings.HasSuffix(lower, suf) { // userRepo, txReqRepo, walletStore, fooRepository
			return true
		}
	}
	// *DB / *Db поля (camelCase-граница), напр. ledgerDB — но не случайные слова на "db".
	if strings.HasSuffix(name, "DB") || strings.HasSuffix(name, "Db") {
		return true
	}
	return false
}

// StoragePackages are the packages a database or remote store is reached
// through. "net" stands for every networked client (pgx, Redis, Mongo, HTTP APIs
// all dial through it); database/sql covers the SQL drivers and the ORMs built
// on it. The client modules are listed as well because a dependency is loaded
// from export data, whose import list may omit packages its API never mentions.
var StoragePackages = []string{
	"database/sql",
	"net",
	"github.com/jackc/pgx",
	"github.com/lib/pq",
	"gorm.io/gorm",
	"github.com/jmoiron/sqlx",
	"go.mongodb.org/mongo-driver",
	"github.com/redis/go-redis",
	"go.etcd.io/bbolt",
	"github.com/dgraph-io/badger",
}

var ReadMethod = regexp.MustCompile(`^(?:Get|Find|List|Load|Select|Query|Count|Read|Lookup|Search|Exists|Sum)`)

// EndsInReturn reports a block whose last statement returns.
func EndsInReturn(block *ast.BlockStmt) bool {
	if len(block.List) == 0 {
		return false
	}
	_, ok := block.List[len(block.List)-1].(*ast.ReturnStmt)
	return ok
}

// TypeUnder returns the underlying type of an expression, nil without type
// information.
func TypeUnder(info *types.Info, expr ast.Expr) types.Type {
	if info == nil {
		return nil
	}
	if t := info.TypeOf(expr); t != nil {
		return t.Underlying()
	}
	return nil
}

// LineFromNode resolves a node's source line through the file set. Counting
// newlines in ctx.Content instead was wrong as soon as several files shared a
// file set: positions are offsets into the set, not into one file.
func LineFromNode(ctx *core.FileContext, node ast.Node) int {
	return ctx.LineFor(node)
}
