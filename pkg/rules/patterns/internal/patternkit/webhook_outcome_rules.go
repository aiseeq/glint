package patternkit

import (
	"go/ast"
)

// OnlyLogs reports a non-empty block made of logger calls alone.
func OnlyLogs(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	for _, stmt := range body.List {
		if !IsLoggerStmt(stmt) {
			return false
		}
	}
	return true
}
