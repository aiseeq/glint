package patternkit

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// CallCreatesError распознаёт вызовы, создающие ошибку: errors.New, fmt.Errorf
// и функции с суффиксом Error/Errorf (NewError, newValidationError, x.Errorf).
// Произвольные подстроки ("new", "fail") не считаются: NewClient() в ветке
// err != nil — это fallback-значение, а не создание ошибки.
func CallCreatesError(call *ast.CallExpr) bool {
	funcName := core.ExtractFullFunctionName(call)
	if funcName == "errors.New" || funcName == "fmt.Errorf" {
		return true
	}

	base := funcName
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		base = base[idx+1:]
	}
	baseLower := strings.ToLower(base)
	return strings.HasSuffix(baseLower, "error") || strings.HasSuffix(baseLower, "errorf")
}
