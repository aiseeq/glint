package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewReturnNilErrorRule())
}

// ReturnNilErrorRule detects functions returning (nil, nil) which is often a bug
type ReturnNilErrorRule struct {
	*rules.BaseRule
}

// NewReturnNilErrorRule creates the rule
func NewReturnNilErrorRule() *ReturnNilErrorRule {
	return &ReturnNilErrorRule{
		BaseRule: rules.NewBaseRule(
			"return-nil-error",
			"patterns",
			"Detects (nil, nil) returns which often indicate missing error handling",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *ReturnNilErrorRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ReturnNilErrorRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; a first result declared through a named
// type is judged by its underlying type.
func (r *ReturnNilErrorRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks for (nil, nil) returns. info is nil for a file without type
// information.
func (r *ReturnNilErrorRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	return analyzeGoFunctions(ctx, func(fn *ast.FuncDecl) []*core.Violation {
		if !r.hasErrorReturn(fn) || r.isValidNilNilPattern(fn) || nilIsEmptyFirstResult(fn, info) {
			return nil
		}

		var violations []*core.Violation
		// Returns of a nested closure answer for the closure's own signature.
		forEachOwnStatement(fn.Body, func(stmt ast.Stmt) {
			ret, ok := stmt.(*ast.ReturnStmt)
			if !ok || !r.isNilNilReturn(ret) {
				return
			}
			line := ctx.LineFor(ret)
			if ctx.IsSuppressed(line, r.Name()) {
				return
			}
			v := r.CreateViolation(ctx.RelPath, line, "Returning (nil, nil) - possible missing error")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Return an error or a valid value, not both nil")
			v.WithContext("pattern", "nil_nil_return")
			violations = append(violations, v)
		})
		return violations
	})
}

// nilIsEmptyFirstResult reports whether nil is the empty value of the first
// result: a slice, a map, a channel or a function. (nil, nil) from such a
// function says "nothing", not "an error went missing". Without type
// information only a type spelled out in the signature is known; a named type
// stays unknown and the return is still reported.
func nilIsEmptyFirstResult(fn *ast.FuncDecl, info *types.Info) bool {
	first := fn.Type.Results.List[0].Type
	if info != nil {
		if typ := info.TypeOf(first); typ != nil {
			switch typ.Underlying().(type) {
			case *types.Slice, *types.Map, *types.Chan, *types.Signature:
				return true
			}
			return false
		}
	}
	switch t := first.(type) {
	case *ast.ArrayType:
		return t.Len == nil
	case *ast.MapType, *ast.ChanType, *ast.FuncType:
		return true
	}
	return false
}

// isValidNilNilPattern checks if (nil, nil) return is a valid Go pattern
func (r *ReturnNilErrorRule) isValidNilNilPattern(fn *ast.FuncDecl) bool {
	funcName := fn.Name.Name
	funcNameLower := strings.ToLower(funcName)

	// 1. driver.Valuer interface: Value() returns (nil, nil) for SQL NULL
	// This is the standard Go database pattern
	if funcName == "Value" && r.hasDriverValueReturn(fn) {
		return true
	}

	// 2. "not found" semantics: Get*, Find*, Lookup*, Search*, Existing*
	// Return (nil, nil) when item doesn't exist (vs error for actual failures)
	// Also includes Check*, Validate* - return (nil, nil) for "no issue found"
	notFoundPrefixes := []string{"get", "find", "lookup", "search", "fetch", "load", "existing", "check", "validate"}
	for _, prefix := range notFoundPrefixes {
		if strings.HasPrefix(funcNameLower, prefix) {
			return true
		}
	}

	// 3. "no data, no error" semantics for processing functions
	// Return (nil, nil) when input is nil/empty (no data to process, not an error)
	noDataPrefixes := []string{"parse", "convert", "transform", "serialize", "deserialize", "decode", "encode", "marshal", "unmarshal"}
	for _, prefix := range noDataPrefixes {
		if strings.HasPrefix(funcNameLower, prefix) {
			return true
		}
	}

	// 4. Functions ending with "FromString", "FromBytes", etc.
	// These commonly return (nil, nil) for empty input
	fromSuffixes := []string{"fromstring", "frombytes", "fromjson", "fromxml"}
	for _, suffix := range fromSuffixes {
		if strings.HasSuffix(funcNameLower, suffix) {
			return true
		}
	}

	return false
}

// hasDriverValueReturn checks if function returns (driver.Value, error)
func (r *ReturnNilErrorRule) hasDriverValueReturn(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
		return false
	}

	// Check first return type is driver.Value
	firstResult := fn.Type.Results.List[0]
	sel, ok := firstResult.Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "driver" && sel.Sel.Name == "Value"
}

// hasErrorReturn checks if function has error as last return type
func (r *ReturnNilErrorRule) hasErrorReturn(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) < 2 {
		return false
	}

	// Check last return type is error
	lastResult := fn.Type.Results.List[len(fn.Type.Results.List)-1]
	ident, ok := lastResult.Type.(*ast.Ident)
	if !ok {
		return false
	}

	return ident.Name == "error"
}

// isNilNilReturn checks if return statement returns (nil, nil)
func (r *ReturnNilErrorRule) isNilNilReturn(ret *ast.ReturnStmt) bool {
	return len(ret.Results) == 2 && isNilIdent(ret.Results[0]) && isNilIdent(ret.Results[1])
}
