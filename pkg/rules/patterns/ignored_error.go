package patterns

import (
	"errors"
	"go/ast"
	"go/types"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewIgnoredErrorRule())
}

// IgnoredErrorRule detects error values thrown away with the blank identifier.
//
// Whether a returned value is an error is decided by its type, not by the name of the
// function returning it. The name-based version of this rule matched a fixed list of verbs
// (Read, Parse, Query, Marshal…) and therefore stayed silent on every domain method — the
// shape `items, _ = repo.List(ctx)` reads as "no data" downstream while the query may well
// have failed (REF-462).
//
// Closing a resource stays exempt: `_ = conn.Close()` and the print family cannot report
// anything useful to the caller, and writing the blank there is the documented way to say
// "checked and deliberately dropped".
type IgnoredErrorRule struct {
	*rules.BaseRule
}

// NewIgnoredErrorRule creates a new ignored error detector
func NewIgnoredErrorRule() *IgnoredErrorRule {
	return &IgnoredErrorRule{
		BaseRule: rules.NewBaseRule(
			"ignored-error",
			"patterns",
			"Detects error values that are explicitly ignored with blank identifier",
			core.SeverityMedium,
		),
	}
}

// RequiresSSA reports that plain type information is enough.
func (r *IgnoredErrorRule) RequiresSSA() bool { return false }

// AnalyzeFile is unused: the rule works on the typed project.
func (r *IgnoredErrorRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// AnalyzeGoProject walks assignments and reports blanks that swallow an error value.
func (r *IgnoredErrorRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("ignored error: nil Go project context")
	}

	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Package.Syntax {
			fileCtx, err := ctx.FileForPosition(file.Pos())
			if err != nil || fileCtx == nil {
				continue
			}
			if r.shouldSkipFile(fileCtx) {
				continue
			}
			violations = append(violations, r.analyzeFile(fileCtx, file, pkg.Package.TypesInfo)...)
		}
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

func (r *IgnoredErrorRule) shouldSkipFile(ctx *core.FileContext) bool {
	if ctx.IsTestFile() {
		return true
	}
	// Тестовая обвязка вне *_test.go: хелперы, фикстуры, генераторы данных.
	pathLower := strings.ToLower(ctx.RelPath)
	return strings.Contains(pathLower, "/test") || strings.Contains(pathLower, "test_") ||
		strings.HasSuffix(pathLower, "/testing.go")
}

func (r *IgnoredErrorRule) analyzeFile(fileCtx *core.FileContext, file *ast.File, info *types.Info) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if v := r.checkAssign(fileCtx, assign, info); v != nil {
			violations = append(violations, v)
		}
		return true
	})

	return violations
}

func (r *IgnoredErrorRule) checkAssign(fileCtx *core.FileContext, assign *ast.AssignStmt, info *types.Info) *core.Violation {
	pos := fileCtx.PositionFor(assign)
	line := fileCtx.GetLine(pos.Line)
	// nolint пишут и на самой строке, и комментарием над ней — принимаем оба места.
	if hasSuppression(line) || hasSuppression(fileCtx.GetLine(pos.Line-1)) {
		return nil
	}

	for i, lhs := range assign.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name != "_" {
			continue
		}
		call, ignored := ignoredValue(assign, i, info)
		if call == nil || ignored == nil || !isErrorType(ignored) {
			continue
		}
		funcName := core.ExtractFullFunctionName(call)
		if isKnownSafeToIgnore(funcName) {
			continue
		}

		v := r.CreateViolation(fileCtx.RelPath, pos.Line, "Error from "+funcName+" is dropped into the blank identifier")
		v.WithCode(strings.TrimSpace(line))
		v.WithSuggestion("Handle the error, or return it to the caller so a failure is not read as empty data")
		return v
	}

	return nil
}

// ignoredValue returns the call feeding the i-th assignment target and the type
// landing there — for both `a, _ := f()` and `a, _ := f(), g()`.
func ignoredValue(assign *ast.AssignStmt, i int, info *types.Info) (*ast.CallExpr, types.Type) {
	if len(assign.Rhs) == 1 && len(assign.Lhs) > 1 {
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return nil, nil
		}
		tuple, ok := info.TypeOf(call).(*types.Tuple)
		if !ok || i >= tuple.Len() {
			return nil, nil
		}
		return call, tuple.At(i).Type()
	}

	if i >= len(assign.Rhs) {
		return nil, nil
	}
	call, ok := assign.Rhs[i].(*ast.CallExpr)
	if !ok {
		return nil, nil
	}
	return call, info.TypeOf(call)
}

func isErrorType(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Pkg() == nil && obj.Name() == "error"
}

// hasSuppression распознаёт явное «проверено, выброшено осознанно».
func hasSuppression(line string) bool {
	return strings.Contains(line, "nolint") || strings.Contains(line, "errcheck")
}

func isKnownSafeToIgnore(funcName string) bool {
	// Печать и закрытие ресурса: вызывающему такая ошибка ничего не даёт, а blank
	// на этом месте — общепринятая пометка «проверено, осознанно выброшено».
	safeSuffixes := []string{
		"Printf", "Println", "Print",
		"Fprintf", "Fprintln", "Fprint",
		"Close",
		// Откат транзакции идёт по пути, где ошибка уже произошла: сообщать о
		// провале отката некому, а исходную ошибку он не заменяет.
		"Rollback",
	}

	for _, suffix := range safeSuffixes {
		if strings.HasSuffix(funcName, suffix) {
			return true
		}
	}

	return false
}
