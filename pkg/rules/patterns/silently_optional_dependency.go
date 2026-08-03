package patterns

import (
	"errors"
	"go/ast"
	"go/types"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/packages"
)

func init() {
	rules.Register(NewSilentlyOptionalDependencyRule())
}

// SilentlyOptionalDependencyRule detects a dependency that is injected by a setter, whose
// absence silently switches a feature off, and which at least one construction site cannot
// have received.
//
// Родилось из реального инцидента (REF-446). У сервиса расчёта доходности был метод
// SetAnomalyAlerter, а в детекторе аномалий стояло `if s.anomalyAlerter == nil { return }`.
// Сервис собирался в девяти местах, сеттер звали в восьми — и алерты по аномалиям
// доходности не ушли ни разу за всю историю прода. Ничего не падало и не логировалось:
// фича просто отсутствовала на том экземпляре, который считал ночной пересчёт.
//
// Признаков нужно три сразу, и по отдельности ни один из них не проблема:
//  1. зависимость приходит сеттером, а не в конструктор — её можно не задать;
//  2. её отсутствие проверяется молчаливым `return` — никто не узнает, что не задали;
//  3. точек сборки больше, чем вызовов сеттера — значит хотя бы одна осталась без него.
//
// Третий признак и делает правило точным: сервис с единственной точкой сборки собран
// правильно, и трогать его незачем. Считается по всему проекту, тестовые файлы не в счёт —
// там конструируют без зависимостей намеренно.
type SilentlyOptionalDependencyRule struct {
	*rules.BaseRule
}

// NewSilentlyOptionalDependencyRule creates the rule.
func NewSilentlyOptionalDependencyRule() *SilentlyOptionalDependencyRule {
	return &SilentlyOptionalDependencyRule{
		BaseRule: rules.NewBaseRule(
			"silently-optional-dependency",
			"patterns",
			"Detects a setter-injected dependency that some construction site leaves unset, silently turning a feature off",
			core.SeverityHigh,
		),
	}
}

// RequiresSSA reports that typed packages are enough — no SSA program needed.
func (r *SilentlyOptionalDependencyRule) RequiresSSA() bool { return false }

// AnalyzeFile does nothing: the rule needs the whole project to count construction sites.
func (r *SilentlyOptionalDependencyRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// setterInfo describes one `func (t *T) SetX(v V) { t.f = v }`.
type setterInfo struct {
	owner  *types.Named
	field  string
	method string
	decl   *ast.FuncDecl
	pkg    *packages.Package
}

// depKey identifies a dependency: the type that holds it plus the field name.
type depKey struct {
	owner string
	field string
}

// setterDecl reports the field a pure setter assigns. Метод, который делает что-то ещё,
// кроме присваивания, — не инъекция зависимости, а поведение.
func setterDecl(fn *ast.FuncDecl) (recv, field string, ok bool) {
	if fn.Recv == nil || len(fn.Recv.List) == 0 || fn.Body == nil || fn.Type.Params == nil {
		return "", "", false
	}
	if !strings.HasPrefix(fn.Name.Name, "Set") || len(fn.Type.Params.List) != 1 {
		return "", "", false
	}
	if len(fn.Body.List) != 1 {
		return "", "", false
	}
	assign, ok := fn.Body.List[0].(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return "", "", false
	}
	sel, ok := assign.Lhs[0].(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	recvIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	return recvIdent.Name, sel.Sel.Name, true
}

// silentNilGuardField reports the field of `if x.field == nil { return }` — пустой return
// или ровно `return nil`, без лога и без ошибки. Именно молчаливый выход превращает
// незаданную зависимость в невидимое отсутствие функциональности.
func silentNilGuardField(stmt ast.Stmt) (field string, ok bool) {
	ifStmt, ok := stmt.(*ast.IfStmt)
	if !ok || ifStmt.Init != nil || ifStmt.Else != nil || ifStmt.Body == nil {
		return "", false
	}
	bin, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok || bin.Op.String() != "==" {
		return "", false
	}
	if nilIdent, ok := bin.Y.(*ast.Ident); !ok || nilIdent.Name != "nil" {
		return "", false
	}
	sel, ok := bin.X.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	if _, ok := sel.X.(*ast.Ident); !ok {
		return "", false
	}
	if len(ifStmt.Body.List) != 1 {
		return "", false
	}
	ret, ok := ifStmt.Body.List[0].(*ast.ReturnStmt)
	if !ok {
		return "", false
	}
	if len(ret.Results) == 0 {
		return sel.Sel.Name, true
	}
	if len(ret.Results) == 1 {
		if id, ok := ret.Results[0].(*ast.Ident); ok && id.Name == "nil" {
			return sel.Sel.Name, true
		}
	}
	return "", false
}

// methodKey keys setter call counts by owning type and method name.
func methodKey(owner, method string) depKey {
	return depKey{owner: owner, field: "method:" + method}
}

// namedKey is the stable identity of a type across packages.
func namedKey(named *types.Named) string {
	if named == nil || named.Obj() == nil {
		return ""
	}
	if pkg := named.Obj().Pkg(); pkg != nil {
		return pkg.Path() + "." + named.Obj().Name()
	}
	return named.Obj().Name()
}

// AnalyzeGoProject pairs setters with silent guards, then counts construction sites.
func (r *SilentlyOptionalDependencyRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("silently optional dependency: nil Go project context")
	}

	setters := map[depKey]setterInfo{}
	guarded := map[depKey]bool{}
	fromConstructor := map[depKey]bool{}
	ctorSites := map[string]int{}
	setterCalls := map[depKey]int{}

	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil {
			continue
		}
		pkg := pkgCtx.Package
		for _, file := range pkg.Syntax {
			if isGoTestFile(ctx, file) {
				continue
			}
			r.collectDeclarations(pkg, file, setters, guarded, fromConstructor)
			r.collectCalls(pkg, file, ctorSites, setterCalls)
		}
	}

	var violations []*core.Violation
	for key, setter := range setters {
		if !guarded[key] || fromConstructor[key] {
			continue
		}
		sites := ctorSites[key.owner]
		calls := setterCalls[methodKey(key.owner, setter.method)]
		// Хотя бы одна точка сборки осталась без сеттера. Сервис с единственной
		// точкой сборки, где сеттер зовут, собран правильно — про него молчим.
		if sites < 2 || calls >= sites {
			continue
		}
		v := r.violationFor(ctx, setter, sites, calls)
		if v != nil {
			violations = append(violations, v)
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

// collectDeclarations records setters, silent guards and constructor-assigned fields.
func (r *SilentlyOptionalDependencyRule) collectDeclarations(
	pkg *packages.Package,
	file *ast.File,
	setters map[depKey]setterInfo,
	guarded map[depKey]bool,
	fromConstructor map[depKey]bool,
) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if _, field, ok := setterDecl(fn); ok {
			if owner := r.receiverNamed(pkg, fn); owner != nil {
				setters[depKey{namedKey(owner), field}] = setterInfo{
					owner: owner, field: field, method: fn.Name.Name, decl: fn, pkg: pkg,
				}
			}
		}
		if fn.Recv != nil {
			owner := r.receiverNamed(pkg, fn)
			if owner != nil {
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					stmt, ok := n.(ast.Stmt)
					if !ok {
						return true
					}
					if field, ok := silentNilGuardField(stmt); ok {
						guarded[depKey{namedKey(owner), field}] = true
					}
					return true
				})
			}
			continue
		}
		if !strings.HasPrefix(fn.Name.Name, "New") {
			continue
		}
		// Поле, которое конструктор заполняет сам, опциональным не является.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			owner := namedOf(pkg.TypesInfo.TypeOf(lit))
			if owner == nil {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok {
					fromConstructor[depKey{namedKey(owner), key.Name}] = true
				}
			}
			return true
		})
	}
}

// collectCalls counts construction sites per type and setter calls per dependency.
func (r *SilentlyOptionalDependencyRule) collectCalls(
	pkg *packages.Package,
	file *ast.File,
	ctorSites map[string]int,
	setterCalls map[depKey]int,
) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// Тело самого конструктора и самого сеттера точками вызова не считается.
		isCtor := fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "New")
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := calleeFunc(pkg, call)
			if callee == nil {
				return true
			}
			// Имя поля по имени метода не восстановить (SetEmailService → emailService,
			// SetUserYieldStateRepo → userYieldStateRepo), поэтому вызовы копятся по
			// методу, а сопоставление с полем берётся из объявления сеттера.
			if strings.HasPrefix(callee.Name(), "Set") && callee.Type() != nil {
				if sig, ok := callee.Type().(*types.Signature); ok && sig.Recv() != nil {
					if owner := namedOf(sig.Recv().Type()); owner != nil {
						setterCalls[methodKey(namedKey(owner), callee.Name())]++
					}
				}
				return true
			}
			if !strings.HasPrefix(callee.Name(), "New") || isCtor {
				return true
			}
			sig, ok := callee.Type().(*types.Signature)
			if !ok || sig.Recv() != nil || sig.Results().Len() == 0 {
				return true
			}
			if owner := namedOf(sig.Results().At(0).Type()); owner != nil {
				ctorSites[namedKey(owner)]++
			}
			return true
		})
	}
}

// calleeFunc resolves the function a call refers to, if it is a plain function or method.
func calleeFunc(pkg *packages.Package, call *ast.CallExpr) *types.Func {
	var ident *ast.Ident
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		ident = fun
	case *ast.SelectorExpr:
		ident = fun.Sel
	default:
		return nil
	}
	obj := pkg.TypesInfo.Uses[ident]
	if obj == nil {
		obj = pkg.TypesInfo.Defs[ident]
	}
	fn, _ := obj.(*types.Func)
	return fn
}

// receiverNamed resolves the named type a method hangs on.
func (r *SilentlyOptionalDependencyRule) receiverNamed(pkg *packages.Package, fn *ast.FuncDecl) *types.Named {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return nil
	}
	return namedOf(pkg.TypesInfo.TypeOf(fn.Recv.List[0].Type))
}

// isGoTestFile reports whether the file is a _test.go one.
func isGoTestFile(ctx *core.GoProjectContext, file *ast.File) bool {
	if ctx.FileSet == nil {
		return false
	}
	name := ctx.FileSet.Position(file.Pos()).Filename
	return strings.HasSuffix(name, "_test.go")
}

// violationFor renders the finding at the setter declaration.
func (r *SilentlyOptionalDependencyRule) violationFor(
	ctx *core.GoProjectContext,
	setter setterInfo,
	sites, calls int,
) *core.Violation {
	pos := ctx.FileSet.Position(setter.decl.Pos())
	rel := pos.Filename
	if ctx.ProjectRoot != "" {
		if r, err := filepath.Rel(ctx.ProjectRoot, pos.Filename); err == nil {
			rel = r
		}
	}
	v := r.CreateViolation(rel, pos.Line,
		"Dependency '"+setter.field+"' is injected by "+setter.method+"(), its absence silently skips work, and "+
			strconv.Itoa(sites-calls)+" of "+strconv.Itoa(sites)+" construction sites never call the setter — "+
			"those instances run with the feature off and report nothing")
	v.WithSuggestion("Take the dependency as a constructor parameter: then a construction site cannot appear without deciding about it, and the compiler checks that")
	v.WithContext("pattern", "silently_optional_dependency")
	v.WithContext("field", setter.field)
	v.WithContext("construction_sites", strconv.Itoa(sites))
	v.WithContext("setter_calls", strconv.Itoa(calls))
	return v
}
