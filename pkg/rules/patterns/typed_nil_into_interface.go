package patterns

import (
	"errors"
	"go/ast"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/packages"
)

func init() {
	rules.Register(NewTypedNilIntoInterfaceRule())
}

// TypedNilIntoInterfaceRule detects a nil-able concrete pointer handed to an interface.
//
// Указатель, равный nil, уложенный в интерфейс, интерфейсом nil не является: у значения
// есть тип, поэтому `iface == nil` даёт false. Получатель, который отличает отсутствие
// зависимости именно этой проверкой, пропускает её и вызывает метод на nil-получателе.
//
// Реальный случай (projectA, REF-446): сервис доходности принял алертер параметром
// конструктора, и точки сборки стали передавать *email.Service напрямую. Без SMTP это
// nil-указатель. Проверка `if s.anomalyAlerter == nil { return }` его не поймала, и
// первый же аномальный день в истории vault уронил пользовательский график баланса
// паникой вместо того, чтобы просто не отправить письмо.
//
// Правило намеренно узкое, иначе тонет в шуме:
//   - указатель должен где-то в этом же файле сравниваться с nil — иначе считать его
//     пустым нет оснований;
//   - получатель должен зависимость сохранять: конструктор, сеттер или присваивание
//     в интерфейсную переменную. Передача в обходчик вроде ast.Inspect не в счёт;
//   - проверка на nil в Cleanup/Close доказательством не считается: teardown по замыслу
//     переживает частично собранный объект;
//   - присваивание внутри `if ptr != nil { ... }` и код после `if ptr == nil { return }`
//     признаются правильными — это и есть нужная нормализация.
type TypedNilIntoInterfaceRule struct {
	*rules.BaseRule
}

// NewTypedNilIntoInterfaceRule creates the rule.
func NewTypedNilIntoInterfaceRule() *TypedNilIntoInterfaceRule {
	return &TypedNilIntoInterfaceRule{
		BaseRule: rules.NewBaseRule(
			"typed-nil-into-interface",
			"patterns",
			"Detects a nil-able concrete pointer stored in an interface, where a nil check on the interface silently fails",
			core.SeverityHigh,
		),
	}
}

// RequiresSSA reports that typed packages are enough — no SSA program needed.
func (r *TypedNilIntoInterfaceRule) RequiresSSA() bool { return false }

// AnalyzeFile does nothing: nil-ability evidence is collected across the whole project.
func (r *TypedNilIntoInterfaceRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// exprText renders an identifier chain (x, x.y, x.y.z) as text. Пустая строка — выражение
// сложнее цепочки полей, и сопоставлять его по тексту нельзя.
func exprText(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		base := exprText(e.X)
		if base == "" {
			return ""
		}
		return base + "." + e.Sel.Name
	case *ast.ParenExpr:
		return exprText(e.X)
	default:
		return ""
	}
}

// nilComparison reports the operand a comparison checks against nil.
func nilComparison(expr ast.Expr) (operand ast.Expr, equal bool, ok bool) {
	bin, isBinary := expr.(*ast.BinaryExpr)
	if !isBinary {
		return nil, false, false
	}
	op := bin.Op.String()
	if op != "==" && op != "!=" {
		return nil, false, false
	}
	ident, isIdent := bin.Y.(*ast.Ident)
	if !isIdent || ident.Name != "nil" {
		return nil, false, false
	}
	return bin.X, op == "==", true
}

// nilableObject resolves the variable or field an expression refers to. Сопоставлять по
// тексту нельзя: `t` в одной функции и `t` в другой — разные переменные, и проверка на nil
// в одной из них ничего не говорит про остальные.
func nilableObject(pkg *packages.Package, expr ast.Expr) types.Object {
	switch e := expr.(type) {
	case *ast.Ident:
		return pkg.TypesInfo.ObjectOf(e)
	case *ast.SelectorExpr:
		return pkg.TypesInfo.ObjectOf(e.Sel)
	case *ast.ParenExpr:
		return nilableObject(pkg, e.X)
	default:
		return nil
	}
}

// nilOperands splits an `&&`/`||` chain and returns every operand compared with nil,
// разделяя проверки «не пусто» и «пусто»: `if a != nil && b != nil` гарантирует оба
// внутри тела, `if a == nil || b == nil { return }` — оба после выхода.
func nilOperands(pkg *packages.Package, cond ast.Expr, wantEqual bool) []types.Object {
	if bin, ok := cond.(*ast.BinaryExpr); ok {
		op := bin.Op.String()
		if op == "&&" || op == "||" {
			return append(
				nilOperands(pkg, bin.X, wantEqual),
				nilOperands(pkg, bin.Y, wantEqual)...,
			)
		}
	}
	if paren, ok := cond.(*ast.ParenExpr); ok {
		return nilOperands(pkg, paren.X, wantEqual)
	}
	operand, equal, ok := nilComparison(cond)
	if !ok || equal != wantEqual {
		return nil
	}
	if obj := nilableObject(pkg, operand); obj != nil {
		return []types.Object{obj}
	}
	return nil
}

// terminates reports whether a block always leaves the enclosing flow: тогда проверка
// `if x == nil { ... }` работает как гарантия для всего кода ниже.
func terminates(block *ast.BlockStmt) bool {
	if block == nil || len(block.List) == 0 {
		return false
	}
	switch last := block.List[len(block.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return last.Tok.String() == "continue" || last.Tok.String() == "break"
	case *ast.ExprStmt:
		call, ok := last.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		return name == "panic" || name == "Fatal" || name == "Fatalf" || name == "Exit"
	default:
		return false
	}
}

// methodfulInterface reports whether the type is an interface that has methods: пустой
// интерфейс (any) ничего не обещает, и подмена nil на типизированный nil там безобидна.
func methodfulInterface(typ types.Type) bool {
	iface, ok := typ.Underlying().(*types.Interface)
	return ok && iface.NumMethods() > 0
}

// AnalyzeGoProject collects nil-checked pointers, then finds where they enter interfaces.
func (r *TypedNilIntoInterfaceRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("typed nil into interface: nil Go project context")
	}

	// Файлы, исключённые из анализа конфигом, в ctx.Files не попадают, и находку в них
	// нельзя привязать к контексту. Собираем список разрешённых заранее.
	analysed := map[string]bool{}
	for _, file := range ctx.Files {
		if file != nil {
			analysed[file.Path] = true
		}
	}

	var violations []*core.Violation
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil {
			continue
		}
		for _, file := range pkgCtx.Package.Syntax {
			if isGoTestFile(ctx, file) || !analysed[ctx.FileSet.Position(file.Pos()).Filename] {
				continue
			}
			// Доказательство «указатель бывает пустым» берётся из того же файла.
			// Шире брать нельзя: `fn.Body`, `ctx.GoAST` и подобные поля проверяют на nil
			// в сотнях мест по проекту, и любое их использование выглядело бы опасным,
			// хотя проверка стоит в вызывающей функции соседнего пакета.
			nilable := map[types.Object]bool{}
			collectNilablePointers(pkgCtx.Package, file, nilable)
			if len(nilable) == 0 {
				continue
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				w := &typedNilWalker{
					rule: r, ctx: ctx, pkg: pkgCtx.Package,
					nilable: nilable, guarded: map[types.Object]bool{},
				}
				w.walkStmt(fn.Body)
				violations = append(violations, w.found...)
			}
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

// teardownMethods — методы разрушения объекта. Проверка на nil в них не говорит, что
// зависимость бывает пустой в работе: teardown по замыслу переживает частично собранный
// объект и вызывается после сбоя конструктора.
var teardownMethods = map[string]bool{
	"Cleanup": true, "Close": true, "Stop": true, "Shutdown": true,
	"Teardown": true, "TearDown": true, "Dispose": true,
}

// collectNilablePointers records pointer expressions the code itself compares with nil:
// именно про них известно, что они бывают пустыми.
func collectNilablePointers(pkg *packages.Package, file *ast.File, nilable map[types.Object]bool) {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && teardownMethods[fn.Name.Name] {
			continue
		}
		collectNilableInNode(pkg, decl, nilable)
	}
}

// collectNilableInNode walks one declaration looking for nil comparisons over pointers.
func collectNilableInNode(pkg *packages.Package, node ast.Node, nilable map[types.Object]bool) {
	ast.Inspect(node, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		operand, _, ok := nilComparison(bin)
		if !ok {
			return true
		}
		if _, isPointer := pkg.TypesInfo.TypeOf(operand).(*types.Pointer); !isPointer {
			return true
		}
		if obj := nilableObject(pkg, operand); obj != nil {
			nilable[obj] = true
		}
		return true
	})
}

// typedNilWalker walks a function body keeping track of active `x != nil` guards.
type typedNilWalker struct {
	rule    *TypedNilIntoInterfaceRule
	ctx     *core.GoProjectContext
	pkg     *packages.Package
	nilable map[types.Object]bool
	guarded map[types.Object]bool
	found   []*core.Violation
}

// walkStmt descends into a statement structurally. Обход именно по структуре, а не
// сплошным ast.Inspect: гарантии из `if x == nil { continue }` действуют до конца своего
// блока, и потерять границы блоков нельзя — иначе каждый `ast.Inspect(fn.Body, …)` внутри
// цикла с таким continue выглядит как незащищённый.
func (w *typedNilWalker) walkStmt(stmt ast.Stmt) {
	switch s := stmt.(type) {
	case nil:
		return
	case *ast.BlockStmt:
		w.walkBlock(s)
	case *ast.IfStmt:
		w.walkIf(s)
	case *ast.ForStmt:
		w.walkStmt(s.Init)
		w.walkExpr(s.Cond)
		w.walkStmt(s.Post)
		w.walkBlock(s.Body)
	case *ast.RangeStmt:
		w.walkExpr(s.X)
		w.walkBlock(s.Body)
	case *ast.SwitchStmt:
		w.walkStmt(s.Init)
		w.walkExpr(s.Tag)
		w.walkBlock(s.Body)
	case *ast.TypeSwitchStmt:
		w.walkStmt(s.Init)
		w.walkStmt(s.Assign)
		w.walkBlock(s.Body)
	case *ast.SelectStmt:
		w.walkBlock(s.Body)
	case *ast.CaseClause:
		for _, expr := range s.List {
			w.walkExpr(expr)
		}
		w.walkList(s.Body)
	case *ast.CommClause:
		w.walkStmt(s.Comm)
		w.walkList(s.Body)
	case *ast.LabeledStmt:
		w.walkStmt(s.Stmt)
	default:
		w.walkLeaf(stmt)
	}
}

// walkLeaf inspects a statement that carries no nested blocks of its own.
func (w *typedNilWalker) walkLeaf(node ast.Node) {
	ast.Inspect(node, func(n ast.Node) bool {
		switch inner := n.(type) {
		case *ast.FuncLit:
			// Замыкание видит те же гарантии, что и код вокруг него.
			w.walkBlock(inner.Body)
			return false
		case *ast.CallExpr:
			w.checkCall(inner)
		case *ast.AssignStmt:
			w.checkAssign(inner)
		}
		return true
	})
}

// walkExpr inspects an expression for calls and closures.
func (w *typedNilWalker) walkExpr(expr ast.Expr) {
	if expr == nil {
		return
	}
	w.walkLeaf(expr)
}

// walkList walks statements in order, letting early-exit checks widen the guard set.
func (w *typedNilWalker) walkList(list []ast.Stmt) {
	var lifted []types.Object
	defer func() {
		for _, obj := range lifted {
			delete(w.guarded, obj)
		}
	}()

	for _, stmt := range list {
		if ifStmt, ok := stmt.(*ast.IfStmt); ok && terminates(ifStmt.Body) && ifStmt.Else == nil {
			w.walkIf(ifStmt)
			for _, obj := range nilOperands(w.pkg, ifStmt.Cond, true) {
				if !w.guarded[obj] {
					w.guarded[obj] = true
					lifted = append(lifted, obj)
				}
			}
			continue
		}
		w.walkStmt(stmt)
	}
}

// walkBlock walks a block as an ordered statement list.
func (w *typedNilWalker) walkBlock(block *ast.BlockStmt) {
	if block == nil {
		return
	}
	w.walkList(block.List)
}

// walkIf handles the guard form: внутри тела `if x != nil` присваивание x в интерфейс
// корректно, а в else-ветке гарантия обратная.
func (w *typedNilWalker) walkIf(ifStmt *ast.IfStmt) {
	var added []types.Object
	for _, obj := range nilOperands(w.pkg, ifStmt.Cond, false) {
		if !w.guarded[obj] {
			w.guarded[obj] = true
			added = append(added, obj)
		}
	}
	if ifStmt.Body != nil {
		w.walkBlock(ifStmt.Body)
	}
	for _, obj := range added {
		delete(w.guarded, obj)
	}
	w.walkStmt(ifStmt.Else)
}

// checkCall reports pointer arguments handed to interface parameters of a callee that
// stores them. Проверяются конструкторы и сеттеры: опасен не любой указатель, попавший в
// интерфейс, а тот, который получатель кладёт в поле и позже сверяет с nil. Передача узла
// в обходчик вроде ast.Inspect ничего не сохраняет и к этому классу не относится.
func (w *typedNilWalker) checkCall(call *ast.CallExpr) {
	callee := calleeFunc(w.pkg, call)
	if callee == nil {
		return
	}
	if !strings.HasPrefix(callee.Name(), "New") && !strings.HasPrefix(callee.Name(), "Set") {
		return
	}
	sig, ok := callee.Type().(*types.Signature)
	if !ok {
		return
	}
	params := sig.Params()
	for i, arg := range call.Args {
		var paramType types.Type
		switch {
		case sig.Variadic() && i >= params.Len()-1:
			last := params.At(params.Len() - 1).Type()
			slice, isSlice := last.(*types.Slice)
			if !isSlice {
				continue
			}
			paramType = slice.Elem()
		case i < params.Len():
			paramType = params.At(i).Type()
		default:
			continue
		}
		w.report(arg, paramType, callee.Name()+"()")
	}
}

// checkAssign reports pointers assigned to interface-typed variables and fields.
func (w *typedNilWalker) checkAssign(assign *ast.AssignStmt) {
	if len(assign.Lhs) != len(assign.Rhs) {
		return
	}
	for i, lhs := range assign.Lhs {
		w.report(assign.Rhs[i], w.pkg.TypesInfo.TypeOf(lhs), exprText(lhs))
	}
}

// report records a finding when a nil-able pointer lands in a methodful interface.
func (w *typedNilWalker) report(arg ast.Expr, target types.Type, sink string) {
	if target == nil || !methodfulInterface(target) {
		return
	}
	if _, isPointer := w.pkg.TypesInfo.TypeOf(arg).(*types.Pointer); !isPointer {
		return
	}
	obj := nilableObject(w.pkg, arg)
	if obj == nil || !w.nilable[obj] || w.guarded[obj] {
		return
	}
	text := exprText(arg)
	if text == "" {
		text = obj.Name()
	}

	pos := w.ctx.FileSet.Position(arg.Pos())
	rel := pos.Filename
	if w.ctx.ProjectRoot != "" {
		if relPath, err := filepath.Rel(w.ctx.ProjectRoot, pos.Filename); err == nil {
			rel = relPath
		}
	}
	v := w.rule.CreateViolation(rel, pos.Line,
		"Pointer '"+text+"' is checked against nil elsewhere, so it can be empty, and here it goes into the interface behind "+
			sink+" — a nil pointer stored in an interface is not nil, so the receiver's nil check passes and the first method call panics")
	v.WithCode(strings.TrimSpace(text))
	v.WithSuggestion("Normalise before handing it over: return an untyped nil when the pointer is empty (if p == nil { return nil }), or pass the concrete type and let the callee build the interface")
	v.WithContext("pattern", "typed_nil_into_interface")
	v.WithContext("pointer", text)
	w.found = append(w.found, v)
}
