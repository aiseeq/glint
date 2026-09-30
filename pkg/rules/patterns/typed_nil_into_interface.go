package patterns

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/types/typeutil"
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
// Реальный случай (projectA): сервис доходности принял алертер параметром
// конструктора, и точки сборки стали передавать *email.Service напрямую. Без SMTP это
// nil-указатель. Проверка `if s.anomalyAlerter == nil { return }` его не поймала, и
// первый же аномальный день в истории vault уронил пользовательский график баланса
// паникой вместо того, чтобы просто не отправить письмо.
//
// Правило намеренно узкое, иначе тонет в шуме:
//   - указатель должен где-то в этом же файле сравниваться с nil — иначе считать его
//     пустым нет оснований;
//   - получатель должен зависимость сохранять: присваивание в интерфейсную переменную,
//     поле интерфейсного типа в составном литерале или вызов функции проекта, которая
//     параметр сохраняет (в поле, в литерал, в возвращаемое значение, дальше по цепочке
//     вызовов). Получатель, чьё тело не загружено (стандартная библиотека, внешний
//     модуль), неизвестен — и молчание; передача в обходчик вроде ast.Inspect не в счёт;
//   - проверка на nil в Cleanup/Close доказательством не считается: teardown по замыслу
//     переживает частично собранный объект;
//   - проверка, которая пустой указатель отвергает (ветка возвращает ошибку или
//     паникует), тоже не доказательство: она говорит, что nil там недопустим;
//   - значения этого интерфейсного типа должны где-то в проекте сравниваться с nil:
//     типизированный nil обманывает только такую проверку, без неё держатель вызывает
//     метод так же, как вызвал бы его на самом указателе;
//   - присваивание внутри `if ptr != nil { ... }`, код после `if ptr == nil { return }`
//     и после `if ptr == nil { ptr = &T{} }` (или любого `ptr = &T{}` / `new(T)`)
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

	stores := newParamStores(ctx)
	checkedInterfaces := nilCheckedInterfaces(ctx)
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
					rule: r, ctx: ctx, pkg: pkgCtx.Package, stores: stores,
					nilable: nilable, guarded: map[types.Object]bool{},
					checkedInterfaces: checkedInterfaces,
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

// rejectingNilChecks returns the `p == nil` comparisons whose branch rejects the
// empty pointer: it returns an error or ends the program. Such a check says nil is
// not allowed there, not that the pointer is sometimes empty.
func rejectingNilChecks(pkg *packages.Package, node ast.Node) map[*ast.BinaryExpr]bool {
	rejecting := map[*ast.BinaryExpr]bool{}
	ast.Inspect(node, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || !rejectsBranch(pkg, ifStmt.Body) {
			return true
		}
		for _, check := range disjunctNilChecks(ifStmt.Cond) {
			rejecting[check] = true
		}
		return true
	})
	return rejecting
}

// disjunctNilChecks returns the `x == nil` comparisons any of which alone
// makes the condition true: the condition itself or a disjunct of an || chain.
func disjunctNilChecks(cond ast.Expr) []*ast.BinaryExpr {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok {
		return nil
	}
	if bin.Op == token.LOR {
		return append(disjunctNilChecks(bin.X), disjunctNilChecks(bin.Y)...)
	}
	if _, equal, ok := nilComparison(bin); ok && equal {
		return []*ast.BinaryExpr{bin}
	}
	return nil
}

// rejectsBranch reports whether the block ends by refusing to go on: a return
// whose last result is an error other than nil, or a call that does not return.
func rejectsBranch(pkg *packages.Package, block *ast.BlockStmt) bool {
	if block == nil || len(block.List) == 0 {
		return false
	}
	switch last := block.List[len(block.List)-1].(type) {
	case *ast.ReturnStmt:
		if len(last.Results) == 0 {
			return false
		}
		result := ast.Unparen(last.Results[len(last.Results)-1])
		return !isNilIdent(result) && isErrorValue(result, pkg.TypesInfo)
	case *ast.ExprStmt:
		return stmtNoReturn(last, pkg.TypesInfo, nil) != callReturns
	}
	return false
}

// nilCheckedInterfaces collects the interface types whose values some code of
// the project compares with nil. A typed nil fools only such a check.
func nilCheckedInterfaces(ctx *core.GoProjectContext) *typeutil.Map {
	checked := &typeutil.Map{}
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		info := pkgCtx.Package.TypesInfo
		for _, file := range pkgCtx.Package.Syntax {
			if isGoTestFile(ctx, file) {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				bin, ok := n.(*ast.BinaryExpr)
				if !ok {
					return true
				}
				operand, _, ok := nilComparison(bin)
				if !ok {
					return true
				}
				operandType := info.TypeOf(operand)
				if operandType == nil {
					return true
				}
				if _, isInterface := operandType.Underlying().(*types.Interface); isInterface {
					checked.Set(operandType, true)
				}
				return true
			})
		}
	}
	return checked
}

// collectNilableInNode walks one declaration looking for nil comparisons over pointers.
func collectNilableInNode(pkg *packages.Package, node ast.Node, nilable map[types.Object]bool) {
	rejecting := rejectingNilChecks(pkg, node)
	ast.Inspect(node, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || rejecting[bin] {
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
	stores  *paramStores
	nilable map[types.Object]bool
	guarded map[types.Object]bool
	found   []*core.Violation
	// checkedInterfaces are the interface types some code compares with nil.
	checkedInterfaces *typeutil.Map
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
		case *ast.ValueSpec:
			w.checkValueSpec(inner)
		case *ast.CompositeLit:
			w.checkCompositeLit(inner)
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

	lift := func(obj types.Object) {
		if !w.guarded[obj] {
			w.guarded[obj] = true
			lifted = append(lifted, obj)
		}
	}

	for _, stmt := range list {
		if ifStmt, ok := stmt.(*ast.IfStmt); ok && ifStmt.Else == nil {
			exits := terminates(ifStmt.Body)
			// `if p == nil { return }` and `if p == nil { p = &T{} }` both
			// leave p non-nil after the if.
			var normalized []types.Object
			for _, obj := range nilOperands(w.pkg, ifStmt.Cond, true) {
				if exits || w.assignsNonNil(ifStmt.Body, obj) {
					normalized = append(normalized, obj)
				}
			}
			if exits || len(normalized) > 0 {
				w.walkIf(ifStmt)
				for _, obj := range normalized {
					lift(obj)
				}
				continue
			}
		}
		w.walkStmt(stmt)
		if assign, ok := stmt.(*ast.AssignStmt); ok {
			w.trackAssignedValues(assign, lift)
		}
	}
}

// trackAssignedValues follows assignments to nil-able pointers in a statement
// list: `p = &T{}` or `p = new(T)` makes p non-nil for the statements after
// it, any other value may be nil again.
func (w *typedNilWalker) trackAssignedValues(assign *ast.AssignStmt, lift func(types.Object)) {
	if len(assign.Lhs) != len(assign.Rhs) {
		return
	}
	for i, lhs := range assign.Lhs {
		obj := nilableObject(w.pkg, lhs)
		if obj == nil || !w.nilable[obj] {
			continue
		}
		if w.isNonNilPointer(assign.Rhs[i]) {
			lift(obj)
			continue
		}
		delete(w.guarded, obj)
	}
}

// assignsNonNil reports whether the block assigns obj a non-nil pointer in one
// of its own statements.
func (w *typedNilWalker) assignsNonNil(block *ast.BlockStmt, obj types.Object) bool {
	if block == nil {
		return false
	}
	for _, stmt := range block.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			continue
		}
		for i, lhs := range assign.Lhs {
			if nilableObject(w.pkg, lhs) == obj && w.isNonNilPointer(assign.Rhs[i]) {
				return true
			}
		}
	}
	return false
}

// isNonNilPointer reports an expression that is a non-nil pointer by
// construction: an address (&T{}, &x) or new(T).
func (w *typedNilWalker) isNonNilPointer(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.UnaryExpr:
		return e.Op == token.AND
	case *ast.CallExpr:
		ident, ok := ast.Unparen(e.Fun).(*ast.Ident)
		if !ok {
			return false
		}
		builtin, ok := w.pkg.TypesInfo.Uses[ident].(*types.Builtin)
		return ok && builtin.Name() == "new"
	}
	return false
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
// stores them: опасен не любой указатель, попавший в интерфейс, а тот, который получатель
// сохраняет и позже сверяет с nil. Сохраняет ли — решает тело получателя, а не его имя;
// передача узла в обходчик вроде ast.Inspect ничего не сохраняет и к этому классу не
// относится.
func (w *typedNilWalker) checkCall(call *ast.CallExpr) {
	callee := calleeFunc(w.pkg, call)
	if callee == nil {
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
		if !methodfulInterface(paramType) || !w.stores.storesParam(callee, i) {
			continue
		}
		w.report(arg, paramType, callee.Name()+"()")
	}
}

// checkCompositeLit reports pointers placed in interface-typed fields of a struct
// literal: `&Service{alerter: m}` сохраняет указатель в интерфейс так же, как сеттер.
func (w *typedNilWalker) checkCompositeLit(lit *ast.CompositeLit) {
	litType := w.pkg.TypesInfo.TypeOf(lit)
	if litType == nil {
		return
	}
	st, ok := litType.Underlying().(*types.Struct)
	if !ok {
		return
	}
	typeName := types.TypeString(litType, types.RelativeTo(w.pkg.Types))
	for i, elt := range lit.Elts {
		if kv, isKeyValue := elt.(*ast.KeyValueExpr); isKeyValue {
			key, isIdent := kv.Key.(*ast.Ident)
			if !isIdent {
				continue
			}
			field, isField := w.pkg.TypesInfo.Uses[key].(*types.Var)
			if !isField || !field.IsField() {
				continue
			}
			w.report(kv.Value, field.Type(), typeName+"{"+field.Name()+"}")
			continue
		}
		if i < st.NumFields() {
			w.report(elt, st.Field(i).Type(), typeName+"{"+st.Field(i).Name()+"}")
		}
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

// checkValueSpec reports pointers used as initializers of interface-typed declarations:
// `var a Iface = p` кладёт указатель в интерфейс точно так же, как присваивание.
func (w *typedNilWalker) checkValueSpec(spec *ast.ValueSpec) {
	for i, name := range spec.Names {
		if i >= len(spec.Values) {
			return
		}
		w.report(spec.Values[i], w.pkg.TypesInfo.TypeOf(name), name.Name)
	}
}

// report records a finding when a nil-able pointer lands in a methodful interface.
func (w *typedNilWalker) report(arg ast.Expr, target types.Type, sink string) {
	if target == nil || !methodfulInterface(target) || w.checkedInterfaces.At(target) == nil {
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
	// cmd/glint maps the absolute path to the project-relative one.
	rel := pos.Filename
	v := w.rule.CreateViolation(rel, pos.Line,
		"Pointer '"+text+"' is checked against nil elsewhere, so it can be empty, and here it goes into the interface behind "+
			sink+" — a nil pointer stored in an interface is not nil, so the receiver's nil check passes and the first method call panics")
	v.WithCode(strings.TrimSpace(text))
	v.WithSuggestion("Normalise before handing it over: return an untyped nil when the pointer is empty (if p == nil { return nil }), or pass the concrete type and let the callee build the interface")
	v.WithContext("pattern", "typed_nil_into_interface")
	v.WithContext("pointer", text)
	w.found = append(w.found, v)
}

// paramStores answers whether a function of the project keeps a parameter
// beyond the call: stores it in a field, a map, a package variable or a
// composite literal, returns it, sends it, appends it, or passes it on to a
// function that does. The declarations come from the loaded packages; a
// function whose body is not loaded is unknown and does not store.
type paramStores struct {
	decls   map[*types.Func]paramStoresDecl
	results map[paramStoresKey]bool
}

type paramStoresDecl struct {
	decl *ast.FuncDecl
	info *types.Info
}

type paramStoresKey struct {
	fn    *types.Func
	index int
}

func newParamStores(ctx *core.GoProjectContext) *paramStores {
	stores := &paramStores{
		decls:   make(map[*types.Func]paramStoresDecl),
		results: make(map[paramStoresKey]bool),
	}
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		info := pkgCtx.Package.TypesInfo
		for _, file := range pkgCtx.Package.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				if obj, ok := info.Defs[fn.Name].(*types.Func); ok {
					stores.decls[obj] = paramStoresDecl{decl: fn, info: info}
				}
			}
		}
	}
	return stores
}

// storesParam reports whether fn keeps its index-th argument; an argument past
// the last parameter belongs to the variadic one.
func (s *paramStores) storesParam(fn *types.Func, index int) bool {
	fn = fn.Origin()
	key := paramStoresKey{fn: fn, index: index}
	if result, done := s.results[key]; done {
		return result
	}
	// A recursive chain answers "no" for itself while it is being decided.
	s.results[key] = false
	found, ok := s.decls[fn]
	if !ok {
		return false
	}
	var params []*ast.Ident
	for _, field := range found.decl.Type.Params.List {
		params = append(params, field.Names...)
	}
	if len(params) == 0 {
		return false
	}
	if index >= len(params) {
		index = len(params) - 1
	}
	param := found.info.Defs[params[index]]
	if param == nil {
		return false
	}
	result := s.keeps(found.decl.Body, found.info, param)
	s.results[key] = result
	return result
}

// keeps reports whether the body keeps the value of obj beyond the call,
// following local copies (`x := a`, `for _, x := range a`).
func (s *paramStores) keeps(body *ast.BlockStmt, info *types.Info, obj types.Object) bool {
	tracked := map[types.Object]bool{obj: true}
	queue := []types.Object{obj}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		kept, aliases := s.usesOf(body, info, current)
		if kept {
			return true
		}
		for _, alias := range aliases {
			if !tracked[alias] {
				tracked[alias] = true
				queue = append(queue, alias)
			}
		}
	}
	return false
}

// usesOf classifies every use of obj in the body: whether one of them keeps
// the value, and which local variables receive a copy of it.
func (s *paramStores) usesOf(body *ast.BlockStmt, info *types.Info, obj types.Object) (bool, []types.Object) {
	var aliases []types.Object
	kept := false
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if ident, ok := n.(*ast.Ident); ok && !kept && info.Uses[ident] == obj {
			var alias types.Object
			kept, alias = s.useKeeps(ident, stack, info)
			if alias != nil {
				aliases = append(aliases, alias)
			}
		}
		stack = append(stack, n)
		return true
	})
	return kept, aliases
}

// useKeeps walks up from one use of the value through the expressions that
// carry it (parentheses, composite literals, conversions) to the statement
// that decides its fate.
func (s *paramStores) useKeeps(use ast.Expr, stack []ast.Node, info *types.Info) (bool, types.Object) {
	current := ast.Node(use)
	for i := len(stack) - 1; i >= 0; i-- {
		switch parent := stack[i].(type) {
		case *ast.ParenExpr, *ast.CompositeLit, *ast.KeyValueExpr:
		case *ast.UnaryExpr:
			if parent.Op != token.AND {
				return false, nil
			}
		case *ast.CallExpr:
			if tv, ok := info.Types[parent.Fun]; ok && tv.IsType() {
				break // a conversion carries the value on
			}
			return s.callKeeps(parent, current, info), nil
		case *ast.AssignStmt:
			return assignKeeps(parent.Lhs, parent.Rhs, current, info)
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, len(parent.Names))
			for j, name := range parent.Names {
				lhs[j] = name
			}
			return assignKeeps(lhs, parent.Values, current, info)
		case *ast.RangeStmt:
			if current != parent.X || parent.Tok != token.DEFINE {
				return false, nil
			}
			if value, ok := parent.Value.(*ast.Ident); ok {
				return false, info.Defs[value]
			}
			return false, nil
		case *ast.ReturnStmt:
			return true, nil
		case *ast.SendStmt:
			return current == parent.Value, nil
		default:
			return false, nil
		}
		current = stack[i]
	}
	return false, nil
}

// callKeeps reports whether a call keeps the argument: append does, a project
// function does when it keeps its parameter, anything else is unknown.
func (s *paramStores) callKeeps(call *ast.CallExpr, arg ast.Node, info *types.Info) bool {
	if ident, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if builtin, ok := info.Uses[ident].(*types.Builtin); ok {
			return builtin.Name() == "append" && len(call.Args) > 0 && arg != call.Args[0]
		}
	}
	callee := calleeFromInfo(info, call)
	if callee == nil {
		return false
	}
	for i, candidate := range call.Args {
		if candidate == arg {
			return s.storesParam(callee, i)
		}
	}
	return false
}

// calleeFromInfo resolves the function or method a call invokes.
func calleeFromInfo(info *types.Info, call *ast.CallExpr) *types.Func {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		fn, _ := info.Uses[fun].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		fn, _ := info.Uses[fun.Sel].(*types.Func)
		return fn
	}
	return nil
}

// assignKeeps decides an assignment of the value: into a field, an element,
// a dereferenced pointer or a package variable it is kept; into a local
// variable it is copied, and the copy is followed.
func assignKeeps(lhs, rhs []ast.Expr, value ast.Node, info *types.Info) (bool, types.Object) {
	if len(lhs) != len(rhs) {
		return false, nil
	}
	for i, expr := range rhs {
		if expr != value {
			continue
		}
		ident, ok := ast.Unparen(lhs[i]).(*ast.Ident)
		if !ok {
			return true, nil
		}
		obj := info.ObjectOf(ident)
		if obj == nil || obj.Pkg() == nil {
			return false, nil
		}
		if obj.Parent() == obj.Pkg().Scope() {
			return true, nil
		}
		return false, obj
	}
	return false, nil
}
