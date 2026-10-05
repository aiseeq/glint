package duplication

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewHelperOutsideTypePackageRule())
}

// HelperOutsideTypePackageRule detects a function that works only on the
// fields of a type from another package of the module and is kept where it is
// used:
//
//	// plan/mining.go
//	func circles(a, b geom.Point, r float64) (geom.Point, geom.Point, bool) {
//		... math on a.X, a.Y, b.X, b.Y ...
//	}
//
// The next package that needs the same math does not look in plan, does not
// find it in geom, and writes its own copy from another source - the copies
// differ in text, so cross-file-duplicate does not see them. A function
// counts when its signature holds the types of one other package of the
// module and basic types only, its body reads a field of that package's
// types, and it uses nothing of its own package or of a third package of the
// module and is passed by value - a value type (a point, a row of data),
// whose helpers are math on its fields; rules over an entity passed by
// pointer belong to the service that changes it. Calling only the type's methods is using its API, not rebuilding
// it, and is left alone; so are a setter and a function that only builds
// values of the type (rows of data written as literals).
type HelperOutsideTypePackageRule struct {
	*rules.BaseRule
}

// NewHelperOutsideTypePackageRule creates the rule
func NewHelperOutsideTypePackageRule() *HelperOutsideTypePackageRule {
	return &HelperOutsideTypePackageRule{BaseRule: rules.NewBaseRule(
		"helper-outside-type-package",
		"duplication",
		"Detects a function that works only on the fields of another module package's type and lives in a consumer package — the next consumer does not find it and writes another copy",
		core.SeverityLow,
	)}
}

// AnalyzeFile is a no-op: the rule needs the module's packages.
func (r *HelperOutsideTypePackageRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *HelperOutsideTypePackageRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports each helper kept outside the package of its type.
func (r *HelperOutsideTypePackageRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("helper outside type package: nil Go project context")
	}
	local := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg != nil && pkg.Package != nil && !testDoublePackage(pkg.Package.PkgPath) {
			local[pkg.Package.PkgPath] = true
		}
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil {
				continue
			}
			fn, ok := info.Defs[fd.Name].(*types.Func)
			if !ok {
				continue
			}
			home := signatureHome(fn.Signature(), fn.Pkg(), local)
			if home == nil || !readsFieldOf(fd.Body, info, home) || leansElsewhere(fd.Body, info, fn.Pkg(), home, local) || speaksVocabulary(fd.Body) {
				continue
			}
			line := file.LineFor(fd)
			if file.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
				"Function %s works only on the fields of %s types — it belongs in package %s: kept here, the next caller does not find it and writes another copy",
				fd.Name.Name, home.Name(), home.Path()))
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion(fmt.Sprintf("Move it to package %s and call it from here; if %s already has the same function, call that one", home.Name(), home.Name()))
			violations = append(violations, v)
		}
		return violations
	})
}

// signatureHome returns the one other module package whose value types the
// signature holds next to basic types, nil when there is none, more than one,
// a pointer to a named type, or a type of any other kind; a parameter must
// carry it.
func signatureHome(sig *types.Signature, own *types.Package, local map[string]bool) *types.Package {
	var home *types.Package
	ok := true
	note := func(t types.Type) {
		pkg, fine := typePackage(t)
		switch {
		case !fine:
			ok = false
		case pkg == nil:
		case home == nil:
			home = pkg
		case home != pkg:
			ok = false
		}
	}
	for i := range sig.Params().Len() {
		note(sig.Params().At(i).Type())
	}
	inParams := home != nil
	for i := range sig.Results().Len() {
		note(sig.Results().At(i).Type())
	}
	if !ok || !inParams || home == own || !local[home.Path()] {
		return nil
	}
	return home
}

// typePackage returns the package of the named type a type is built from,
// nil for a basic type or error; fine is false for any other type.
func typePackage(t types.Type) (pkg *types.Package, fine bool) {
	switch t := t.(type) {
	case *types.Basic:
		return nil, true
	case *types.Pointer:
		// A pointer carries an entity with state: rules over it belong to the
		// service that changes it, not to the type's package.
		if named, ok := t.Elem().(*types.Named); ok && named.Obj().Pkg() != nil {
			return nil, false
		}
		return typePackage(t.Elem())
	case *types.Slice:
		return typePackage(t.Elem())
	case *types.Array:
		return typePackage(t.Elem())
	case *types.Named:
		if t.Obj().Pkg() == nil {
			return nil, t.Obj().Name() == "error"
		}
		return t.Obj().Pkg(), true
	}
	return nil, false
}

// readsFieldOf reports a field of a home package type read in the body; a
// field only written (a setter) or a value only built (a literal of the type)
// is configuring the type, not rebuilding its math.
func readsFieldOf(body *ast.BlockStmt, info *types.Info, home *types.Package) bool {
	written := make(map[ast.Expr]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && as.Tok != token.DEFINE {
			for _, lhs := range as.Lhs {
				written[unwrapIndex(lhs)] = true
			}
		}
		return true
	})
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && !written[sel] {
			if s := info.Selections[sel]; s != nil && s.Kind() == types.FieldVal && s.Obj().Pkg() == home && !wrappedValue(s) {
				found = true
			}
		}
		return !found
	})
	return found
}

// wrappedValue reports the embedded field of a struct that has no other one
// (Amount{big.Int}): the struct is a scalar, and reading the field is using
// the number, not the type's fields.
func wrappedValue(s *types.Selection) bool {
	field, ok := s.Obj().(*types.Var)
	if !ok || !field.Embedded() || len(s.Index()) != 1 {
		return false
	}
	recv := s.Recv()
	if ptr, ok := recv.Underlying().(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	st, ok := recv.Underlying().(*types.Struct)
	return ok && st.NumFields() == 1
}

// speaksVocabulary reports a body with a non-empty string literal that is not
// a message (a format, the text of an error or a log line): statuses,
// severities and ID suffixes are the consumer's words, so the function is a
// rule of the consumer, not math on the type.
func speaksVocabulary(body *ast.BlockStmt) bool {
	messages := make(map[*ast.BasicLit]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !messageCall.MatchString(calleeName(call)) {
			return true
		}
		for _, arg := range call.Args {
			if lit, ok := arg.(*ast.BasicLit); ok {
				messages[lit] = true
			}
		}
		return true
	})
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if ok && lit.Kind == token.STRING && len(lit.Value) > 2 && !messages[lit] && !strings.Contains(lit.Value, "%") {
			found = true
		}
		return !found
	})
	return found
}

// messageCall names the calls whose string arguments are messages.
var messageCall = regexp.MustCompile(`^(?:Errorf|New|Wrap\w*|Sprint\w*|Print\w*|Fatal\w*|Panic\w*|Debug\w*|Info\w*|Warn\w*|Error\w*|Log\w*)$`)

// calleeName returns the name of the called function or method.
func calleeName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// unwrapIndex returns the expression an index assignment writes into: p.F
// for p.F[k] = v.
func unwrapIndex(e ast.Expr) ast.Expr {
	for {
		ix, ok := e.(*ast.IndexExpr)
		if !ok {
			return e
		}
		e = ix.X
	}
}

// leansElsewhere reports a body that uses a declaration of its own package
// (a function, constant, variable, type, method or field) or of a third
// package of the module: such a function belongs with its own code.
func leansElsewhere(body *ast.BlockStmt, info *types.Info, own, home *types.Package, local map[string]bool) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		obj := info.Uses[id]
		if obj == nil || obj.Pkg() == nil || obj.Pkg() == home {
			return true
		}
		if obj.Pkg() != own {
			found = found || local[obj.Pkg().Path()]
			return !found
		}
		if packageLevel(obj) {
			found = true
		}
		return !found
	})
	return found
}

// packageLevel reports a declaration of the package rather than a local of
// the function: package scope, a method, or a field.
func packageLevel(obj types.Object) bool {
	if obj.Parent() == obj.Pkg().Scope() {
		return true
	}
	switch o := obj.(type) {
	case *types.Func:
		return true
	case *types.Var:
		return o.IsField()
	}
	return false
}
