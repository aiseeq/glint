package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
)

// allowlistName names a list of who or what is let through.
var allowlistName = regexp.MustCompile(`(?i)allow|whitelist|admins?$|admin.*(?:emails|ids|users)|permitted|trusted|operators$`)

// emptyAllowlistPasses returns the ifs of a bool predicate that answer true
// when the allowlist is empty or nil:
//
//	allowed := adminEmails() // nil when ADMIN_EMAILS is unset
//	if allowed == nil { return true }
//
// The allowlist is named so, or read from the environment in the function or
// through a function of the file that reads it.
func emptyAllowlistPasses(file *ast.File, fn *ast.FuncDecl) []*ast.IfStmt {
	if fn.Body == nil || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 || types.ExprString(fn.Type.Results.List[0].Type) != "bool" {
		return nil
	}
	envFuncs := envReadingFuncs(file)
	fromEnv := make(map[string]bool)
	var found []*ast.IfStmt
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if id, ok := node.Lhs[min(i, len(node.Lhs)-1)].(*ast.Ident); ok && readsEnv(rhs, envFuncs) {
					fromEnv[id.Name] = true
				}
			}
		case *ast.IfStmt:
			subject := emptinessSubject(node.Cond)
			if subject == nil || !returnsTrue(node.Body) {
				return true
			}
			id, isIdent := subject.(*ast.Ident)
			if (isIdent && fromEnv[id.Name]) || allowlistName.MatchString(lastName(subject)) {
				found = append(found, node)
			}
		}
		return true
	})
	return found
}

// envReadingFuncs returns the functions of the file that call os.Getenv or
// os.LookupEnv.
func envReadingFuncs(file *ast.File) map[string]bool {
	funcs := make(map[string]bool)
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil && fn.Recv == nil && readsEnv(fn.Body, nil) {
			funcs[fn.Name.Name] = true
		}
	}
	return funcs
}

// readsEnv reports a node that calls os.Getenv/os.LookupEnv or one of funcs.
func readsEnv(node ast.Node, funcs map[string]bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := fun.X.(*ast.Ident); ok && pkg.Name == "os" && (fun.Sel.Name == "Getenv" || fun.Sel.Name == "LookupEnv") {
				found = true
			}
		case *ast.Ident:
			found = funcs[fun.Name]
		}
		return !found
	})
	return found
}

// emptinessSubject returns x of x == nil or len(x) == 0.
func emptinessSubject(cond ast.Expr) ast.Expr {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return nil
	}
	if id, ok := bin.Y.(*ast.Ident); ok && id.Name == "nil" {
		return bin.X
	}
	if lit, ok := bin.Y.(*ast.BasicLit); ok && lit.Value == "0" {
		if call, ok := bin.X.(*ast.CallExpr); ok && len(call.Args) == 1 && isIdentNamed(call.Fun, "len") {
			return call.Args[0]
		}
	}
	return nil
}

// returnsTrue reports a block that ends in return true.
func returnsTrue(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	ret, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	id, ok := ret.Results[0].(*ast.Ident)
	return ok && id.Name == "true"
}
