package doccheck

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDocCompletenessRule())
}

// DocCompletenessRule detects exported symbols without documentation
type DocCompletenessRule struct {
	*rules.BaseRule
	skipTrivial bool // Skip symbols whose own code already says everything
}

// NewDocCompletenessRule creates the rule
func NewDocCompletenessRule() *DocCompletenessRule {
	return &DocCompletenessRule{
		BaseRule: rules.NewBaseRule(
			"doc-missing",
			"documentation",
			"Detects exported types, functions, and methods without documentation comments",
			core.SeverityLow,
		),
		skipTrivial: true,
	}
}

// Configure allows setting rule options
func (r *DocCompletenessRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	if v, ok := settings["skip_trivial"]; ok {
		if skipTrivial, ok := v.(bool); ok {
			r.skipTrivial = skipTrivial
		}
	}
	return nil
}

// AnalyzeFile checks for missing documentation
func (r *DocCompletenessRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	// Skip test files
	if ctx.IsTestFile() {
		return nil
	}
	if strings.HasPrefix(ctx.RelPath, "internal/") {
		return nil
	}

	var violations []*core.Violation

	for _, decl := range ctx.GoAST.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			violations = append(violations, r.checkGenDecl(ctx, d)...)

		case *ast.FuncDecl:
			violations = append(violations, r.checkFuncDecl(ctx, d)...)
		}
	}

	return violations
}

// checkGenDecl checks type and const/var declarations
func (r *DocCompletenessRule) checkGenDecl(ctx *core.FileContext, decl *ast.GenDecl) []*core.Violation {
	var violations []*core.Violation
	enumType := enumGroupType(decl)

	for _, spec := range decl.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			// An alias says which type it stands for, and that type is documented
			if r.skipTrivial && s.Assign.IsValid() {
				continue
			}

			if ast.IsExported(s.Name.Name) && !r.hasDoc(decl.Doc, s.Doc) {
				pos := ctx.PositionFor(s.Name)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Exported type '"+s.Name.Name+"' is missing documentation")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Add a comment starting with the type name: // " + s.Name.Name + " ...")
				v.WithContext("symbol", s.Name.Name)
				v.WithContext("kind", "type")
				violations = append(violations, v)
			}

		case *ast.ValueSpec:
			// Only check if it's a single const/var declaration at top level
			// Skip if there's a group doc comment
			if decl.Doc.Text() != "" && len(decl.Specs) > 1 {
				continue // Group has doc, individual items don't need it
			}

			for _, name := range s.Names {
				// A member of a typed enum repeats the type it belongs to
				if r.skipTrivial && isEnumMember(name.Name, enumType) {
					continue
				}

				if ast.IsExported(name.Name) && !r.hasDoc(decl.Doc, s.Doc) {
					pos := ctx.PositionFor(name)
					v := r.CreateViolation(ctx.RelPath, pos.Line,
						"Exported constant/variable '"+name.Name+"' is missing documentation")
					v.WithCode(ctx.GetLine(pos.Line))
					v.WithSuggestion("Add a comment: // " + name.Name + " ...")
					v.WithContext("symbol", name.Name)
					v.WithContext("kind", "value")
					violations = append(violations, v)
				}
			}
		}
	}

	return violations
}

// enumGroupType returns the type a const group declares, so its members can be
// recognized from the code instead of from a list of domain-specific prefixes.
func enumGroupType(decl *ast.GenDecl) string {
	if decl.Tok != token.CONST || len(decl.Specs) < 2 {
		return ""
	}
	for _, spec := range decl.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		if ident, ok := value.Type.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}

// isEnumMember reports whether the constant names the type it belongs to, the
// Go convention for enums: SeverityLow of type Severity.
func isEnumMember(name, enumType string) bool {
	return enumType != "" && len(name) > len(enumType) && strings.HasPrefix(name, enumType)
}

// checkFuncDecl checks function declarations
func (r *DocCompletenessRule) checkFuncDecl(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation

	// Skip unexported functions
	if !ast.IsExported(fn.Name.Name) {
		return nil
	}

	// Skip main and init
	if fn.Name.Name == "main" || fn.Name.Name == "init" {
		return nil
	}

	if r.skipTrivial && r.isTrivialFunction(fn) {
		return nil
	}

	// Text strips comment markers and drops directives (//go:generate,
	// //nolint), which instruct tools rather than document the function.
	docText := fn.Doc.Text()
	if docText == "" {
		pos := ctx.PositionFor(fn.Name)
		kind := "function"
		if fn.Recv != nil {
			kind = "method"
		}

		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Exported "+kind+" '"+fn.Name.Name+"' is missing documentation")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Add a comment starting with the function name: // " + fn.Name.Name + " ...")
		v.WithContext("symbol", fn.Name.Name)
		v.WithContext("kind", kind)
		return append(violations, v)
	}

	// Check that doc starts with function name (Go convention)
	if !strings.HasPrefix(docText, fn.Name.Name) {
		pos := ctx.PositionFor(fn.Name)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Documentation for '"+fn.Name.Name+"' should start with the function name")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Start comment with: // " + fn.Name.Name + " ...")
		v.WithContext("symbol", fn.Name.Name)
		v.WithContext("kind", "doc-format")
		violations = append(violations, v)
	}

	return violations
}

// standardMethods are the methods whose contract is written in the standard
// library: repeating it in a comment adds nothing.
var standardMethods = map[string]bool{
	"String": true, "Error": true, "Unwrap": true, "Is": true, "As": true,
	"MarshalJSON": true, "UnmarshalJSON": true,
	"MarshalText": true, "UnmarshalText": true,
	"MarshalBinary": true, "UnmarshalBinary": true,
	"MarshalYAML": true, "UnmarshalYAML": true,
	"GobEncode": true, "GobDecode": true,
	"Scan": true, "Value": true, // sql.Scanner, driver.Valuer
	"ServeHTTP": true,                                                // http.Handler
	"Read":      true, "Write": true, "Close": true, "WriteTo": true, // io interfaces
	"ReadFrom": true, "Seek": true, "Flush": true,
	"Len": true, "Less": true, "Swap": true, // sort.Interface
}

// isTrivialFunction reports whether the function's own code already says what a
// comment would. Only two shapes qualify: a method implementing a standard
// library contract, and a method that just hands a field over. A familiar verb
// in the name proves nothing — ProcessSettlement and ProcessRefund share it.
func (r *DocCompletenessRule) isTrivialFunction(fn *ast.FuncDecl) bool {
	if fn.Recv == nil {
		return false
	}
	if standardMethods[fn.Name.Name] {
		return true
	}
	return isFieldAccessor(fn)
}

// isFieldAccessor recognizes a one-statement getter or setter over a receiver
// field: the signature and the field name carry the whole meaning.
func isFieldAccessor(fn *ast.FuncDecl) bool {
	if fn.Body == nil || len(fn.Body.List) != 1 {
		return false
	}
	receiver := receiverName(fn)
	if receiver == "" {
		return false
	}

	switch stmt := fn.Body.List[0].(type) {
	case *ast.ReturnStmt:
		return len(stmt.Results) == 1 && isFieldOf(stmt.Results[0], receiver)
	case *ast.AssignStmt:
		if len(stmt.Lhs) != 1 || len(stmt.Rhs) != 1 || stmt.Tok != token.ASSIGN {
			return false
		}
		_, plainValue := stmt.Rhs[0].(*ast.Ident)
		return plainValue && isFieldOf(stmt.Lhs[0], receiver)
	}
	return false
}

// receiverName returns the name the method gave its receiver, or "" when the
// receiver is unnamed and no field access can refer to it.
func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return ""
	}
	return fn.Recv.List[0].Names[0].Name
}

// isFieldOf reports whether the expression reads a field of the receiver,
// possibly through its address.
func isFieldOf(expr ast.Expr, receiver string) bool {
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = unary.X
	}
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == receiver
}

// hasDoc reports whether the group or the individual doc carries real
// documentation. Text strips comment markers and drops directives
// (//go:generate, //nolint), which instruct tools rather than document the
// symbol — a directive-only doc group counts as no documentation.
func (r *DocCompletenessRule) hasDoc(groupDoc, itemDoc *ast.CommentGroup) bool {
	return groupDoc.Text() != "" || itemDoc.Text() != ""
}
