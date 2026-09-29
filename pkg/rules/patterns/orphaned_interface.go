package patterns

import (
	"errors"
	"go/ast"
	"go/token"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewOrphanedInterfaceRule())
}

// OrphanedInterfaceRule detects interfaces that nothing implements or uses.
// These are "dead code" interfaces that can be safely removed.
//
// The search scope is the whole loaded project: an interface declared in one
// file is routinely used as a field or parameter type in a sibling file,
// implemented in a third one, or consumed by another package. Packages that
// did not type-check (--tolerant) fall back to the syntax of every file of
// their package.
type OrphanedInterfaceRule struct {
	*rules.BaseRule
}

// NewOrphanedInterfaceRule creates the rule
func NewOrphanedInterfaceRule() *OrphanedInterfaceRule {
	return &OrphanedInterfaceRule{
		BaseRule: rules.NewBaseRule(
			"orphaned-interface",
			"patterns",
			"Detects interfaces that nothing in the project implements or uses",
			core.SeverityMedium,
		),
	}
}

// interfaceInfo holds information about a declared interface
type interfaceInfo struct {
	name    string
	pos     token.Position
	spec    *ast.TypeSpec
	methods []string // method names for implementation matching
}

// AnalyzeFile is a no-op: whether an interface is used is a question about
// its package and the packages importing it, answered in AnalyzeGoProject.
func (r *OrphanedInterfaceRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *OrphanedInterfaceRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports interfaces without implementations or usages:
// typed packages are checked against the whole project, untyped files
// against the syntax of their own package.
func (r *OrphanedInterfaceRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New(r.Name() + ": nil Go project context")
	}
	typed, err := r.analyzeTyped(ctx)
	if err != nil {
		return nil, err
	}
	violations := append(typed, r.analyzeUntyped(ctx)...)
	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

// report builds the violation for an orphaned interface unless it is exempt.
func (r *OrphanedInterfaceRule) report(ctx *core.FileContext, iface *interfaceInfo, scope string) *core.Violation {
	if r.hasExemptComment(ctx, iface.pos.Line) {
		return nil
	}
	v := r.CreateViolation(ctx.RelPath, iface.pos.Line,
		"Interface '"+iface.name+"' has no implementations or usages in "+scope+" - potentially orphaned")
	v.Suggestion = "Remove the unused interface, or add the implementation or usage it was declared for."
	return v
}

// shouldSkipFile checks if file should be excluded
func (r *OrphanedInterfaceRule) shouldSkipFile(ctx *core.FileContext) bool {
	path := ctx.RelPath

	// Skip test files - they may have mock interfaces
	if ctx.IsTestFile() {
		return true
	}

	if isVendoredOrGeneratedPath(path) {
		return true
	}

	// Skip interface definition directories (contracts, interfaces packages)
	// These are meant to be implemented elsewhere
	if strings.Contains(path, "contracts/") || strings.Contains(path, "interfaces/") {
		return true
	}

	// Skip files specifically named for interface definitions
	baseName := ctx.BaseName()
	if strings.HasSuffix(baseName, "_interface.go") ||
		strings.HasSuffix(baseName, "_interfaces.go") ||
		baseName == "interfaces.go" ||
		baseName == "interface.go" {
		return true
	}

	return false
}

// hasExemptComment checks if interface has nolint or "Used by:" documentation
func (r *OrphanedInterfaceRule) hasExemptComment(ctx *core.FileContext, line int) bool {
	// Check 5 lines above interface declaration for comments
	for i := max(1, line-5); i <= line; i++ {
		lineContent := ctx.GetLine(i)
		// Check for nolint comment
		if strings.Contains(lineContent, "nolint") {
			return true
		}
		// Check for "Used by:" documentation pattern
		if strings.Contains(lineContent, "Used by:") || strings.Contains(lineContent, "USED BY:") {
			return true
		}
	}
	return false
}

// collectInterfaces finds all interface type declarations
func (r *OrphanedInterfaceRule) collectInterfaces(ctx *core.FileContext) []*interfaceInfo {
	var interfaces []*interfaceInfo

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		genDecl, ok := n.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			return true
		}

		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}

			ifaceType, ok := typeSpec.Type.(*ast.InterfaceType)
			if !ok {
				continue
			}

			// Skip interfaces with common DI/abstraction suffixes
			// These are typically defined in one file and used elsewhere
			name := typeSpec.Name.Name
			if r.isDIInterface(name) {
				continue
			}

			iface := &interfaceInfo{
				name:    name,
				pos:     ctx.PositionFor(typeSpec),
				spec:    typeSpec,
				methods: r.extractMethodNames(ifaceType),
			}
			interfaces = append(interfaces, iface)
		}

		return true
	})

	return interfaces
}

// isDIInterface checks if interface name suggests it's a DI/abstraction interface
// These are typically defined in type files and implemented/used elsewhere
func (r *OrphanedInterfaceRule) isDIInterface(name string) bool {
	diSuffixes := []string{
		"Interface",
		"Service",
		"Repository",
		"Factory",
		"Provider",
		"Manager",
		"Handler",
		"Adapter",
		"Client",
		"Store",
		"Cache",
		"Reader",
		"Writer",
		"Validator",
		"Formatter",
		"Parser",
		"Builder",
		"Registrar",
		"Registry",
		"Checker",
		"Constraint",
		"Rule",
	}

	for _, suffix := range diSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// extractMethodNames gets method names from interface
func (r *OrphanedInterfaceRule) extractMethodNames(ifaceType *ast.InterfaceType) []string {
	var methods []string

	if ifaceType.Methods == nil {
		return methods
	}

	for _, method := range ifaceType.Methods.List {
		// Named method
		for _, name := range method.Names {
			methods = append(methods, name.Name)
		}
		// Embedded interface - we skip these for simplicity
	}

	return methods
}

// findImplementations checks if any types declared in files implement the interfaces
func (r *OrphanedInterfaceRule) findImplementations(files []*ast.File, interfaces []*interfaceInfo) map[string][]string {
	// Map: interface name -> list of implementing type names
	implementations := make(map[string][]string)

	// Collect all type declarations and their methods
	typeMethods := make(map[string]map[string]bool) // type name -> method names

	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			// Find method declarations
			funcDecl, ok := n.(*ast.FuncDecl)
			if !ok || funcDecl.Recv == nil {
				return true
			}

			// Get receiver type name
			recvType := receiverTypeName(funcDecl.Recv)
			if recvType == "" {
				return true
			}

			if typeMethods[recvType] == nil {
				typeMethods[recvType] = make(map[string]bool)
			}
			typeMethods[recvType][funcDecl.Name.Name] = true

			return true
		})
	}

	// Check which types implement which interfaces
	for _, iface := range interfaces {
		if len(iface.methods) == 0 {
			// Empty interface - everything implements it, skip
			continue
		}

		for typeName, methods := range typeMethods {
			if r.implementsInterface(iface.methods, methods) {
				implementations[iface.name] = append(implementations[iface.name], typeName)
			}
		}
	}

	return implementations
}

// implementsInterface checks if a type implements an interface
func (r *OrphanedInterfaceRule) implementsInterface(ifaceMethods []string, typeMethods map[string]bool) bool {
	for _, method := range ifaceMethods {
		if !typeMethods[method] {
			return false
		}
	}
	return true
}

// findUsages checks if interfaces are used anywhere in files. The declaration
// of an interface is not searched: a method returning its own interface is
// not a usage.
func (r *OrphanedInterfaceRule) findUsages(files []*ast.File, interfaces []*interfaceInfo) map[string]bool {
	usages := make(map[string]bool)
	interfaceNames := make(map[string]bool)
	ownSpecs := make(map[*ast.TypeSpec]bool)
	for _, iface := range interfaces {
		interfaceNames[iface.name] = true
		ownSpecs[iface.spec] = true
	}

	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.TypeSpec:
				if ownSpecs[node] {
					return false
				}

			// Function parameters, return types and generic constraints
			case *ast.FuncType:
				r.checkFieldList(node.TypeParams, interfaceNames, usages)
				r.checkFieldList(node.Params, interfaceNames, usages)
				r.checkFieldList(node.Results, interfaceNames, usages)

			// Struct fields
			case *ast.StructType:
				r.checkFieldList(node.Fields, interfaceNames, usages)

			// Embedding into another interface: type B interface { A }.
			// Named methods carry a FuncType and are ignored by checkExpr, so only
			// embedded interface identifiers register as usages here.
			case *ast.InterfaceType:
				r.checkFieldList(node.Methods, interfaceNames, usages)

			// Type assertions: x.(InterfaceName)
			case *ast.TypeAssertExpr:
				if ident, ok := node.Type.(*ast.Ident); ok {
					if interfaceNames[ident.Name] {
						usages[ident.Name] = true
					}
				}

			// Type switch cases
			case *ast.TypeSwitchStmt:
				r.checkTypeSwitchCases(node, interfaceNames, usages)

			// Variable declarations
			case *ast.ValueSpec:
				if node.Type != nil {
					if ident, ok := node.Type.(*ast.Ident); ok {
						if interfaceNames[ident.Name] {
							usages[ident.Name] = true
						}
					}
				}

			// Composite literals (map[InterfaceName]...)
			case *ast.MapType:
				r.checkExpr(node.Key, interfaceNames, usages)
				r.checkExpr(node.Value, interfaceNames, usages)

			// Array/slice types
			case *ast.ArrayType:
				r.checkExpr(node.Elt, interfaceNames, usages)
			}

			return true
		})
	}

	return usages
}

// checkFieldList checks field list for interface usages
func (r *OrphanedInterfaceRule) checkFieldList(fields *ast.FieldList, names map[string]bool, usages map[string]bool) {
	if fields == nil {
		return
	}

	for _, field := range fields.List {
		r.checkExpr(field.Type, names, usages)
	}
}

// checkExpr checks an expression for interface identifier
func (r *OrphanedInterfaceRule) checkExpr(expr ast.Expr, names map[string]bool, usages map[string]bool) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.Ident:
		if names[e.Name] {
			usages[e.Name] = true
		}
	case *ast.StarExpr:
		r.checkExpr(e.X, names, usages)
	case *ast.ArrayType:
		r.checkExpr(e.Elt, names, usages)
	case *ast.MapType:
		r.checkExpr(e.Key, names, usages)
		r.checkExpr(e.Value, names, usages)
	case *ast.ChanType:
		r.checkExpr(e.Value, names, usages)
	case *ast.SelectorExpr:
		// package.Type - check the selector (Type) part
		if names[e.Sel.Name] {
			usages[e.Sel.Name] = true
		}
	}
}

// checkTypeSwitchCases checks type switch for interface usages
func (r *OrphanedInterfaceRule) checkTypeSwitchCases(ts *ast.TypeSwitchStmt, names map[string]bool, usages map[string]bool) {
	if ts.Body == nil {
		return
	}

	for _, stmt := range ts.Body.List {
		caseClause, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}

		for _, expr := range caseClause.List {
			r.checkExpr(expr, names, usages)
		}
	}
}
