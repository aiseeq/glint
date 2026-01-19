package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewOrphanedInterfaceRule())
}

// OrphanedInterfaceRule detects interfaces with no implementations or usages
// These are "dead code" interfaces that can be safely removed
type OrphanedInterfaceRule struct {
	*rules.BaseRule
}

// NewOrphanedInterfaceRule creates the rule
func NewOrphanedInterfaceRule() *OrphanedInterfaceRule {
	return &OrphanedInterfaceRule{
		BaseRule: rules.NewBaseRule(
			"orphaned-interface",
			"patterns",
			"Detects interfaces with no implementations or usages in the same file",
			core.SeverityMedium,
		),
	}
}

// interfaceInfo holds information about a declared interface
type interfaceInfo struct {
	name    string
	pos     token.Position
	methods []string // method names for implementation matching
	node    *ast.TypeSpec
}

// AnalyzeFile checks for orphaned interfaces
func (r *OrphanedInterfaceRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if r.shouldSkipFile(ctx) {
		return nil
	}

	if !ctx.HasGoAST() {
		return nil
	}

	// Phase 1: Collect all interfaces
	interfaces := r.collectInterfaces(ctx)
	if len(interfaces) == 0 {
		return nil
	}

	// Phase 2: Find implementations (types with matching methods)
	implementedBy := r.findImplementations(ctx, interfaces)

	// Phase 3: Find usages (params, returns, fields, type assertions)
	usedIn := r.findUsages(ctx, interfaces)

	// Phase 4: Report orphaned interfaces
	var violations []*core.Violation
	for _, iface := range interfaces {
		hasImpl := len(implementedBy[iface.name]) > 0
		hasUsage := usedIn[iface.name]

		if !hasImpl && !hasUsage {
			// Check for nolint or "Used by:" comment
			if r.hasExemptComment(ctx, iface.pos.Line) {
				continue
			}

			v := r.CreateViolation(ctx.RelPath, iface.pos.Line,
				"Interface '"+iface.name+"' has no implementations or usages in this file - potentially orphaned")
			v.Suggestion = "Remove unused interface or add implementations/usages. " +
				"If interface is implemented in other files, consider adding a usage comment."
			violations = append(violations, v)
		}
	}

	return violations
}

// shouldSkipFile checks if file should be excluded
func (r *OrphanedInterfaceRule) shouldSkipFile(ctx *core.FileContext) bool {
	path := ctx.RelPath

	// Skip test files - they may have mock interfaces
	if ctx.IsTestFile() {
		return true
	}

	// Skip vendor, node_modules
	if strings.Contains(path, "vendor/") || strings.Contains(path, "node_modules/") {
		return true
	}

	// Skip generated files
	if strings.Contains(path, "generated") || strings.Contains(path, ".gen.") {
		return true
	}

	// Skip interface definition directories (contracts, interfaces packages)
	// These are meant to be implemented elsewhere
	if strings.Contains(path, "/contracts/") ||
		strings.Contains(path, "/interfaces/") ||
		strings.Contains(path, "contracts/") ||
		strings.Contains(path, "interfaces/") {
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
				methods: r.extractMethodNames(ifaceType),
				node:    typeSpec,
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

// findImplementations checks if any struct types implement the interfaces
func (r *OrphanedInterfaceRule) findImplementations(ctx *core.FileContext, interfaces []*interfaceInfo) map[string][]string {
	// Map: interface name -> list of implementing type names
	implementations := make(map[string][]string)

	// Collect all type declarations and their methods
	typeMethods := make(map[string]map[string]bool) // type name -> method names

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		// Find method declarations
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok || funcDecl.Recv == nil {
			return true
		}

		// Get receiver type name
		recvType := r.getReceiverTypeName(funcDecl.Recv)
		if recvType == "" {
			return true
		}

		if typeMethods[recvType] == nil {
			typeMethods[recvType] = make(map[string]bool)
		}
		typeMethods[recvType][funcDecl.Name.Name] = true

		return true
	})

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

// getReceiverTypeName extracts the type name from a method receiver
func (r *OrphanedInterfaceRule) getReceiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}

	recvType := recv.List[0].Type

	// Handle pointer receiver (*T)
	if starExpr, ok := recvType.(*ast.StarExpr); ok {
		recvType = starExpr.X
	}

	// Get the identifier
	if ident, ok := recvType.(*ast.Ident); ok {
		return ident.Name
	}

	return ""
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

// findUsages checks if interfaces are used anywhere in the file
func (r *OrphanedInterfaceRule) findUsages(ctx *core.FileContext, interfaces []*interfaceInfo) map[string]bool {
	usages := make(map[string]bool)
	interfaceNames := make(map[string]bool)
	for _, iface := range interfaces {
		interfaceNames[iface.name] = true
	}

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		// Function parameters and return types
		case *ast.FuncType:
			r.checkFieldList(node.Params, interfaceNames, usages)
			r.checkFieldList(node.Results, interfaceNames, usages)

		// Struct fields
		case *ast.StructType:
			r.checkFieldList(node.Fields, interfaceNames, usages)

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
