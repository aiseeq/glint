package patterns

import (
	"go/ast"
	"go/token"
)

// TypeInfo holds inferred type information for a variable
type TypeInfo struct {
	IsSlice  bool
	IsMap    bool
	IsTime   bool
	IsError  bool
	IsChan   bool
	TypeName string // e.g., "[]string", "time.Time", "error"
}

// TypeInferrer infers types from AST declarations within a file
type TypeInferrer struct {
	varTypes map[string]TypeInfo
}

// NewTypeInferrer creates a type inferrer and collects type info from the AST
func NewTypeInferrer(file *ast.File) *TypeInferrer {
	ti := &TypeInferrer{
		varTypes: make(map[string]TypeInfo),
	}
	if file != nil {
		ti.collectTypes(file)
	}
	return ti
}

// GetType returns type info for a variable name
func (ti *TypeInferrer) GetType(name string) (TypeInfo, bool) {
	info, ok := ti.varTypes[name]
	return info, ok
}

// IsSlice checks if a variable is a slice
func (ti *TypeInferrer) IsSlice(name string) bool {
	info, ok := ti.varTypes[name]
	return ok && info.IsSlice
}

// IsTime checks if a variable is time.Time
func (ti *TypeInferrer) IsTime(name string) bool {
	info, ok := ti.varTypes[name]
	return ok && info.IsTime
}

// IsAny checks if a variable is any/interface{}
func (ti *TypeInferrer) IsAny(name string) bool {
	info, ok := ti.varTypes[name]
	if !ok {
		return false
	}
	return info.TypeName == "any" || info.TypeName == "interface{}"
}

func (ti *TypeInferrer) collectTypes(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			// var items []string
			// var t time.Time
			ti.processValueSpec(node)

		case *ast.Field:
			// Function parameters and struct fields
			ti.processField(node)

		case *ast.AssignStmt:
			// Short declarations: items := []string{}, t := time.Now()
			if node.Tok == token.DEFINE {
				ti.processAssignment(node)
			}

		case *ast.RangeStmt:
			// for _, item := range items
			ti.processRangeStmt(node)
		}
		return true
	})
}

func (ti *TypeInferrer) processValueSpec(spec *ast.ValueSpec) {
	typeInfo := ti.analyzeTypeExpr(spec.Type)

	// Also check RHS for composite literals
	if typeInfo.TypeName == "" && len(spec.Values) > 0 {
		typeInfo = ti.analyzeExpr(spec.Values[0])
	}

	for _, name := range spec.Names {
		if name.Name != "_" {
			ti.varTypes[name.Name] = typeInfo
		}
	}
}

func (ti *TypeInferrer) processField(field *ast.Field) {
	typeInfo := ti.analyzeTypeExpr(field.Type)
	for _, name := range field.Names {
		if name.Name != "_" {
			ti.varTypes[name.Name] = typeInfo
		}
	}
}

func (ti *TypeInferrer) processAssignment(assign *ast.AssignStmt) {
	for i, lhs := range assign.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}

		var typeInfo TypeInfo
		if i < len(assign.Rhs) {
			typeInfo = ti.analyzeExpr(assign.Rhs[i])
		} else if len(assign.Rhs) == 1 {
			// Multiple returns: a, b := funcReturningTwo()
			typeInfo = ti.analyzeExpr(assign.Rhs[0])
		}

		if typeInfo.TypeName != "" {
			ti.varTypes[ident.Name] = typeInfo
		}
	}
}

func (ti *TypeInferrer) processRangeStmt(rangeStmt *ast.RangeStmt) {
	// The range expression type tells us about the collection
	// but we mainly care about marking the key/value variables
	// For now, skip - could be enhanced later
}

func (ti *TypeInferrer) analyzeTypeExpr(expr ast.Expr) TypeInfo {
	if expr == nil {
		return TypeInfo{}
	}

	switch t := expr.(type) {
	case *ast.ArrayType:
		// []T or [N]T
		return TypeInfo{
			IsSlice:  t.Len == nil, // nil Len means slice, not array
			TypeName: "[]" + ti.typeExprToString(t.Elt),
		}

	case *ast.MapType:
		return TypeInfo{
			IsMap:    true,
			TypeName: "map[" + ti.typeExprToString(t.Key) + "]" + ti.typeExprToString(t.Value),
		}

	case *ast.ChanType:
		return TypeInfo{
			IsChan:   true,
			TypeName: "chan " + ti.typeExprToString(t.Value),
		}

	case *ast.SelectorExpr:
		// time.Time, context.Context, etc.
		if ident, ok := t.X.(*ast.Ident); ok {
			typeName := ident.Name + "." + t.Sel.Name
			return TypeInfo{
				IsTime:   ident.Name == "time" && t.Sel.Name == "Time",
				TypeName: typeName,
			}
		}

	case *ast.Ident:
		// Built-in types or local type names
		name := t.Name
		return TypeInfo{
			IsError:  name == "error",
			TypeName: name, // includes "any" which is alias for interface{}
		}

	case *ast.StarExpr:
		// *T - pointer type
		inner := ti.analyzeTypeExpr(t.X)
		inner.TypeName = "*" + inner.TypeName
		return inner

	case *ast.InterfaceType:
		return TypeInfo{TypeName: "interface{}"}

	case *ast.Ellipsis:
		// ...T (variadic)
		inner := ti.analyzeTypeExpr(t.Elt)
		inner.IsSlice = true
		inner.TypeName = "..." + inner.TypeName
		return inner
	}

	return TypeInfo{}
}

func (ti *TypeInferrer) analyzeExpr(expr ast.Expr) TypeInfo {
	if expr == nil {
		return TypeInfo{}
	}

	switch e := expr.(type) {
	case *ast.Ident:
		// Look up variable in already collected types
		if info, ok := ti.varTypes[e.Name]; ok {
			return info
		}

	case *ast.CompositeLit:
		// []string{}, map[string]int{}, MyStruct{}
		return ti.analyzeTypeExpr(e.Type)

	case *ast.CallExpr:
		// time.Now(), make([]string, 0), append(slice, item)
		return ti.analyzeCallExpr(e)

	case *ast.UnaryExpr:
		// &x, *x
		if e.Op == token.AND {
			inner := ti.analyzeExpr(e.X)
			inner.TypeName = "*" + inner.TypeName
			return inner
		}

	case *ast.SliceExpr:
		// x[1:2] - result is same type as x
		return ti.analyzeExpr(e.X)
	}

	return TypeInfo{}
}

func (ti *TypeInferrer) analyzeCallExpr(call *ast.CallExpr) TypeInfo {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		// time.Now(), time.Parse(), time.Date(), etc.
		if ident, ok := fn.X.(*ast.Ident); ok {
			if ident.Name == "time" {
				switch fn.Sel.Name {
				case "Now", "Parse", "ParseInLocation", "Date", "Unix", "UnixMilli", "UnixMicro":
					return TypeInfo{IsTime: true, TypeName: "time.Time"}
				case "Since", "Until":
					return TypeInfo{TypeName: "time.Duration"}
				}
			}
		}

	case *ast.Ident:
		// Built-in functions
		switch fn.Name {
		case "make":
			// make([]T, len), make(map[K]V), make(chan T)
			if len(call.Args) > 0 {
				return ti.analyzeTypeExpr(call.Args[0])
			}
		case "append":
			// append(slice, items...) returns same type as first arg
			if len(call.Args) > 0 {
				return ti.analyzeExpr(call.Args[0])
			}
		case "new":
			// new(T) returns *T
			if len(call.Args) > 0 {
				inner := ti.analyzeTypeExpr(call.Args[0])
				inner.TypeName = "*" + inner.TypeName
				return inner
			}
		}
	}

	return TypeInfo{}
}

func (ti *TypeInferrer) typeExprToString(expr ast.Expr) string {
	if expr == nil {
		return ""
	}

	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name + "." + t.Sel.Name
		}
	case *ast.StarExpr:
		return "*" + ti.typeExprToString(t.X)
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + ti.typeExprToString(t.Elt)
		}
		return "[...]" + ti.typeExprToString(t.Elt)
	case *ast.MapType:
		return "map[" + ti.typeExprToString(t.Key) + "]" + ti.typeExprToString(t.Value)
	case *ast.InterfaceType:
		return "interface{}"
	}
	return ""
}
