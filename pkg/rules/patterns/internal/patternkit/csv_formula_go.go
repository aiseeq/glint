package patternkit

import (
	"go/ast"
	"regexp"
)

// CsvTextField names a field that holds free text someone typed: a name, a
// description, a comment.
var CsvTextField = regexp.MustCompile(`(?i)name$|title$|description$|label$|comment$|note$|notes$|memo$|reason$|text$|message$|tag$|category$|counterparty$`)

// RowSources returns the functions of the file whose result a csv Write or
// WriteAll takes: writer.WriteAll(summaryRows(report)).
func RowSources(file *ast.File) map[string]bool {
	sources := make(map[string]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		if arg := csvWriteArg(n); arg != nil {
			if call, ok := arg.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok {
					sources[id.Name] = true
				}
			}
		}
		return true
	})
	return sources
}

// csvWriteArg returns the argument of x.Write(arg) or x.WriteAll(arg).
func csvWriteArg(n ast.Node) ast.Expr {
	call, ok := n.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Write" && sel.Sel.Name != "WriteAll") {
		return nil
	}
	return ast.Unparen(call.Args[0])
}

// RawRows returns the row literals of a function that reach a csv write as
// they are: passed to it, through a variable passed to it, or returned by a
// function whose result is written.
func RawRows(fn *ast.FuncDecl, source bool) []*ast.CompositeLit {
	written := make(map[string]bool)
	var rows []*ast.CompositeLit
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch arg := csvWriteArg(n).(type) {
		case *ast.Ident:
			written[arg.Name] = true
		case *ast.CompositeLit:
			rows = append(rows, arg)
		}
		if ret, ok := n.(*ast.ReturnStmt); ok && source {
			for _, result := range ret.Results {
				if lit, ok := ast.Unparen(result).(*ast.CompositeLit); ok {
					rows = append(rows, lit)
				}
			}
		}
		return true
	})
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			id, isIdent := lhs.(*ast.Ident)
			lit, isLit := ast.Unparen(assign.Rhs[i]).(*ast.CompositeLit)
			if isIdent && isLit && written[id.Name] {
				rows = append(rows, lit)
			}
		}
		return true
	})
	return rows
}

// CsvRows returns the rows of a []string or [][]string literal.
func CsvRows(lit *ast.CompositeLit) []*ast.CompositeLit {
	array, ok := lit.Type.(*ast.ArrayType)
	if !ok {
		return nil
	}
	switch elt := array.Elt.(type) {
	case *ast.Ident:
		if elt.Name == "string" {
			return []*ast.CompositeLit{lit}
		}
	case *ast.ArrayType:
		if id, ok := elt.Elt.(*ast.Ident); ok && id.Name == "string" {
			var rows []*ast.CompositeLit
			for _, inner := range lit.Elts {
				if row, ok := inner.(*ast.CompositeLit); ok {
					rows = append(rows, row)
				}
			}
			return rows
		}
	}
	return nil
}

// RawFieldName returns the name of a cell that is a plain variable or field,
// "" for a call, a literal or any other expression.
func RawFieldName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}
