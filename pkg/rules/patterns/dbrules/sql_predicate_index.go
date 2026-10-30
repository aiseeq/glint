package dbrules

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

var emptySQLAliasPrefix = regexp.MustCompile(`(?i)(^|\bAND\s*|\()\s*\.`)

// collectSQLPredicateIndex is shared by the SQL and Go copy rules.
func collectSQLPredicateIndex(files []*core.FileContext, values map[string]string) map[string][]predicateConstant {
	index := make(map[string][]predicateConstant)
	functions := make(map[string]*ast.FuncDecl)
	for _, ctx := range files {
		if !patternkit.ProductionGoFile(ctx) {
			continue
		}
		for _, decl := range ctx.GoAST.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				functions[fn.Name.Name] = fn
			}
		}
	}
	for _, ctx := range files {
		if !patternkit.ProductionGoFile(ctx) {
			continue
		}
		for _, decl := range ctx.GoAST.Decls {
			switch x := decl.(type) {
			case *ast.FuncDecl:
				if !predicateName.MatchString(x.Name.Name) || x.Body == nil {
					continue
				}
				for _, returned := range returnedSQLStrings(x, values) {
					if returned.node != nil && returned.expression != "" && returned.predicateSource {
						value := formatVerb.ReplaceAllLiteralString(returned.expression, "$9")
						addPredicateIndex(index, x.Name.Name, ctx, returned.node, value, true)
					}
				}
				context := &sqlStringContext{functions: functions, seen: map[string]bool{x.Name.Name: true}}
				for _, returned := range returnedSQLStringsWithContext(x, values, nil, context) {
					if returned.node != nil && returned.expression != "" {
						value := normalizeSQLPredicateSource(returned.expression)
						addPredicateIndex(index, x.Name.Name, ctx, returned.node, value, false)
					}
				}
			case *ast.GenDecl:
				indexSQLPredicateValueDecl(index, ctx, x, values)
			}
		}
	}
	return index
}

func normalizeSQLPredicateSource(value string) string {
	value = formatVerb.ReplaceAllLiteralString(value, "$9")
	return emptySQLAliasPrefix.ReplaceAllString(value, "$1")
}

func indexSQLPredicateValueDecl(index map[string][]predicateConstant, ctx *core.FileContext, decl *ast.GenDecl, values map[string]string) {
	if decl.Tok != token.CONST && decl.Tok != token.VAR {
		return
	}
	for _, raw := range decl.Specs {
		spec, ok := raw.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range spec.Names {
			if i >= len(spec.Values) || !predicateName.MatchString(name.Name) {
				continue
			}
			if value, ok := constString(spec.Values[i], values); ok {
				addPredicateIndex(index, name.Name, ctx, spec.Values[i], value, true)
			}
		}
	}
}

func addPredicateIndex(index map[string][]predicateConstant, name string, ctx *core.FileContext, at ast.Node, value string, legacy bool) {
	for norm, entries := range collectPredicateAtoms(name, ctx, at, value) {
		for i := range entries {
			entries[i].legacy = legacy
		}
		index[norm] = append(index[norm], entries...)
	}
}

func sqlLiteralPredicateIndex(index map[string][]predicateConstant) map[string][]predicateConstant {
	legacy := make(map[string][]predicateConstant)
	for norm, entries := range index {
		for _, entry := range entries {
			if entry.legacy {
				legacy[norm] = append(legacy[norm], entry)
			}
		}
	}
	return legacy
}

type sqlPredicateSource struct {
	name, path string
	line       int
	norms      map[string]bool
	legacy     bool
}

func sqlPredicateSources(index map[string][]predicateConstant) []sqlPredicateSource {
	byLocation := make(map[string]*sqlPredicateSource)
	for norm, entries := range index {
		for _, entry := range entries {
			key := fmt.Sprintf("%s\x00%s\x00%d\x00%t", entry.name, entry.path, entry.line, entry.legacy)
			source := byLocation[key]
			if source == nil {
				source = &sqlPredicateSource{name: entry.name, path: entry.path, line: entry.line, norms: make(map[string]bool), legacy: entry.legacy}
				byLocation[key] = source
			}
			source.norms[norm] = true
		}
	}
	result := make([]sqlPredicateSource, 0, len(byLocation))
	for _, source := range byLocation {
		if len(source.norms) >= 2 {
			result = append(result, *source)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].name != result[j].name {
			return result[i].name < result[j].name
		}
		if result[i].path != result[j].path {
			return result[i].path < result[j].path
		}
		return result[i].line < result[j].line
	})
	return result
}

func normalizeGoSQLComparison(column string, operator token.Token, value string) string {
	op := "="
	if operator == token.NEQ {
		op = "<>"
	}
	if strings.HasPrefix(value, "'") {
		value = strings.ReplaceAll(strings.Trim(value, "'"), "''", "'")
		value = "'" + strings.ReplaceAll(value, "'", "''") + "'"
	}
	conjuncts := sqlschema.ConditionConjuncts(column + " " + op + " " + value)
	if len(conjuncts) != 1 {
		return ""
	}
	return conjuncts[0].Norm
}
