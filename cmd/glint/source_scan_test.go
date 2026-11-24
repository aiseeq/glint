// The checks below read glint's own source with go/parser and match it with
// regular expressions and the rule registry, one goroutine and no analysis:
// nothing for the race detector to find, at several seconds a race build. They
// run in the plain test task; the race build leaves them out.

//go:build !race

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleSettingsDeclared(t *testing.T) {
	exceptions := map[string]map[string]string{
		"duplicate-block":      {"min_block_size": "Configure delegates parsing to the shared blockSizeSetting helper."},
		"cross-file-duplicate": {"min_block_size": "Configure delegates parsing to the shared blockSizeSetting helper."},
		"non-atomic-status-history": {
			"mutation_methods": "The setting key is passed to NameSetSetting through configuredStatusHistoryNames.",
			"history_methods":  "The setting key is passed to NameSetSetting through configuredStatusHistoryNames.",
		},
	}
	defaultExceptions := map[string]map[string]string{
		"duplicate-block":                 {"min_block_size": "Configure reads the setting through blockSizeSetting and applies its fallback there."},
		"cross-file-duplicate":            {"min_block_size": "Configure reads the setting through blockSizeSetting and applies its fallback there."},
		"solid-srp":                       {"infrastructure_areas": "Configure falls back to the package-level default area list."},
		"unused-field":                    {"application": "Configure parses the boolean directly from the raw settings map."},
		"audit-actor-propagation":         {"sinks": "Configure falls back to defaultAuditActorSinks when the list is absent."},
		"default-tag-unread":              {"readers": "NameSetSetting parses the list and has no default argument."},
		"error-string":                    {"proper_nouns": "NameSetSetting parses the list and has no default argument."},
		"migration-duplicate-version":     {"require_pairs": "Configure parses the boolean directly from the raw settings map."},
		"model-not-approved":              {"approved_file": "Configure retains the package-level default path when the key is absent."},
		"multi-write-no-transaction":      {"store_types": "Configure uses the package default regular expression when the key is absent.", "independent_calls": "NameSetSetting has no fallback argument.", "transaction_functions": "NameSetSetting has no fallback argument."},
		"sql-concept-table-outside-owner": {"concepts": "Configure parses the nested list of maps directly from the raw settings map."},
		"ts-period-boundary-by-hand":      {"period_modules": "GetStringListSetting reports presence and has no fallback argument."},
		"duplicate-func-of-library":       {"library_modules": "GetStringListSetting reports presence and has no fallback argument.", "peer_roots": "GetStringListSetting reports presence and has no fallback argument."},
		"non-atomic-status-history":       {"mutation_methods": "NameSetSetting has no fallback argument.", "history_methods": "NameSetSetting has no fallback argument.", "transaction_functions": "NameSetSetting has no fallback argument."},
		"test-external-service":           {"guard_functions": "NameSetSetting has no fallback argument."},
		"unused-internal-export":          {"closed_modules": "NameSetSetting has no fallback argument."},
		"doc-missing":                     {"skip_trivial": "Configure parses the boolean directly from the raw settings map."},
	}
	root, err := filepath.Abs("../../pkg/rules")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	methods := map[string][]*ast.FuncDecl{}
	functions := map[string][]*ast.FuncDecl{}
	constants := map[string]map[string]ast.Expr{}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			if general, ok := decl.(*ast.GenDecl); ok && general.Tok == token.CONST {
				packageDir := filepath.Dir(path)
				if constants[packageDir] == nil {
					constants[packageDir] = map[string]ast.Expr{}
				}
				for _, spec := range general.Specs {
					value := spec.(*ast.ValueSpec)
					for index, name := range value.Names {
						if index < len(value.Values) {
							constants[packageDir][name.Name] = value.Values[index]
						}
					}
				}
			}
			if fn, ok := decl.(*ast.FuncDecl); ok {
				functions[fn.Name.Name] = append(functions[fn.Name.Name], fn)
				if fn.Recv == nil {
					continue
				}
				typ := fn.Recv.List[0].Type
				if star, ok := typ.(*ast.StarExpr); ok {
					typ = star.X
				}
				if ident, ok := typ.(*ast.Ident); ok {
					methods[ident.Name] = append(methods[ident.Name], fn)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules.All() {
		info := rules.GetRuleInfo(rule)
		declared, read := map[string]bool{}, map[string]bool{}
		getterDefaults := map[string][]string{}
		for _, spec := range info.Settings {
			if spec.Key == "" || spec.Type == "" || spec.Description == "" || spec.Example == nil {
				t.Errorf("%s has incomplete setting metadata: %+v", info.Name, spec)
			}
			if declared[spec.Key] {
				t.Errorf("%s declares %q more than once", info.Name, spec.Key)
			}
			declared[spec.Key] = true
		}
		typeOf := reflect.TypeOf(rule)
		if typeOf.Kind() == reflect.Pointer {
			typeOf = typeOf.Elem()
		}
		for _, fn := range methods[typeOf.Name()] {
			// Follow helper calls by name throughout pkg/rules. This includes
			// shared patternkit functions called with the rule as an argument.
			queue := []*ast.FuncDecl{fn}
			visited := map[*ast.FuncDecl]bool{}
			for len(queue) > 0 {
				current := queue[0]
				queue = queue[1:]
				if visited[current] || current.Body == nil {
					continue
				}
				visited[current] = true
				ast.Inspect(current.Body, func(node ast.Node) bool {
					switch expr := node.(type) {
					case *ast.CallExpr:
						name := ""
						localCall := false
						switch called := expr.Fun.(type) {
						case *ast.SelectorExpr:
							name = called.Sel.Name
							if receiver, ok := called.X.(*ast.Ident); ok && receiver.Name != "r" && receiver.Name != "rule" && receiver.Name != "ctx" && receiver.Name != "settings" {
								for _, helper := range functions[name] {
									if helper.Recv == nil {
										queue = append(queue, helper)
									}
								}
							}
						case *ast.Ident:
							name = called.Name
							localCall = true
						}
						if strings.HasSuffix(name, "Setting") && len(expr.Args) > 0 {
							keyArg := 0
							if name == "NameSetSetting" && len(expr.Args) >= 3 {
								keyArg = 2
							}
							if value, ok := expr.Args[keyArg].(*ast.BasicLit); ok && value.Kind == token.STRING {
								key, _ := strconv.Unquote(value.Value)
								read[key] = true
								if strings.HasPrefix(name, "Get") && len(expr.Args) > 1 {
									packageDir := filepath.Dir(fset.Position(current.Pos()).Filename)
									if fallback, ok := staticSettingValue(expr.Args[1], packageDir, constants, map[string]bool{}); ok {
										getterDefaults[key] = append(getterDefaults[key], fallback)
									} else {
										getterDefaults[key] = append(getterDefaults[key], "<dynamic>")
									}
								}
							}
						}
						if localCall && name != "" && !strings.HasSuffix(name, "Setting") {
							for _, helper := range functions[name] {
								if helper.Recv == nil && filepath.Dir(fset.Position(helper.Pos()).Filename) == filepath.Dir(fset.Position(current.Pos()).Filename) {
									queue = append(queue, helper)
								}
							}
						}
					case *ast.IndexExpr:
						ident, ok := expr.X.(*ast.Ident)
						if !ok || ident.Name != "settings" {
							break
						}
						if value, ok := expr.Index.(*ast.BasicLit); ok && value.Kind == token.STRING {
							key, _ := strconv.Unquote(value.Value)
							read[key] = true
						}
					}
					return true
				})
			}
		}
		for key := range exceptions[info.Name] {

			read[key] = true
		}
		for key := range read {
			if !declared[key] {
				t.Errorf("%s reads undeclared setting %q", info.Name, key)
			}
		}
		for key := range declared {
			if !read[key] {
				t.Errorf("%s declares unread setting %q", info.Name, key)
			}
		}
		for key := range declared {
			if len(getterDefaults[key]) == 0 {
				if _, excepted := defaultExceptions[info.Name][key]; !excepted {
					t.Errorf("%s setting %q has no statically checked getter default and no exception reason", info.Name, key)
				}
			}
		}
		for key, fallbacks := range getterDefaults {
			if _, excepted := defaultExceptions[info.Name][key]; excepted {
				continue
			}
			for _, fallback := range fallbacks {
				if fallback != fmt.Sprint(findSettingSpec(info.Settings, key).Default) {
					t.Errorf("%s setting %q declares default %q, getter uses %q", info.Name, key, fmt.Sprint(findSettingSpec(info.Settings, key).Default), fallback)
				}
			}
		}
	}
}

func findSettingSpec(specs []rules.SettingSpec, key string) rules.SettingSpec {
	for _, spec := range specs {
		if spec.Key == key {
			return spec
		}
	}
	return rules.SettingSpec{}
}

func staticSettingValue(expr ast.Expr, packageDir string, constants map[string]map[string]ast.Expr, visiting map[string]bool) (string, bool) {
	switch value := expr.(type) {
	case *ast.BasicLit:
		switch value.Kind {
		case token.STRING:
			decoded, err := strconv.Unquote(value.Value)
			return decoded, err == nil
		case token.INT:
			parsed, err := strconv.ParseInt(strings.ReplaceAll(value.Value, "_", ""), 0, 64)
			if err != nil {
				return "", false
			}
			return fmt.Sprint(parsed), true
		case token.FLOAT:
			parsed, err := strconv.ParseFloat(strings.ReplaceAll(value.Value, "_", ""), 64)
			if err != nil {
				return "", false
			}
			return fmt.Sprint(parsed), true
		}
	case *ast.Ident:
		if value.Name == "true" || value.Name == "false" {
			return value.Name, true
		}
		if visiting[value.Name] {
			return "", false
		}
		expr, ok := constants[packageDir][value.Name]
		if !ok {
			return "", false
		}
		visiting[value.Name] = true
		defer delete(visiting, value.Name)
		return staticSettingValue(expr, packageDir, constants, visiting)
	}
	return "", false
}

// adviceMarker finds a marker example in glint's text: nolint:<rule> or
// <rule>: safe, with the comment opener before it when there is one.
var adviceMarker = regexp.MustCompile(`(?:(?://|#)\s*)?(?:nolint:([a-z][a-z0-9]*(?:-[a-z0-9]+)*)|([a-z][a-z0-9]*(?:-[a-z0-9]+)+):\s?safe\b)`)

// A marker example in glint's advice, copied from the marker to the end of
// the advice, is no reason: the advice leaves the reason to the reader with a
// placeholder, and its own words do not stand in for one.
func TestGlintAdviceMarkersAreNoReason(t *testing.T) {
	found := map[string]bool{}
	for _, dir := range []string{"../../pkg", "../../cmd"} {
		require.NoError(t, filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				text, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				for _, m := range adviceMarker.FindAllStringSubmatchIndex(text, -1) {
					name, end := m[2], m[3] // nolint:<rule>
					if name < 0 {
						name, end = m[4], m[5] // <rule>: safe
					}
					rule := text[name:end]
					found[rule] = true
					assert.False(t, core.SuppressionHasReason(text[m[0]:], rule), "%s: %s", path, text[m[0]:])
				}
				return true
			})
			return nil
		}))
	}
	for _, name := range []string{"broad-exclusion", "allocation-in-hot-function", "reflect-in-hot-function", "runtime-gc-tuning", "nil-di", "any-in-public-contract"} {
		assert.True(t, found[name], "advice of %s carries a marker example", name)
	}
}
