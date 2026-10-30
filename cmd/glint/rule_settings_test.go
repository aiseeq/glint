package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func captureRuleOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	file, err := os.CreateTemp(os.TempDir(), "glint-rule-output-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(file.Name()) }()
	old := os.Stdout
	os.Stdout = file
	callErr := fn()
	os.Stdout = old
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	_, copyErr := io.Copy(&output, file)
	_ = file.Close()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	return output.String(), callErr
}

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

func TestRulesCommandShowsSettings(t *testing.T) {
	list, err := captureRuleOutput(t, func() error { return runRules(nil, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list, "settings:") || !strings.Contains(list, "period_modules (string list)") {
		t.Fatalf("settings absent from list:\n%s", list)
	}
	for _, name := range []string{"ts-period-boundary-by-hand", "sql-concept-table-outside-owner"} {
		card, err := captureRuleOutput(t, func() error { return showRule(name) })
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(card, "YAML (.glint.yaml):") || !strings.Contains(card, "settings:") {
			t.Errorf("%s card lacks settings YAML:\n%s", name, card)
		}
		if name == "ts-period-boundary-by-hand" {
			block := card[strings.Index(card, "categories:"):]
			path := filepath.Join(t.TempDir(), ".glint.yaml")
			if err := os.WriteFile(path, []byte(block), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := core.LoadConfig(path)
			if err != nil {
				t.Fatalf("card YAML does not load: %v\n%s", err, block)
			}
			if _, ok := cfg.Categories["patterns"].Rules[name].Settings["period_modules"]; !ok {
				t.Fatalf("card YAML lost period_modules: %+v", cfg.Categories["patterns"].Rules[name])
			}
		}
	}
}

func TestRulesCommandUnknownRule(t *testing.T) {
	err := showRule("clock-bypas")
	if err == nil || !strings.Contains(err.Error(), "clock-bypass") {
		t.Fatalf("expected unknown rule suggestion, got %v", err)
	}
}
