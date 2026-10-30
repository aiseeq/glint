package gorules

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewDefaultTagUnreadRule())
}

// defaultTagReaders are the libraries that read the default key of a struct
// tag: configuration and flag loaders, defaults setters, API schema
// generators. A library that keeps its default in a key of its own
// (cleanenv's env-default, caarlos0/env's envDefault) or inside its tag
// (env:"X,default=1") is not one of them.
var defaultTagReaders = []string{
	"github.com/kelseyhightower/envconfig",
	"github.com/creasty/defaults",
	"github.com/mcuadros/go-defaults",
	"github.com/alexflint/go-arg",
	"github.com/jessevdk/go-flags",
	"github.com/alecthomas/kong",
	"github.com/jinzhu/configor",
	"github.com/gookit/config",
	"github.com/kkyr/fig",
	"github.com/num30/config",
	"github.com/danielgtaylor/huma",
	"github.com/swaggest/jsonschema-go",
	"github.com/swaggest/openapi-go",
	"github.com/swaggo/swag",
}

// DefaultTagUnreadRule detects a struct field with a default tag in a module
// where nothing reads that key:
//
//	RetryAfter int `yaml:"retry_after" default:"60"`
//
// The tag looks like the field's default, but neither the YAML decoder nor
// encoding/json nor cleanenv (it reads env-default) looks at it: the field
// stays zero unless code sets it, and the written default drifts from the
// one a setDefaults function applies. A module reads the key when one of its
// packages imports a library that does (defaultTagReaders, plus the readers
// setting) or reads it itself through reflect.StructTag.
type DefaultTagUnreadRule struct {
	*rules.BaseRule
	readers map[string]bool
}

// NewDefaultTagUnreadRule creates the rule
func NewDefaultTagUnreadRule() *DefaultTagUnreadRule {
	return &DefaultTagUnreadRule{BaseRule: rules.NewBaseRule(
		"default-tag-unread",
		"patterns",
		"Detects a struct field with a default:\"...\" tag in a module where no loader reads that key (no defaults library, no reflect on the tag) — the field stays zero unless code sets it",
		core.SeverityMedium,
	).DeclareSettings(rules.NewSettingSpec("readers", "string list", "", "Additional import paths of libraries that read default struct tags.", []string{"example.com/config"}))}
}

// Configure reads readers, the import paths of further libraries that read
// the default key.
func (r *DefaultTagUnreadRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	readers, _, err := rules.NameSetSetting(settings, r.Name(), "readers")
	if err != nil {
		return err
	}
	r.readers = readers
	return nil
}

// AnalyzeFile is a no-op: the readers are known only across the module.
func (r *DefaultTagUnreadRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DefaultTagUnreadRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the default tags of the modules that do not read
// them.
func (r *DefaultTagUnreadRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	reads := map[string]bool{}
	moduleOf := map[*core.FileContext]string{}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		module := ""
		if pkg.Package.Module != nil {
			module = pkg.Package.Module.Path
		}
		for _, file := range pkg.Files {
			moduleOf[file] = module
		}
		if !reads[module] && r.readsDefaultTag(pkg) {
			reads[module] = true
		}
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, _ *types.Info) []*core.Violation {
		module := moduleOf[file]
		if reads[module] {
			return nil
		}
		return r.unreadTags(file, module)
	})
}

// readsDefaultTag reports a package that imports a reader of the default key
// or reads a struct tag itself under the key "default" or a key it does not
// spell out.
func (r *DefaultTagUnreadRule) readsDefaultTag(pkg *core.GoPackageContext) bool {
	for path := range pkg.Package.Imports {
		if r.readers[path] || slices.ContainsFunc(defaultTagReaders, func(reader string) bool {
			return path == reader || strings.HasPrefix(path, reader+"/")
		}) {
			return true
		}
	}
	info := pkg.Package.TypesInfo
	if info == nil {
		return false
	}
	found := false
	for _, file := range pkg.Package.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && !found {
				found = readsTagKey(info, call)
			}
			return !found
		})
	}
	return found
}

// readsTagKey reports reflect.StructTag's Get or Lookup with the key
// "default" or a key that is not a constant.
func readsTagKey(info *types.Info, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" || (fn.Name() != "Get" && fn.Name() != "Lookup") {
		return false
	}
	recv := fn.Signature().Recv()
	if recv == nil || types.TypeString(recv.Type(), nil) != "reflect.StructTag" {
		return false
	}
	key := info.Types[call.Args[0]].Value
	return key == nil || key.Kind() != constant.String || constant.StringVal(key) == "default"
}

// unreadTags reports the struct fields of the file with a default tag.
func (r *DefaultTagUnreadRule) unreadTags(file *core.FileContext, module string) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(file.GoAST, func(n ast.Node) bool {
		field, ok := n.(*ast.Field)
		if !ok {
			return true
		}
		def, found := helpers.FieldTag(field).Lookup("default")
		if !found {
			return true
		}
		line := file.LineFor(field.Tag)
		if file.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
			"Field %s declares default:%q, but nothing in module %s reads the default tag — the field stays zero unless code sets it",
			fieldName(field), def, module))
		v.WithCode(strings.TrimSpace(file.GetLine(line)))
		v.WithSuggestion("Set the default where the configuration loads and drop the tag, or load the struct with a library that reads it; a library that reads the key and is not known to the rule goes into its readers setting")
		violations = append(violations, v)
		return true
	})
	return violations
}

// fieldName returns the names of a field, or its type for an embedded one.
func fieldName(field *ast.Field) string {
	if len(field.Names) == 0 {
		return types.ExprString(field.Type)
	}
	names := make([]string, len(field.Names))
	for i, name := range field.Names {
		names[i] = name.Name
	}
	return strings.Join(names, ", ")
}
