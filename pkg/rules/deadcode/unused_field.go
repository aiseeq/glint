package deadcode

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnusedFieldRule())
}

// UnusedFieldRule detects unexported struct fields that the package never reads:
//
//	type Cache struct {
//	    entries map[string]string
//	    hits    int      // counted on every Get, read by nobody
//	}
//
// A field only ever written is a computation whose result is discarded: the
// value costs memory per instance and, worse, tells the next reader that
// something keeps track of hits when nothing does.
//
// Unexported fields of the analyzed packages are considered, and on top of them
// the exported fields of a settings type — one whose name ends in Opts, Options,
// Config or Settings — and of a filter (Filter, Filters, Criteria). An ordinary
// exported field belongs to the package's API and its reader may live outside
// the analyzed tree; a setting or a filter is different, because one nobody
// reads does nothing no matter who sets it - a caller asking for transactions
// created after a date gets them all - and setting it in a composite literal
// is what hides it from the compiler and from deadcode tools.
// Every exported field is judged too where no reader can live outside the
// tree: in a package under internal/, which nothing outside the module may
// import, and anywhere in a module configured as an application
// (application: true) - a program with no importers. An exported field of a
// struct an encoder reads, or whose value reaches an empty interface (a
// template, fmt or an encoder behind a wrapper reads it by reflection), stays
// alive there as well.
// Tagged fields belong to unused-config-field, which knows about values arriving
// from outside. Embedded and blank fields carry no name to use.
type UnusedFieldRule struct {
	*rules.BaseRule
	// application judges every exported field (setting application).
	application bool
}

// Configure reads application: the module is a program nothing imports, so its
// exported fields have no readers outside the analyzed tree.
func (r *UnusedFieldRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.application = false
	raw, ok := settings["application"]
	if !ok {
		return nil
	}
	app, ok := raw.(bool)
	if !ok {
		return fmt.Errorf("configure unused-field: application must be a boolean, got %T", raw)
	}
	r.application = app
	return nil
}

// NewUnusedFieldRule creates the rule
func NewUnusedFieldRule() *UnusedFieldRule {
	return &UnusedFieldRule{
		BaseRule: rules.NewBaseRule(
			"unused-field",
			"deadcode",
			"Detects struct fields that are never read — unexported fields, and every field of a settings type (…Opts, …Options, …Config, …Settings) or a filter (…Filter, …Filters, …Criteria): dead state kept up to date for nobody",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op: the readers of a field may live in any file.
func (r *UnusedFieldRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *UnusedFieldRule) RequiresSSA() bool { return false }

// declaredField is a field of an analyzed struct type this rule judges.
type declaredField struct {
	obj       *types.Var
	named     *types.Named
	fileCtx   *core.FileContext
	line      int
	typeName  string
	fieldName string
	setting   bool
	filter    bool // an exported field of a filter: reported only when set
	exported  bool // an exported field judged because no reader lives outside the tree
}

// AnalyzeGoProject reports the fields of the analyzed files that no compiled
// file reads. Every loaded package counts as a reader, whether or not its own
// files are analyzed.
func (r *UnusedFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unused field: nil Go project context")
	}
	access, err := projectFieldAccess(ctx)
	if err != nil {
		return nil, fmt.Errorf("unused field: %w", err)
	}

	// Test files are outside the typed load; a field read only by its
	// white-box test must still count as read.
	mentions, err := projectMentions(ctx)
	if err != nil {
		return nil, fmt.Errorf("unused field: %w", err)
	}

	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, field := range collectCheckedFields(fileCtx, info, r.application) {
			pos := field.obj.Pos()
			if access.read[pos] || access.hashed[pos] {
				continue
			}
			// An encoder reads every exported field on the program's behalf,
			// so a setting of a type that is marshalled is not dead.
			if (field.setting || field.exported) && field.named != nil && access.encoded[field.named] {
				continue
			}
			// A value boxed into any may be read by reflection behind it.
			if field.exported && field.named != nil && access.boxed[field.named] {
				continue
			}
			if mentions.mentioned(field.fileCtx, field.fieldName) || (field.exported && mentions.mentionedAnywhere(field.fieldName)) {
				continue
			}
			// A filter field nobody sets is unused surface; one callers set
			// and nothing reads is a filter that filters nothing.
			if field.filter && !access.written[pos] {
				continue
			}
			violations = append(violations, r.report(field, access.written[pos]))
		}
		return violations
	})
}

func (r *UnusedFieldRule) report(field declaredField, written bool) *core.Violation {
	state := "is never used"
	if written {
		state = "is kept up to date but never read"
	}
	message := fmt.Sprintf("Field %s.%s %s — the work maintaining it produces nothing",
		field.typeName, field.fieldName, state)
	if field.filter {
		message = fmt.Sprintf("Filter %s.%s is set but never read — a caller narrowing by it gets every record",
			field.typeName, field.fieldName)
	} else if field.setting {
		settingState := "is never set nor read"
		if written {
			settingState = "is set but never read"
		}
		message = fmt.Sprintf("Setting %s.%s %s — the option does nothing, and the behaviour behind it is unreachable",
			field.typeName, field.fieldName, settingState)
	}
	v := r.CreateViolation(field.fileCtx.RelPath, field.line, message)
	v.WithCode(strings.TrimSpace(field.fileCtx.GetLine(field.line)))
	v.WithSuggestion(fmt.Sprintf("Use %s where its value is meant to matter, or delete the field and the code that fills it",
		field.fieldName))
	v.WithContext("pattern", "unused_field")
	v.WithContext("field", field.typeName+"."+field.fieldName)
	return v
}

// settingTypeSuffixes name the structs that carry behaviour switches.
var settingTypeSuffixes = []string{"Opts", "Options", "Config", "Settings"}

// filterTypeSuffixes name the structs that narrow a query. Their tagged
// fields are judged too: a filter is filled by its callers, not decoded from
// a configuration.
var filterTypeSuffixes = []string{"Filter", "Filters", "Criteria"}

// isSettingType reports whether the type name says the struct holds settings
// or a filter.
func isSettingType(name string) bool {
	return hasAnySuffix(name, settingTypeSuffixes) || isFilterType(name)
}

func isFilterType(name string) bool { return hasAnySuffix(name, filterTypeSuffixes) }

func hasAnySuffix(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// collectCheckedFields returns the named fields this rule judges: the untagged
// unexported ones of any struct, every untagged field of a settings struct,
// every field of a filter, and every untagged exported field where no reader
// lives outside the tree (an application, an internal package).
func collectCheckedFields(fileCtx *core.FileContext, info *types.Info, application bool) []declaredField {
	var fields []declaredField

	ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok || structType.Fields == nil {
			return true
		}
		if _, ok := declaredStructType(spec, info); !ok {
			return true
		}
		named, _ := declaredNamedType(spec, info)

		setting := isSettingType(spec.Name.Name)
		filter := isFilterType(spec.Name.Name)
		closed := application || (named != nil && internalPackage(named.Obj().Pkg()))
		for _, field := range structType.Fields.List {
			if (field.Tag != nil && !filter) || len(field.Names) == 0 {
				continue // tagged fields and embedded ones are other rules' business
			}
			for _, name := range field.Names {
				if name.Name == "_" || (name.IsExported() && !setting && !closed) {
					continue
				}
				obj, ok := info.Defs[name].(*types.Var)
				if !ok {
					continue
				}
				fields = append(fields, declaredField{
					obj:       obj,
					named:     named,
					fileCtx:   fileCtx,
					line:      fileCtx.LineFor(name),
					typeName:  spec.Name.Name,
					fieldName: name.Name,
					setting:   setting && name.IsExported(),
					filter:    filter && name.IsExported(),
					exported:  closed && name.IsExported() && !setting,
				})
			}
		}
		return true
	})

	return fields
}

// internalPackage reports a package nothing outside its module may import.
func internalPackage(pkg *types.Package) bool {
	if pkg == nil {
		return false
	}
	path := pkg.Path()
	return strings.HasPrefix(path, "internal/") || strings.Contains(path, "/internal/") || strings.HasSuffix(path, "/internal")
}

// declaredStructType returns the checked struct behind a type declaration.
func declaredStructType(spec *ast.TypeSpec, info *types.Info) (*types.Struct, bool) {
	obj, ok := info.Defs[spec.Name].(*types.TypeName)
	if !ok {
		return nil, false
	}
	structType, ok := obj.Type().Underlying().(*types.Struct)
	return structType, ok
}
