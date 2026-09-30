package architecture

import (
	"go/ast"
	"go/types"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

const (
	defaultMaxInterfaceMethods = 25
)

func init() {
	rules.Register(NewSolidISPRule())
}

// SolidISPRule detects interfaces that violate Interface Segregation Principle
type SolidISPRule struct {
	*rules.BaseRule
	maxMethods int
}

// NewSolidISPRule creates the rule
func NewSolidISPRule() *SolidISPRule {
	return &SolidISPRule{
		BaseRule: rules.NewBaseRule(
			"solid-isp",
			"architecture",
			"Detects interfaces with too many methods (Interface Segregation Principle)",
			core.SeverityHigh,
		),
		maxMethods: defaultMaxInterfaceMethods,
	}
}

// Configure sets rule settings
func (r *SolidISPRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.maxMethods = r.GetIntSetting("max_methods", defaultMaxInterfaceMethods)
	return nil
}

// AnalyzeFile checks one file without type information: the fallback for
// files no type-checked package covers.
func (r *SolidISPRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SolidISPRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every Go file; with types an embedded interface
// counts with its whole method set.
func (r *SolidISPRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// interfaceMethodCount returns the size of the method set an implementation
// has to provide. With type information that is the full set, embedded
// interfaces included. Without it only the methods the declaration spells out
// are known — a lower bound, so an interface is reported only when that bound
// alone is over the limit.
func interfaceMethodCount(typeSpec *ast.TypeSpec, iface *ast.InterfaceType, info *types.Info) int {
	if info != nil {
		if obj, ok := info.Defs[typeSpec.Name].(*types.TypeName); ok {
			if checked, ok := obj.Type().Underlying().(*types.Interface); ok {
				return checked.NumMethods()
			}
		}
	}
	count := 0
	if iface.Methods != nil {
		for _, method := range iface.Methods.List {
			count += len(method.Names) // embedded interfaces have no names
		}
	}
	return count
}

// analyze checks for ISP violations. info is nil for a file without type
// information.
func (r *SolidISPRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}

		interfaceType, ok := typeSpec.Type.(*ast.InterfaceType)
		if !ok {
			return true
		}

		// Skip config-related interfaces - they are legitimately large
		// as they provide typed access to all configuration values
		interfaceName := typeSpec.Name.Name
		if r.isConfigInterface(ctx.RelPath, interfaceName) {
			return true
		}

		methodCount := interfaceMethodCount(typeSpec, interfaceType, info)

		if methodCount > r.maxMethods {
			pos := ctx.PositionFor(typeSpec)
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				typeSpec.Name.Name+" interface has "+strconv.Itoa(methodCount)+" methods (max "+strconv.Itoa(r.maxMethods)+")")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Split into smaller, focused interfaces following Interface Segregation Principle")
			v.WithContext("method_count", methodCount)
			v.WithContext("max_methods", r.maxMethods)
			violations = append(violations, v)
		}

		return true
	})

	return violations
}

// isConfigInterface checks if an interface is a configuration interface
// Config interfaces are legitimately large - they provide typed getters for all config values
func (r *SolidISPRule) isConfigInterface(filePath, interfaceName string) bool {
	// Check file path for config-related patterns
	pathLower := strings.ToLower(filePath)
	if strings.Contains(pathLower, "config") {
		return true
	}

	// Check interface name patterns
	nameLower := strings.ToLower(interfaceName)
	configPatterns := []string{"config", "configuration", "settings", "options"}
	for _, pattern := range configPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	return false
}
