package architecture

import (
	"go/ast"

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

// AnalyzeFile checks for ISP violations
func (r *SolidISPRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() {
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

		methodCount := 0
		if interfaceType.Methods != nil {
			for _, method := range interfaceType.Methods.List {
				// Each field can have multiple names (though rare for methods)
				if len(method.Names) == 0 {
					// Embedded interface
					methodCount++
				} else {
					methodCount += len(method.Names)
				}
			}
		}

		if methodCount > r.maxMethods {
			pos := ctx.PositionFor(typeSpec)
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				typeSpec.Name.Name+" interface has "+itoa(methodCount)+" methods (max "+itoa(r.maxMethods)+")")
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
