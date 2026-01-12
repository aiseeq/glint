package architecture

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

const (
	defaultMaxResponsibilities = 3
)

func init() {
	rules.Register(NewSolidSRPRule())
}

// SolidSRPRule detects structs that violate Single Responsibility Principle
type SolidSRPRule struct {
	*rules.BaseRule
	maxResponsibilities int
}

// NewSolidSRPRule creates the rule
func NewSolidSRPRule() *SolidSRPRule {
	return &SolidSRPRule{
		BaseRule: rules.NewBaseRule(
			"solid-srp",
			"architecture",
			"Detects structs with too many responsibilities (Single Responsibility Principle)",
			core.SeverityHigh,
		),
		maxResponsibilities: defaultMaxResponsibilities,
	}
}

// Configure sets rule settings
func (r *SolidSRPRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.maxResponsibilities = r.GetIntSetting("max_responsibilities", defaultMaxResponsibilities)
	return nil
}

// AnalyzeFile checks for SRP violations
func (r *SolidSRPRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	// Collect all structs and their methods
	structMethods := make(map[string][]string)
	structPositions := make(map[string]int)

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.TypeSpec:
			if _, ok := node.Type.(*ast.StructType); ok {
				pos := ctx.PositionFor(node)
				structPositions[node.Name.Name] = pos.Line
			}

		case *ast.FuncDecl:
			if node.Recv != nil && len(node.Recv.List) > 0 {
				if typeName := getStructName(node.Recv.List[0].Type); typeName != "" {
					structMethods[typeName] = append(structMethods[typeName], node.Name.Name)
				}
			}
		}
		return true
	})

	// Analyze each struct's methods for responsibility areas
	for structName, methods := range structMethods {
		line, exists := structPositions[structName]
		if !exists {
			continue
		}

		areas := detectResponsibilityAreas(methods)
		if len(areas) > r.maxResponsibilities {
			v := r.CreateViolation(ctx.RelPath, line,
				structName+" has "+itoa(len(areas))+" responsibility areas (max "+itoa(r.maxResponsibilities)+")")
			v.WithCode("type " + structName + " struct { ... }")
			v.WithSuggestion("Split into smaller structs, each with a single responsibility: " + strings.Join(areas, ", "))
			v.WithContext("areas", strings.Join(areas, ", "))
			v.WithContext("method_count", len(methods))
			violations = append(violations, v)
		}
	}

	return violations
}

func getStructName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}

// detectResponsibilityAreas analyzes method names to detect different responsibility areas
func detectResponsibilityAreas(methods []string) []string {
	areaPatterns := map[string][]string{
		"database":    {"Get", "Find", "Create", "Update", "Delete", "Save", "Load", "Query", "Insert", "Select"},
		"http":        {"Handle", "Serve", "Route", "Request", "Response", "HTTP", "API", "Endpoint"},
		"validation":  {"Validate", "Check", "Verify", "Assert", "Ensure"},
		"logging":     {"Log", "Debug", "Info", "Warn", "Error", "Trace"},
		"cache":       {"Cache", "Invalidate", "Refresh", "TTL", "Expire"},
		"auth":        {"Auth", "Login", "Logout", "Permission", "Role", "Token", "Session"},
		"crypto":      {"Encrypt", "Decrypt", "Hash", "Sign", "Verify"},
		"file":        {"Read", "Write", "File", "Open", "Close", "Path"},
		"network":     {"Connect", "Disconnect", "Send", "Receive", "Listen"},
		"config":      {"Config", "Setting", "Option", "Preference"},
		"metrics":     {"Metric", "Counter", "Gauge", "Histogram", "Timer"},
		"scheduling":  {"Schedule", "Cron", "Timer", "Interval", "Periodic"},
		"transaction": {"Transaction", "Commit", "Rollback", "Begin"},
		"export":      {"Export", "Import", "Marshal", "Unmarshal", "Encode", "Decode"},
		"notification": {"Notify", "Alert", "Email", "SMS", "Push"},
	}

	detectedAreas := make(map[string]bool)

	for _, method := range methods {
		methodLower := strings.ToLower(method)
		for area, patterns := range areaPatterns {
			for _, pattern := range patterns {
				if strings.Contains(methodLower, strings.ToLower(pattern)) {
					detectedAreas[area] = true
					break
				}
			}
		}
	}

	var areas []string
	for area := range detectedAreas {
		areas = append(areas, area)
	}

	return areas
}
