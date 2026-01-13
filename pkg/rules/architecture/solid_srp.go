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

// Default infrastructure areas - these are cross-cutting concerns typically injected via DI
// and don't count as separate "responsibilities" for SRP purposes
var defaultInfrastructureAreas = []string{
	"logging",      // Logger is injected, not a responsibility
	"config",       // Config is injected, not a responsibility
	"validation",   // Validator is injected, not a responsibility
	"cache",        // Cache is injected, not a responsibility
	"metrics",      // Metrics collector is injected, not a responsibility
	"auth",         // Auth is cross-cutting concern (middleware, guards)
	"crypto",       // Crypto operations are infrastructure (hashing, signing)
	"notification", // Notifications are injected services
}

func init() {
	rules.Register(NewSolidSRPRule())
}

// SolidSRPRule detects structs that violate Single Responsibility Principle
type SolidSRPRule struct {
	*rules.BaseRule
	maxResponsibilities   int
	infrastructureAreas   map[string]bool
	excludeInfrastructure bool
}

// NewSolidSRPRule creates the rule
func NewSolidSRPRule() *SolidSRPRule {
	// Build default infrastructure areas map
	infraAreas := make(map[string]bool)
	for _, area := range defaultInfrastructureAreas {
		infraAreas[area] = true
	}

	return &SolidSRPRule{
		BaseRule: rules.NewBaseRule(
			"solid-srp",
			"architecture",
			"Detects structs with too many responsibilities (Single Responsibility Principle)",
			core.SeverityHigh,
		),
		maxResponsibilities:   defaultMaxResponsibilities,
		infrastructureAreas:   infraAreas,
		excludeInfrastructure: true, // By default, exclude infrastructure areas from counting
	}
}

// Configure sets rule settings
func (r *SolidSRPRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.maxResponsibilities = r.GetIntSetting("max_responsibilities", defaultMaxResponsibilities)
	r.excludeInfrastructure = r.GetBoolSetting("exclude_infrastructure", true)

	// Allow custom infrastructure areas via settings
	if customAreas, ok := settings["infrastructure_areas"].([]any); ok {
		r.infrastructureAreas = make(map[string]bool)
		for _, area := range customAreas {
			if areaStr, ok := area.(string); ok {
				r.infrastructureAreas[areaStr] = true
			}
		}
	}

	return nil
}

// isConfigStruct checks if struct name suggests it's a configuration/settings container
func isConfigStruct(name string) bool {
	nameLower := strings.ToLower(name)
	configSuffixes := []string{"config", "settings", "options", "params", "module", "messages"}
	for _, suffix := range configSuffixes {
		if strings.HasSuffix(nameLower, suffix) {
			return true
		}
	}
	return false
}

// getStructTypeExclusions returns areas that should be excluded based on struct type
// e.g., Routers naturally handle HTTP, Repositories naturally do database operations
func getStructTypeExclusions(structName string) []string {
	nameLower := strings.ToLower(structName)

	var exclusions []string

	// Routers and Handlers naturally deal with HTTP, data access, and files
	// They orchestrate calls to services/repositories and return responses
	if strings.HasSuffix(nameLower, "router") || strings.HasSuffix(nameLower, "handler") ||
		strings.HasSuffix(nameLower, "controller") || strings.HasSuffix(nameLower, "endpoint") {
		exclusions = append(exclusions, "http", "database", "file", "export", "network")
	}

	// Repositories naturally do database operations
	if strings.HasSuffix(nameLower, "repository") || strings.HasSuffix(nameLower, "repo") ||
		strings.HasSuffix(nameLower, "store") || strings.HasSuffix(nameLower, "dao") {
		exclusions = append(exclusions, "database")
	}

	// Factories, Containers, Providers are meant to create/manage multiple things
	if strings.HasSuffix(nameLower, "factory") || strings.HasSuffix(nameLower, "container") ||
		strings.HasSuffix(nameLower, "provider") || strings.HasSuffix(nameLower, "builder") ||
		strings.HasSuffix(nameLower, "manager") || strings.HasSuffix(nameLower, "impl") {
		exclusions = append(exclusions, "database", "http", "file", "network")
	}

	// Middleware naturally deals with HTTP and auth
	if strings.HasSuffix(nameLower, "middleware") {
		exclusions = append(exclusions, "http", "auth")
	}

	// Collectors/Monitors naturally deal with metrics
	if strings.HasSuffix(nameLower, "collector") || strings.HasSuffix(nameLower, "monitor") {
		exclusions = append(exclusions, "metrics", "network", "database")
	}

	// Helpers/Utils are meant to be multi-purpose
	if strings.HasSuffix(nameLower, "helper") || strings.HasSuffix(nameLower, "helpers") ||
		strings.HasSuffix(nameLower, "util") || strings.HasSuffix(nameLower, "utils") {
		exclusions = append(exclusions, "database", "http", "file", "auth")
	}

	return exclusions
}

// filterDomainAreas removes areas that are part of the struct's domain name
// e.g., TransactionRepository shouldn't count "transaction" as separate area
func filterDomainAreas(structName string, areas []string) []string {
	structNameLower := strings.ToLower(structName)
	var filtered []string
	for _, area := range areas {
		// If the struct name contains this area, it's the struct's primary domain, not a separate responsibility
		if !strings.Contains(structNameLower, area) {
			filtered = append(filtered, area)
		}
	}
	return filtered
}

// isGetterOnlyStruct checks if struct only has getter methods (typical for config objects)
func isGetterOnlyStruct(methods []string) bool {
	if len(methods) == 0 {
		return false
	}
	getterCount := 0
	for _, method := range methods {
		methodLower := strings.ToLower(method)
		if strings.HasPrefix(methodLower, "get") || strings.HasPrefix(methodLower, "is") ||
			strings.HasPrefix(methodLower, "has") || strings.HasPrefix(methodLower, "can") {
			getterCount++
		}
	}
	// If >80% of methods are getters, it's likely a config/data object
	return float64(getterCount)/float64(len(methods)) > 0.8
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

		// Skip config/settings structs - they're data containers, not services
		if isConfigStruct(structName) || isGetterOnlyStruct(methods) {
			continue
		}

		allAreas := detectResponsibilityAreas(methods)

		// Remove areas that are part of the struct's domain name
		// e.g., TransactionRepository shouldn't count "transaction" as separate area
		allAreas = filterDomainAreas(structName, allAreas)

		// Get type-based exclusions (e.g., Router excludes "http")
		typeExclusions := getStructTypeExclusions(structName)
		typeExclusionMap := make(map[string]bool)
		for _, ex := range typeExclusions {
			typeExclusionMap[ex] = true
		}

		// Filter out infrastructure areas and type-based exclusions
		var businessAreas []string
		var infraAreas []string
		var typeAreas []string
		for _, area := range allAreas {
			if r.excludeInfrastructure && r.infrastructureAreas[area] {
				infraAreas = append(infraAreas, area)
			} else if typeExclusionMap[area] {
				typeAreas = append(typeAreas, area)
			} else {
				businessAreas = append(businessAreas, area)
			}
		}

		if len(businessAreas) > r.maxResponsibilities {
			msg := structName + " has " + itoa(len(businessAreas)) + " business responsibility areas (max " + itoa(r.maxResponsibilities) + ")"
			if len(infraAreas) > 0 || len(typeAreas) > 0 {
				var excluded []string
				if len(infraAreas) > 0 {
					excluded = append(excluded, "infra: "+strings.Join(infraAreas, ", "))
				}
				if len(typeAreas) > 0 {
					excluded = append(excluded, "type: "+strings.Join(typeAreas, ", "))
				}
				msg += " [excluded " + strings.Join(excluded, "; ") + "]"
			}
			v := r.CreateViolation(ctx.RelPath, line, msg)
			v.WithCode("type " + structName + " struct { ... }")
			v.WithSuggestion("Split into smaller structs, each with a single responsibility: " + strings.Join(businessAreas, ", "))
			v.WithContext("business_areas", strings.Join(businessAreas, ", "))
			v.WithContext("infrastructure_areas", strings.Join(infraAreas, ", "))
			v.WithContext("type_areas", strings.Join(typeAreas, ", "))
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
		"database":     {"Get", "Find", "Create", "Update", "Delete", "Save", "Load", "Query", "Insert", "Select"},
		"http":         {"Handle", "Serve", "Route", "Request", "Response", "HTTP", "API", "Endpoint"},
		"validation":   {"Validate", "Check", "Verify", "Assert", "Ensure"},
		"logging":      {"Log", "Debug", "Info", "Warn", "Error", "Trace"},
		"cache":        {"Cache", "Invalidate", "Refresh", "TTL", "Expire"},
		"auth":         {"Auth", "Login", "Logout", "Permission", "Role", "Token", "Session"},
		"crypto":       {"Encrypt", "Decrypt", "Hash", "Sign", "Verify"},
		"file":         {"Read", "Write", "File", "Open", "Close", "Path"},
		"network":      {"Connect", "Disconnect", "Send", "Receive", "Listen"},
		"config":       {"Config", "Setting", "Option", "Preference"},
		"metrics":      {"Metric", "Counter", "Gauge", "Histogram", "Timer"},
		"scheduling":   {"Schedule", "Cron", "Timer", "Interval", "Periodic"},
		"transaction":  {"Transaction", "Commit", "Rollback", "Begin"},
		"export":       {"Export", "Import", "Marshal", "Unmarshal", "Encode", "Decode"},
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
