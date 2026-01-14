package doccheck

import (
	"go/ast"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDocCompletenessRule())
}

// DocCompletenessRule detects exported symbols without documentation
type DocCompletenessRule struct {
	*rules.BaseRule
	skipTrivial bool // Skip self-documenting functions (getters, setters, etc.)
}

// NewDocCompletenessRule creates the rule
func NewDocCompletenessRule() *DocCompletenessRule {
	return &DocCompletenessRule{
		BaseRule: rules.NewBaseRule(
			"doc-missing",
			"documentation",
			"Detects exported types, functions, and methods without documentation comments",
			core.SeverityLow,
		),
		skipTrivial: true, // By default, skip trivial/self-documenting functions
	}
}

// Configure allows setting rule options
func (r *DocCompletenessRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	if v, ok := settings["skip_trivial"]; ok {
		if skipTrivial, ok := v.(bool); ok {
			r.skipTrivial = skipTrivial
		}
	}
	return nil
}

// AnalyzeFile checks for missing documentation
func (r *DocCompletenessRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	// Skip test files
	if ctx.IsTestFile() {
		return nil
	}

	// Skip compatibility/alias files - they just re-export types
	if r.skipTrivial && r.isCompatibilityFile(ctx.RelPath) {
		return nil
	}

	var violations []*core.Violation

	for _, decl := range ctx.GoAST.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			violations = append(violations, r.checkGenDecl(ctx, d)...)

		case *ast.FuncDecl:
			violations = append(violations, r.checkFuncDecl(ctx, d)...)
		}
	}

	return violations
}

// isCompatibilityFile checks if file is a compatibility/alias file
func (r *DocCompletenessRule) isCompatibilityFile(path string) bool {
	pathLower := strings.ToLower(path)
	patterns := []string{
		"_aliases", "_compat", "compatibility", "_deprecated",
		"/aliases/", "/compat/",
	}
	for _, pattern := range patterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}
	return false
}

// checkGenDecl checks type and const/var declarations
func (r *DocCompletenessRule) checkGenDecl(ctx *core.FileContext, decl *ast.GenDecl) []*core.Violation {
	var violations []*core.Violation

	for _, spec := range decl.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			// Skip type aliases (type X = Y) - they're self-documenting
			if r.skipTrivial && s.Assign.IsValid() {
				continue
			}

			// Skip trivial type names
			if r.skipTrivial && r.isTrivialTypeName(s.Name.Name) {
				continue
			}

			if ast.IsExported(s.Name.Name) && !r.hasDoc(decl.Doc, s.Doc) {
				pos := ctx.PositionFor(s.Name)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Exported type '"+s.Name.Name+"' is missing documentation")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Add a comment starting with the type name: // " + s.Name.Name + " ...")
				v.WithContext("symbol", s.Name.Name)
				v.WithContext("kind", "type")
				violations = append(violations, v)
			}

		case *ast.ValueSpec:
			// Only check if it's a single const/var declaration at top level
			// Skip if there's a group doc comment
			if decl.Doc != nil && len(decl.Specs) > 1 {
				continue // Group has doc, individual items don't need it
			}

			for _, name := range s.Names {
				// Skip trivial constant names
				if r.skipTrivial && r.isTrivialConstName(name.Name) {
					continue
				}

				if ast.IsExported(name.Name) && !r.hasDoc(decl.Doc, s.Doc) {
					pos := ctx.PositionFor(name)
					v := r.CreateViolation(ctx.RelPath, pos.Line,
						"Exported constant/variable '"+name.Name+"' is missing documentation")
					v.WithCode(ctx.GetLine(pos.Line))
					v.WithSuggestion("Add a comment: // " + name.Name + " ...")
					v.WithContext("symbol", name.Name)
					v.WithContext("kind", "value")
					violations = append(violations, v)
				}
			}
		}
	}

	return violations
}

// checkFuncDecl checks function declarations
func (r *DocCompletenessRule) checkFuncDecl(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation

	// Skip unexported functions
	if !ast.IsExported(fn.Name.Name) {
		return nil
	}

	// Skip main and init
	if fn.Name.Name == "main" || fn.Name.Name == "init" {
		return nil
	}

	// Skip trivial/self-documenting functions if enabled
	if r.skipTrivial && r.isTrivialFunction(fn) {
		return nil
	}

	if fn.Doc == nil || len(fn.Doc.List) == 0 {
		pos := ctx.PositionFor(fn.Name)
		kind := "function"
		if fn.Recv != nil {
			kind = "method"
		}

		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Exported "+kind+" '"+fn.Name.Name+"' is missing documentation")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Add a comment starting with the function name: // " + fn.Name.Name + " ...")
		v.WithContext("symbol", fn.Name.Name)
		v.WithContext("kind", kind)
		violations = append(violations, v)
	} else if !r.skipTrivial || !r.isTrivialFunction(fn) {
		// Check that doc starts with function name (Go convention)
		// Skip this check for trivial functions - their meaning is obvious from name
		firstLine := fn.Doc.List[0].Text
		if !strings.HasPrefix(strings.TrimPrefix(firstLine, "// "), fn.Name.Name) &&
			!strings.HasPrefix(strings.TrimPrefix(firstLine, "/* "), fn.Name.Name) {
			pos := ctx.PositionFor(fn.Name)
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Documentation for '"+fn.Name.Name+"' should start with the function name")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Start comment with: // " + fn.Name.Name + " ...")
			v.WithContext("symbol", fn.Name.Name)
			v.WithContext("kind", "doc-format")
			violations = append(violations, v)
		}
	}

	return violations
}

// isTrivialFunction checks if function is self-documenting and doesn't need explicit docs
func (r *DocCompletenessRule) isTrivialFunction(fn *ast.FuncDecl) bool {
	name := fn.Name.Name

	// Standard interface methods - contract is well-known
	standardMethods := map[string]bool{
		"String": true, "Error": true, "Unwrap": true,
		"MarshalJSON": true, "UnmarshalJSON": true,
		"MarshalText": true, "UnmarshalText": true,
		"MarshalBinary": true, "UnmarshalBinary": true,
		"MarshalYAML": true, "UnmarshalYAML": true,
		"Scan": true, "Value": true, // sql.Scanner, driver.Valuer
		"ServeHTTP": true,                               // http.Handler
		"Read":      true, "Write": true, "Close": true, // io interfaces
		"Len": true, "Less": true, "Swap": true, // sort.Interface
		"Reset": true, "Clone": true,
		// Logging methods (Error already in interface methods above)
		"Debug": true, "Info": true, "Warn": true,
		"Fatal": true, "Trace": true, "Print": true, "Println": true,
		// Repository/CRUD methods
		"Store": true, "Delete": true, "Create": true, "Update": true,
		"Get": true, "List": true, "Find": true, "Count": true,
		"Save": true, "Remove": true, "Where": true,
		// HTTP methods
		"Post": true, "Put": true, "Patch": true,
		// Router methods
		"Mount": true, "Use": true, "Group": true, "Route": true,
		// Auth methods
		"Login": true, "Logout": true, "Authenticate": true, "Authorize": true,
	}
	if standardMethods[name] {
		return true
	}

	// Trivial prefixes - meaning is obvious from name
	trivialPrefixes := []string{
		"Get", "Set", // Getters/setters
		"Is", "Has", "Can", "Should", "Will", // Boolean checks
		"With", "Without", // Builder pattern
		"New", "Create", "Make", "Build", // Constructors
		"Must",                                    // Panic versions
		"Parse", "Format", "Convert", "Transform", // Conversions
		"Enable", "Disable", "Toggle", // Toggle operations
		"Add", "Remove", "Delete", "Insert", // Collection/CRUD operations
		"Update", "Save", "Upsert", // CRUD operations
		"Find", "Search", "Query", "List", "Fetch", // Query operations
		"Register", "Unregister", // Registration
		"Assign", "Revoke", "Grant", // Permission operations
		"Start", "Stop", "Pause", "Resume", // Lifecycle
		"Open", "Close", // Resource management
		"Lock", "Unlock", // Mutex operations
		"Load", "Store", "Clear", "Reset", // State operations
		"Inc", "Dec", "Count", // Counter operations
		"Validate", "Check", "Verify", // Validation
		"Send", "Receive", "Emit", "Broadcast", // Communication
		"Subscribe", "Unsubscribe", "Publish", // Pub/sub
		"Encode", "Decode", "Marshal", "Unmarshal", // Serialization
		"Hash", "Sign", "Encrypt", "Decrypt", // Crypto
		"Log", "Debug", "Info", "Warn", "Error", // Logging
		"Handle", "Process", // Processing
		"Init", "Setup", "Configure", "Apply", // Initialization
		"Run", "Execute", "Invoke", "Call", // Execution
		"Wait", "Await", "Block", // Synchronization
		"Copy", "Clone", "Dup", // Copying
		"Merge", "Split", "Join", // Data manipulation
		"Filter", "Map", "Reduce", "Sort", // Functional
		"Normalize", "Sanitize", "Clean", "Trim", // Data cleaning
		"Render", "Display", "Show", "Print", // Output
		"Reject", "Approve", "Complete", "Cancel", // Action outcomes
		"Bulk",          // Batch operations
		"Benchmark",     // Test functions
		"Sync", "Async", // Sync operations
		"Cleanup", "Generate", "Refresh", // Common operations
		"Zero", "One", "Default", // Value constructors
		"Safe", // Safe type constructors
	}
	for _, prefix := range trivialPrefixes {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			// Ensure next char is uppercase (proper PascalCase)
			nextChar := rune(name[len(prefix)])
			if unicode.IsUpper(nextChar) {
				return true
			}
		}
	}

	// Trivial suffixes
	trivialSuffixes := []string{
		"Handler", "Middleware", // HTTP - context in request
		"Callback", "Hook", // Event handlers
	}
	for _, suffix := range trivialSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}

	// Simple accessor methods (single word, returns receiver field)
	// e.g., func (u *User) Name() string { return u.name }
	if fn.Recv != nil && !strings.Contains(name, "_") {
		// Method with simple name (no underscores) on a receiver
		// These are typically field accessors
		if fn.Type.Params != nil && len(fn.Type.Params.List) == 0 {
			// No parameters - likely a getter
			return true
		}
		if fn.Type.Params != nil && len(fn.Type.Params.List) == 1 {
			// Single parameter - likely a setter
			return true
		}
	}

	return false
}

// hasDoc checks if there's documentation in either group or individual doc
func (r *DocCompletenessRule) hasDoc(groupDoc, itemDoc *ast.CommentGroup) bool {
	if groupDoc != nil && len(groupDoc.List) > 0 {
		return true
	}
	if itemDoc != nil && len(itemDoc.List) > 0 {
		return true
	}
	return false
}

// isTrivialConstName checks if constant/variable name is self-documenting
func (r *DocCompletenessRule) isTrivialConstName(name string) bool {
	// Trivial suffixes - meaning is clear from name
	trivialSuffixes := []string{
		"Columns", "Fields", "Keys", // SQL/data column definitions
		"Query", "SQL", "Statement", // SQL queries
		"Timeout", "Interval", "Duration", "Delay", // Time values
		"Limit", "Max", "Min", "Size", "Length", "Count", // Limits
		"Port", "Host", "URL", "URI", "Path", "Addr", "Address", // Network
		"Name", "Type", "Kind", "Format", "Pattern", "Regex", // Identifiers
		"Prefix", "Suffix", "Separator", "Delimiter", // String patterns
		"Header", "Key", "Value", "Token", "Secret", // HTTP/auth
		"Version", "Code", "ID", // Identifiers
		"Error", "Message", "Template", // Strings
		"Endpoint", "Route", "Handler", // API endpoints
		"Param", "QueryParam", "PathParam", // Request parameters
		"Group", "Services", "Overrides", // Config groupings
	}
	for _, suffix := range trivialSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}

	// Trivial prefixes
	trivialPrefixes := []string{
		"Err",        // Error variables (ErrNotFound, etc.)
		"Max", "Min", // Limit constants
		"Test",                               // Test patterns/data
		"Status",                             // Status codes
		"Role",                               // Role constants (RoleAdmin, RoleUser)
		"Severity",                           // Severity levels (SeverityHigh, SeverityLow)
		"Risk",                               // Risk levels (RiskHigh, RiskMedium)
		"Task",                               // Task identifiers (TaskCompliance)
		"Currency",                           // Currency codes (CurrencyBTC, CurrencyETH)
		"Network",                            // Network identifiers (NetworkEthereum)
		"Safe",                               // Safe types (SafeDecimalZero)
		"Default",                            // Default values
		"Transaction",                        // Transaction types/approaches
		"Storage", "User", "Admin", "System", // Domain prefixes
		"Wallet",                              // Wallet constants
		"Investment", "Deposit", "Withdrawal", // Financial entities
		"Sync", "Async", "Batch", // Operation modes
		"Resource",                            // Resource identifiers
		"Event",                               // Event types
		"Reject", "Approve", "Accept", "Deny", // Action outcomes
		"Generate", "Refresh", "Revoke", // Token operations
		"Financial", "Compliance", "Violation", // Business domain
		"Post", "Mount", "Logout", // HTTP/router methods
		"Action",        // Action constants
		"AML", "Amount", // Risk/compliance prefixes
		"Address",            // Address constants
		"Complete", "Cancel", // Action outcomes
		"Blockchain",        // Blockchain constants
		"Benchmark", "Bulk", // Test/batch prefixes
		"Composite", "Cleanup", "Auth", // Misc prefixes
		"DB", "Database", // Database prefixes
	}
	for _, prefix := range trivialPrefixes {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			nextChar := rune(name[len(prefix)])
			if unicode.IsUpper(nextChar) {
				return true
			}
		}
	}

	// Enum-style constants following Go convention: TypeNameValue
	// e.g., DepositStatusPending, WithdrawalCreatorUser, FeeTypeCommercial
	if r.isEnumConstant(name) {
		return true
	}

	return false
}

// isEnumConstant checks if constant follows enum pattern: TypeCategoryValue
// where Category is Status, Type, Creator, Kind, Mode, State, Level, etc.
func (r *DocCompletenessRule) isEnumConstant(name string) bool {
	// Common enum category markers that appear in the middle of compound names
	enumCategories := []string{
		"Status", "Type", "Creator", "Kind", "Mode", "State", "Level",
		"Category", "Role", "Permission", "Action", "Event", "Stage",
		"Phase", "Priority", "Severity", "Source", "Target", "Direction",
		"Method", "Provider", "Strategy", "Policy", "Result", "Reason",
	}

	for _, category := range enumCategories {
		idx := strings.Index(name, category)
		if idx > 0 && idx+len(category) < len(name) {
			// Found category in the middle
			prefix := name[:idx]
			suffix := name[idx+len(category):]

			// Check that prefix starts with uppercase (type name)
			// and suffix starts with uppercase (value name)
			if len(prefix) > 0 && len(suffix) > 0 {
				firstPrefixChar := rune(prefix[0])
				firstSuffixChar := rune(suffix[0])
				if unicode.IsUpper(firstPrefixChar) && unicode.IsUpper(firstSuffixChar) {
					return true
				}
			}
		}
	}

	return false
}

// isTrivialTypeName checks if type name is self-documenting
func (r *DocCompletenessRule) isTrivialTypeName(name string) bool {
	// Trivial suffixes - name describes what it is
	trivialSuffixes := []string{
		"Interface",                                      // XxxInterface - it's an interface for Xxx
		"Config", "Configuration", "Settings", "Options", // Configuration types
		"Info", "Data", "Details", "Summary", // Data containers
		"Request", "Response", // HTTP request/response types
		"Input", "Output", "Params", "Args", // Function parameters
		"Result", "Results", "Outcome", // Return types
		"Error", "Err", // Error types
		"Handler", "Middleware", "Controller", // HTTP handlers
		"Repository", "Repo", "Store", "Storage", // Data access
		"Service", "Manager", "Provider", "Factory", // Business logic
		"Client", "Conn", "Connection", // Client types
		"Model", "Entity", "Record", "Row", // Data models
		"DTO", "VO", // Data transfer objects
		"Spec", "Schema", "Definition", // Schema types
		"Filter", "Criteria", "Query", // Query types
		"Event", "Message", "Payload", // Messaging types
		"State", "Status", "Context", // State types
		"Mock", "Stub", "Fake", // Test doubles
		"Impl", "Implementation", // Implementation types
		"Type",                                    // Type definitions
		"Breakdown", "Calculation", "Aggregation", // Financial breakdowns
		"Transaction", "Transfer", "Payment", // Transaction types
		"Writer", "Reader", "Closer", // IO types
		"Group",                       // Service groups
		"Bus",                         // Event bus types
		"Router",                      // Router types
		"Constraint",                  // Constraint types
		"Infrastructure",              // Infrastructure types
		"Metadata", "Health", "Check", // Monitoring types
		"Services", "Business", // Service collection types
		"Timestamp", "Builder", "Audit", // Utility types
		"Overrides", "Compliance", // Config/compliance types
	}
	for _, suffix := range trivialSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}

	// Trivial prefixes
	trivialPrefixes := []string{
		"Base",     // BaseXxx - base class
		"Abstract", // AbstractXxx - abstract class
		"Default",  // DefaultXxx - default implementation
		"Simple",   // SimpleXxx - simple implementation
		"Basic",    // BasicXxx - basic implementation
		"Internal", // InternalXxx - internal type
		"Raw",      // RawXxx - raw/unprocessed type
		"Test",     // TestXxx - test types
		"Task",     // TaskXxx - task types
	}
	for _, prefix := range trivialPrefixes {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			nextChar := rune(name[len(prefix)])
			if unicode.IsUpper(nextChar) {
				return true
			}
		}
	}

	return false
}
