package patterns

import (
	"go/ast"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewContextFirstRule())
}

// ContextFirstRule detects public functions without context.Context as first parameter
type ContextFirstRule struct {
	*rules.BaseRule
}

// NewContextFirstRule creates the rule
func NewContextFirstRule() *ContextFirstRule {
	return &ContextFirstRule{
		BaseRule: rules.NewBaseRule(
			"context-first",
			"patterns",
			"Detects public functions without context.Context as first parameter",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks for context.Context as first parameter in public functions
func (r *ContextFirstRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	// Skip main package and test helpers
	if r.shouldSkipFile(ctx.RelPath) {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			return true
		}

		// Only check public functions (capitalized)
		if !isPublic(fn.Name.Name) {
			return true
		}

		// Skip special functions
		if r.isSpecialFunction(fn) {
			return true
		}

		// Skip functions that return only error (like Close(), Flush())
		if r.isSimpleOperation(fn) {
			return true
		}

		// Skip constructors and factory functions
		if r.isConstructor(fn.Name.Name) {
			return true
		}

		// Check if first parameter is context.Context
		if !r.hasContextFirstParam(fn) {
			pos := ctx.PositionFor(fn)
			funcName := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				if typeName := getReceiverTypeName(fn.Recv.List[0].Type); typeName != "" {
					funcName = typeName + "." + funcName
				}
			}

			v := r.CreateViolation(ctx.RelPath, pos.Line,
				funcName+" should have context.Context as first parameter")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Add ctx context.Context as the first parameter for proper cancellation and deadline propagation")
			violations = append(violations, v)
		}

		return true
	})

	return violations
}

func (r *ContextFirstRule) shouldSkipFile(path string) bool {
	skipPatterns := []string{
		"_test.go",
		"/testdata/",
		"/testing/",
		"/test_",
		"_mock",
		"/mocks/",
		"/generated/",
		"main.go",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range skipPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

func (r *ContextFirstRule) isSpecialFunction(fn *ast.FuncDecl) bool {
	name := fn.Name.Name
	specialNames := []string{
		"init", "main",
		"String", "Error", "MarshalJSON", "UnmarshalJSON",
		"MarshalText", "UnmarshalText", "MarshalBinary", "UnmarshalBinary",
		"Scan", "Value", // sql.Scanner, driver.Valuer
		"ServeHTTP",     // http.Handler (context is in request)
		"Unwrap",        // error interface method for unwrapping errors
		"Commit",        // database transaction (context often stored in struct)
		"Rollback",      // database transaction
		"Ping",          // simple healthcheck operations
		"Stats",         // statistics retrieval (no side effects)
		"Write", "Read", // io.Writer/Reader interfaces
		"Info", "Warn", "Debug", "Fatal", "Trace", // logging methods
		"Cleanup", "Shutdown", "Dispose", // lifecycle
		"HealthCheck", "ReadyCheck", "LiveCheck", // health checks
		"Middleware", "Handler", "HandlerFunc", // HTTP middleware (context in request)
		"Do", "Get", "Post", "Put", "Patch", "Delete", "Head", "Options", // HTTP methods
		"Validate", "Validates", // validation (no I/O)
		"Where", "Select", "OrderBy", "GroupBy", "Limit", "Offset", "Set", // SQL builder
		"LeftJoin", "InnerJoin", "RightJoin", "OuterJoin", "Join", "From", // SQL joins
		"WhereIf", "Having", "Union", "Distinct", // SQL clauses
		"And", "Or", "Not", // SQL conditions
		"Register", "Unregister", "Subscribe", "Unsubscribe", // event patterns
		"Use", "With", "Version", // utility methods
		"Has", "Float", "Sub", "Mul", "Div", "Add", "Neg", "Abs", // math/value type methods
		"LessThan", "GreaterThan", "Equal", "Cmp", "Compare", // comparison methods
		"Revoke", "Retrieve", "Resolve", "Rollback", // operations
		"Keys", "Values", "Entries", "Items", // collection accessors
		"Authenticate", "Authorize", // auth methods (context often in struct)
		"HTTPStatusCode", "StatusCode", // status helpers
		"Coalesce", "Min", "Max", // utility functions
		"Ptr", "Ref", // pointer helpers
		"Contains", "Float64", "Float32", "Int64", "Int32", // exact type helpers
		"Deactivate", "Increment", "Decrement", // state operations
		"Logout", "Login", // auth operations (context often in struct)
		"Group", "Mount", "NotFound", "MethodNotAllowed", // router methods
		"Select", "Handle", // handler methods
		"Connect", "Disconnect", "Reconnect", // connection methods
		"DSN", "URL", "URI", // config getters
		"Count", "Length", "Size", "Len", // size methods
		"Health", "Liveness", "Readiness", // health check handlers (context in request)
		"Initialize", "InitializeDefaultContainer", "InitializeEnterpriseErrorSystem", // initialization functions
		"ConfigurationNotLoaded", "QueryExecutionFailed", "HTTPRequestFailed", // error message methods
		"RevokeAllSessions",         // session management
		"Enable", "Disable", "Name", // middleware control methods
		"CommitTransaction", "RollbackTransaction", // transaction methods
		"Calculate", // calculation methods
	}

	for _, special := range specialNames {
		if name == special {
			return true
		}
	}

	// Pure function prefixes - no I/O, no need for context
	purePrefixes := []string{
		"Is", "Has", "Can", "Should", "Must", "Will", "Requires", // predicates
		"Get", "Set", // accessors
		"Valid", "Validate", "Check", "Verify", // validation
		"Wrap", "Unwrap", "Handle", // error handling
		"Marshal", "Unmarshal", "Encode", "Decode", "Serialize", "Deserialize", // serialization
		"Sign", "Encrypt", "Decrypt", "Hash", // crypto (pure operations)
		"Calculate", "Compute", "Convert", "Transform", "Format", "Normalize", // transformations
		"Extract", "Split", "Join", "Trim", "Replace", // string/data manipulation
		"Register", "Unregister", // registration (often init-time)
		"Add", "Remove", "Append", "Prepend", "Insert", "Delete", // collection operations
		"With", "Without", // builder pattern
		"To", "From", "As", // conversion
		"Apply", "Filter", "Map", "Reduce", "Sort", "Merge", // functional operations
		"Contains", "ContainsKey", "ContainsValue", "Exists", "Lookup", "Find", // lookups (in-memory)
		"Compare", "Equal", "Match", "Matches", // comparison
		"Clone", "Copy", "Dup", // copying
		"Or",                                    // alternative values
		"Prepare", "Setup", "Configure", "Init", // initialization
		"Enable", "Disable", "Activate", "Deactivate", // toggle operations
		"Write", "Read", "Close", "Open", // I/O (often interface methods)
		"Multi", "Safe", "Try", // wrapper patterns
		"Generate", "Render", "Print", // output generation
		"Allowed", "Denied", "Permitted", // authorization checks
		"Reset", "Update", "Refresh", // state operations
		"Serve", "Benchmark", "Test", "Example", // special function types
		"Array", "Slice", "Map", "Struct", // type conversion helpers
		"Bool", "Int", "String", "Float", "Byte", // type helpers
		"Canonical", "Standard", "Combine", // utility patterns
		"Cannot", "Invalid", "Missing", "Unknown", // error message helpers
		"Failed", "Unable", "Database", "Transaction", "Connection", // error patterns
		"Require", "Assert", "Ensure", // assertion helpers
		"Analyze", "Inspect", "Examine", // analysis helpers
		"Authentication", "Authorization", // auth helpers (return strings/errors)
		"Send", "Respond", "Reply", // HTTP response helpers
		"Decimal", "Time", "UUID", "Null", "Nullable", "Jsonb", "Json", // type conversion
		"Truncate", "Pad", "Smart", // string/data utilities
		"Success", "Failure", "Result", // result helpers
		"SLA", "Monitoring", "Logging", "Log", // observability
		"Status", "Resource", "Start", "Stop", "Span", // lifecycle/tracing
		"Required", "Optional", "Default", // field helpers
		"List", "Enumerate", "Iterate", // listing operations
		"Broadcast", "Emit", "Notify", "Dispatch", "Publish", // event operations
		"Determine", "Resolve", "Decide", // decision helpers
		"Clear", "Wipe", "Purge", // cleanup operations
		"First", "Last", "Min", "Max", // accessor helpers
		"Record", "Track", "Measure", // metrics (often context in struct)
		"Finish", "Complete", "Finalize", // completion operations
		"Name", "Type", "Kind", // metadata accessors
		"Enforce",                // permission/security enforcement
		"Increment", "Decrement", // counter operations
		"Logout", "Login", // auth operations
		"Select", "Choose", "Pick", // selection operations
		"Error",                           // error helpers
		"Health", "Liveness", "Readiness", // health checks (context in request)
		"Cleanup", "Teardown", // cleanup operations
		"Common", "Shared", "Global", // utility accessors
		"Business", "Domain", // domain logic (often pure)
		"Blockchain", "Detailed", // specific handlers
		"LessThan", "GreaterThan", "EqualTo", // comparison methods
		"Compound", // calculation prefixes
	}

	for _, prefix := range purePrefixes {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			nextChar := rune(name[len(prefix)])
			// Allow uppercase letter or digit after prefix (e.g., Float64, Int32)
			if unicode.IsUpper(nextChar) || unicode.IsDigit(nextChar) || prefix == name {
				return true
			}
		}
	}

	// Pure function suffixes
	pureSuffixes := []string{
		"Operations", "Interface", "Impl", // delegation/interface patterns
		"Helper", "Helpers", "Utils", "Util", // utility functions
		"Builder", "Factory", // builder pattern
		"Handler", "Processor", // often have context in struct
		"Validator", "Checker", // validation
		"Formatter", "Converter", "Transformer", "Mapper", "Serializer", // transformations
		"JSONB", "JSON", "XML", "YAML", // serialization helpers
		"ByID", "ByName", "ByEmail", "ByKey", "ByValue", // lookup helpers
		"Repo", "Repository", "Service", "Client", // dependency accessors
		"Provider", "Manager", "Store", "Cache", // infrastructure accessors
		"Config", "Logger", "Metrics", // infrastructure getters
		"Columns", "Table", "Schema", "Query", // database metadata
		"Command", "Action", "Task", // CLI/commands
		"Response", "Request", // HTTP helpers
		"ForTesting", "ForTests", "ForTest", // test helpers
		"Quietly", "WithTimeout", // utility wrappers
		"Address", "Network", "Path", "URL", // resource identifiers
		"Middleware", "Interceptor", // HTTP middleware
		"FromString", "FromNull", "FromNullable", "ToNullable", // conversions
		"Strict",                                     // validation variants
		"WithTrace", "Structured", "WithCorrelation", // logging variants
		"Success", "Error", "Access", // response/status suffixes
		"Exists", "Value", "Path", // JSONB/JSON query helpers
		"Time", "Duration", "Retry", // timing helpers
		"Event", "Session", "Token", // domain objects
	}

	for _, suffix := range pureSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}

	return false
}

func (r *ContextFirstRule) isSimpleOperation(fn *ast.FuncDecl) bool {
	// Skip simple operations like Close(), Flush(), Reset()
	simpleOps := []string{"Close", "Flush", "Reset", "Clear", "Stop", "Start"}
	for _, op := range simpleOps {
		if fn.Name.Name == op {
			return true
		}
	}
	return false
}

func (r *ContextFirstRule) isConstructor(name string) bool {
	// New*, Make*, Create* without further params context expectation
	return strings.HasPrefix(name, "New") ||
		strings.HasPrefix(name, "Make") ||
		strings.HasPrefix(name, "Create") ||
		strings.HasPrefix(name, "Build") ||
		strings.HasPrefix(name, "Parse") ||
		strings.HasPrefix(name, "Load") ||
		strings.HasPrefix(name, "Must")
}

func (r *ContextFirstRule) hasContextFirstParam(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return false
	}

	firstParam := fn.Type.Params.List[0]
	return isContextType(firstParam.Type)
}

func isContextType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name == "context" && t.Sel.Name == "Context"
		}
	case *ast.Ident:
		// Handle aliased imports like `ctx context.Context`
		return t.Name == "Context"
	}
	return false
}

func isPublic(name string) bool {
	if len(name) == 0 {
		return false
	}
	return unicode.IsUpper(rune(name[0]))
}

func getReceiverTypeName(expr ast.Expr) string {
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
