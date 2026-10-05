package patterns

import (
	"errors"
	"go/ast"
	"go/constant"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUpstream4xxReportedAsOutageRule())
}

// Upstream4xxReportedAsOutageRule detects an HTTP handler answering every
// failure of a call into an upstream client with 502, 503 or 504, while the
// client's errors carry the upstream's HTTP status:
//
//	banks, err := a.provider.GetBanks(ctx, req)
//	if err != nil {
//		a.logger.Error("failed to get banks", "error", err)
//		writeJSONError(w, http.StatusBadGateway, "provider is unavailable")
//		return
//	}
//
// A 4xx of the upstream is its answer on the merits - the direction is not
// served, the currency is unknown, the input is invalid. Reported as an
// outage, it tells the client to retry what cannot work, hides the reason,
// and fills the incident log with requests nothing on our side can fix.
//
// The upstream is a package of the project that declares an error type with
// an HTTP status field, or imports one, other than the handler's own; an
// interface method counts when one of its implementations lives there. A
// branch that tells errors apart (an if, a switch, errors.As) is left alone.
type Upstream4xxReportedAsOutageRule struct {
	*rules.BaseRule
}

// NewUpstream4xxReportedAsOutageRule creates the rule
func NewUpstream4xxReportedAsOutageRule() *Upstream4xxReportedAsOutageRule {
	return &Upstream4xxReportedAsOutageRule{BaseRule: rules.NewBaseRule(
		"upstream-4xx-reported-as-outage",
		"patterns",
		"Detects a handler answering every failure of an upstream client call with 502/503/504 while the client's errors carry the upstream's HTTP status — the upstream's refusal of the request is reported as its outage",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the upstream is found across packages.
func (r *Upstream4xxReportedAsOutageRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *Upstream4xxReportedAsOutageRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the outage answers to upstream calls.
func (r *Upstream4xxReportedAsOutageRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("upstream 4xx reported as outage: nil Go project context")
	}
	upstream := statusErrorPackages(ctx)
	if len(upstream) == 0 {
		return nil, nil
	}
	named := projectNamedTypes(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !takesResponseWriter(info, fn.Type) {
				continue
			}
			own := info.Defs[fn.Name].Pkg()
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				block, ok := n.(*ast.BlockStmt)
				if !ok {
					return true
				}
				for i, stmt := range block.List {
					call, branch := executeChecked(block.List, i, stmt)
					if call == nil || branchesOnError(branch) || !callsUpstream(info, call, own, upstream, named) {
						continue
					}
					answer := outageAnswer(info, branch)
					if answer == nil {
						continue
					}
					line := file.LineFor(answer)
					if file.IsSuppressed(line, r.Name()) {
						continue
					}
					v := r.CreateViolation(file.RelPath, line,
						"Every failure of this upstream call is answered as an outage, while the client's errors carry the upstream's HTTP status — a 4xx refusal of the request is reported as the upstream being down")
					v.WithCode(strings.TrimSpace(file.GetLine(line)))
					v.WithSuggestion("Tell the upstream's 4xx apart (errors.As to its error type, a refusal classifier of the adapter) and answer it as the request's problem with the reason; keep 502/503 for transport failures and 5xx")
					violations = append(violations, v)
				}
				return true
			})
		}
		return violations
	})
}

// outageResponder is the name of a function answering an outage.
var outageResponder = regexp.MustCompile(`(?i)badgateway|serviceunavailable|gatewaytimeout`)

// outageAnswer returns the call of a branch answering 502, 503 or 504.
func outageAnswer(info *types.Info, body *ast.BlockStmt) *ast.CallExpr {
	var answer *ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || answer != nil {
			return answer == nil
		}
		if outageResponder.MatchString(callName(call)) {
			answer = call
			return false
		}
		for _, arg := range call.Args {
			if tv, ok := info.Types[arg]; ok && tv.Value != nil && tv.Value.Kind() == constant.Int && isStatusExpr(arg) {
				if status, exact := constant.Int64Val(tv.Value); exact && status >= 502 && status <= 504 {
					answer = call
				}
			}
		}
		return answer == nil
	})
	return answer
}

// branchesOnError reports a branch that tells anything apart: an if, a
// switch, or errors.Is/As.
func branchesOnError(body *ast.BlockStmt) bool {
	found := comparesError(body)
	ast.Inspect(body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.IfStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt:
			found = true
		}
		return !found
	})
	return found
}

// callsUpstream reports a call of a function or method of an upstream
// package other than own, or of an interface method one of whose
// implementations is in an upstream package.
func callsUpstream(info *types.Info, call *ast.CallExpr, own *types.Package, upstream map[string]bool, named []*types.Named) bool {
	callee, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok || callee.Pkg() == nil || callee.Pkg() == own {
		return false
	}
	if upstream[callee.Pkg().Path()] {
		return true
	}
	sig, ok := callee.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	iface, ok := sig.Recv().Type().Underlying().(*types.Interface)
	if !ok {
		return false
	}
	for _, t := range named {
		if t.Obj().Pkg() == nil || !upstream[t.Obj().Pkg().Path()] || types.IsInterface(t) {
			continue
		}
		if types.Implements(t, iface) || types.Implements(types.NewPointer(t), iface) {
			return true
		}
	}
	return false
}

// statusFieldNames are the fields an error type keeps an HTTP status in.
var statusFieldNames = map[string]bool{"StatusCode": true, "HTTPStatus": true, "HTTPStatusCode": true, "Status": true}

// statusErrorPackages returns the project packages that declare an error
// type with an HTTP status field, and the packages importing one of them.
func statusErrorPackages(ctx *core.GoProjectContext) map[string]bool {
	declaring := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.Types == nil {
			continue
		}
		scope := pkg.Package.Types.Scope()
		for _, name := range scope.Names() {
			if isStatusErrorType(scope.Lookup(name)) {
				declaring[pkg.Package.PkgPath] = true
				break
			}
		}
	}
	upstream := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		if declaring[pkg.Package.PkgPath] {
			upstream[pkg.Package.PkgPath] = true
			continue
		}
		for path := range pkg.Package.Imports {
			if declaring[path] {
				upstream[pkg.Package.PkgPath] = true
			}
		}
	}
	return upstream
}

// isStatusErrorType reports a struct type implementing error with an int
// field holding an HTTP status.
func isStatusErrorType(obj types.Object) bool {
	typeName, ok := obj.(*types.TypeName)
	if !ok || typeName.IsAlias() {
		return false
	}
	structType, ok := typeName.Type().Underlying().(*types.Struct)
	if !ok || (!implementsError(typeName.Type()) && !implementsError(types.NewPointer(typeName.Type()))) {
		return false
	}
	for field := range structType.Fields() {
		if basic, ok := field.Type().(*types.Basic); ok && basic.Info()&types.IsInteger != 0 && statusFieldNames[field.Name()] {
			return true
		}
	}
	return false
}

// projectNamedTypes returns the named types the project's packages declare.
func projectNamedTypes(ctx *core.GoProjectContext) []*types.Named {
	var named []*types.Named
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.Types == nil {
			continue
		}
		scope := pkg.Package.Types.Scope()
		for _, name := range scope.Names() {
			if typeName, ok := scope.Lookup(name).(*types.TypeName); ok && !typeName.IsAlias() {
				if t, ok := typeName.Type().(*types.Named); ok {
					named = append(named, t)
				}
			}
		}
	}
	return named
}
