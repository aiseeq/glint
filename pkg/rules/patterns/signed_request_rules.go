package patterns

import (
	"cmp"
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewSignatureOverDifferentBytesThanSentRule())
	rules.Register(NewOutboundRequestBodyLoggedRule())
	rules.Register(NewProviderResponseBodyLoggedRule())
	rules.Register(NewHMACVerifiedWithEmptySecretRule())
	rules.Register(NewRequestSignatureWithoutTimestampOrTargetRule())
	rules.Register(NewJSONMarshalHTMLEscapingInSignedPayloadRule())
}

// NewSignatureOverDifferentBytesThanSentRule creates signature-over-different-bytes-than-sent:
// the signer is given the value and marshals it on its own, while the request
// body is another marshal of the value - key order, trimming or escaping
// differ, and the provider rejects the signature:
//
//	sig, err := c.signer.SignBody(body)       // marshals inside
//	data, err := json.Marshal(trim(body))     // what is sent
//	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
func NewSignatureOverDifferentBytesThanSentRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"signature-over-different-bytes-than-sent",
			"patterns",
			"Detects a signer given an unserialized value while the request body is a separate json.Marshal of it — the signed bytes are not the sent bytes",
			core.SeverityHigh,
		),
		suggestion: "Marshal once and pass the same []byte to the signer and to the request body",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		marshals := jsonMarshals(scope.info, fn.Body)
		sent := sentBodies(scope.info, fn.Body)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !signsValue(call) {
				return true
			}
			for _, arg := range call.Args {
				v := identObject(scope.info, arg)
				if v == nil || isBytesOrString(v.Type()) {
					continue
				}
				for _, data := range slices.SortedFunc(maps.Keys(marshals), func(a, b types.Object) int { return cmp.Compare(a.Pos(), b.Pos()) }) {
					if sent[data] && mentionsObject(scope.info, marshals[data], v) {
						findings = append(findings, funcFinding{node: call, message: callName(call) + " signs " + v.Name() + " marshaled on its own, while the request sends " + data.Name() + " from a separate json.Marshal — the provider checks the signature against other bytes"})
						return true
					}
				}
			}
			return true
		})
		return findings
	}
	return r
}

// signsValue matches a call named Sign...: SignBody, signPayload.
func signsValue(call *ast.CallExpr) bool {
	name := callName(call)
	if !helpers.HasLeadingWord(name, "Sign") {
		return false
	}
	words := helpers.IdentifierWords(name)
	return len(words) < 2 || (words[1] != "in" && words[1] != "up" && words[1] != "out" && words[1] != "on")
}

// jsonMarshals returns the variables assigned from json.Marshal and what
// each marshals.
func jsonMarshals(info *types.Info, body *ast.BlockStmt) map[types.Object]ast.Expr {
	marshals := make(map[types.Object]ast.Expr)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || len(call.Args) != 1 || !isPkgFunc(info, call, "encoding/json", "Marshal") {
			return true
		}
		if obj := identObject(info, assign.Lhs[0]); obj != nil {
			marshals[obj] = call.Args[0]
		}
		return true
	})
	return marshals
}

// requestBodyReaders wrap the bytes a request sends.
var requestBodyReaders = map[string]map[string]bool{
	"bytes":    {"NewReader": true, "NewBuffer": true},
	"strings":  {"NewReader": true},
	"net/http": {"NewRequest": true, "NewRequestWithContext": true, "Post": true},
}

// sentBodies returns the variables a body passes as the body of an outgoing
// request: bytes.NewReader(data) or an http.NewRequest argument.
func sentBodies(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	sent := make(map[types.Object]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := staticFunc(info, call)
		if fn == nil || fn.Pkg() == nil || !requestBodyReaders[fn.Pkg().Path()][fn.Name()] {
			return true
		}
		for _, arg := range call.Args {
			if obj := identObject(info, arg); obj != nil && isBytesOrString(obj.Type()) {
				sent[obj] = true
			}
		}
		return true
	})
	return sent
}

// identObject returns the variable an identifier expression names.
func identObject(info *types.Info, expr ast.Expr) *types.Var {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil
	}
	v, _ := info.ObjectOf(id).(*types.Var)
	return v
}

// isBytesOrString reports []byte or a string.
func isBytesOrString(t types.Type) bool {
	if basic, ok := t.Underlying().(*types.Basic); ok {
		return basic.Kind() == types.String
	}
	slice, ok := t.Underlying().(*types.Slice)
	if !ok {
		return false
	}
	elem, ok := slice.Elem().Underlying().(*types.Basic)
	return ok && elem.Kind() == types.Byte
}

// stringConversionOf returns x of string(x).
func stringConversionOf(info *types.Info, expr ast.Expr) ast.Expr {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil
	}
	tv, ok := info.Types[call.Fun]
	if !ok || !tv.IsType() {
		return nil
	}
	if basic, ok := tv.Type.Underlying().(*types.Basic); !ok || basic.Kind() != types.String {
		return nil
	}
	return call.Args[0]
}

// loudLogVerbs are the levels a production logger writes.
var loudLogVerbs = map[string]bool{"info": true, "infof": true, "infow": true, "warn": true, "warnf": true, "warnw": true,
	"warning": true, "error": true, "errorf": true, "errorw": true, "print": true, "printf": true, "println": true}

// NewOutboundRequestBodyLoggedRule creates outbound-request-body-logged: a
// client logs the bytes it sends to an external API at Info or above - the
// customer's data in the request lands in the logs on every call:
//
//	c.logger.Info("provider request", "body", string(data))
//	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
func NewOutboundRequestBodyLoggedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"outbound-request-body-logged",
			"patterns",
			"Detects the body of an outgoing request logged at Info or above — the personal data it carries lands in the logs on every call",
			core.SeverityMedium,
		),
		suggestion: "Log the length, a hash or the identifiers of the request, not its body; keep the body for a Debug line off in production",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		sent := sentBodies(scope.info, fn.Body)
		if len(sent) == 0 {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !loudLogCall(call) {
				return true
			}
			for _, arg := range call.Args {
				if obj := identObject(scope.info, stringConversionOf(scope.info, arg)); obj != nil && sent[obj] {
					findings = append(findings, funcFinding{node: arg, message: "The body sent to the external API (" + obj.Name() + ") is logged — the personal data it carries lands in the logs on every call"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// loudLogCall matches a logger call at Info or above.
func loudLogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && helpers.IsLoggerCall(call) && loudLogVerbs[helpers.LogVerb(sel)]
}

// NewProviderResponseBodyLoggedRule creates provider-response-body-logged:
// the body of an external API's response logged at Info - the provider's copy
// of the customer's data lands in the logs on every call. A body logged at
// error level about a failed call is left alone:
//
//	body, _ := io.ReadAll(resp.Body)
//	logger.Info("provider response", "body", string(body))
func NewProviderResponseBodyLoggedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"provider-response-body-logged",
			"patterns",
			"Detects the body of an HTTP response logged at Info — the provider's copy of the personal data lands in the logs on every call",
			core.SeverityMedium,
		),
		suggestion: "Log the status, the length and the identifiers of the response; log its body only on a failure, or at Debug",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		carriers := responseBodies(scope.info, fn.Body)
		if obj, ok := scope.info.Defs[fn.Name].(*types.Func); ok {
			for i, param := range paramObjects(typedFuncDecl{decl: fn, info: scope.info}) {
				if param != nil && isBytesOrString(param.Type()) && passedResponseBody(scope.callers[obj], i) {
					carriers[param] = true
				}
			}
		}
		if len(carriers) == 0 {
			return nil
		}
		spreadCarriers(scope.info, fn.Body, carriers)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !infoLogCall(call) {
				return true
			}
			for _, arg := range call.Args {
				if t := scope.info.TypeOf(arg); t != nil && isBytesOrString(t) && readsCarrier(scope.info, arg, carriers) {
					findings = append(findings, funcFinding{node: arg, message: "The body of the provider's response is logged at Info — the personal data it carries lands in the logs on every call"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// infoLogCall matches a logger call at Info (or an unlevelled print).
func infoLogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !helpers.IsLoggerCall(call) {
		return false
	}
	switch helpers.LogVerb(sel) {
	case "info", "infof", "infow", "print", "printf", "println":
		return true
	}
	return false
}

// responseBodies returns the variables a body reads an HTTP response's body
// into: body, _ := io.ReadAll(resp.Body).
func responseBodies(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	bodies := make(map[types.Object]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || len(call.Args) != 1 || !isPkgFunc(info, call, "io", "ReadAll") {
			return true
		}
		sel, ok := ast.Unparen(call.Args[0]).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Body" || !isPointerToNamedType(info.TypeOf(sel.X), "net/http", "Response") {
			return true
		}
		if obj := identObject(info, assign.Lhs[0]); obj != nil {
			bodies[obj] = true
		}
		return true
	})
	return bodies
}

// passedResponseBody reports a parameter some caller fills with the
// body of an HTTP response it read.
func passedResponseBody(sites []funcCallSite, i int) bool {
	for _, site := range sites {
		if i >= len(site.call.Args) {
			continue
		}
		if obj := identObject(site.caller.info, site.call.Args[i]); obj != nil && responseBodies(site.caller.info, site.caller.decl.Body)[obj] {
			return true
		}
	}
	return false
}

// spreadCarriers adds the string and byte variables assigned from a carrier:
// text := string(body), text = text[:500] + "...".
func spreadCarriers(info *types.Info, body *ast.BlockStmt, carriers map[types.Object]bool) {
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != len(assign.Rhs) {
				return true
			}
			for i, lhs := range assign.Lhs {
				obj := identObject(info, lhs)
				if obj == nil || carriers[obj] || !isBytesOrString(obj.Type()) || !readsCarrier(info, assign.Rhs[i], carriers) {
					continue
				}
				carriers[obj] = true
				changed = true
			}
			return true
		})
	}
}

// readsCarrier reports an expression reading one of the objects outside a
// len() call.
func readsCarrier(info *types.Info, expr ast.Expr, objects map[types.Object]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isIdentNamed(call.Fun, "len") {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && objects[info.ObjectOf(id)] {
			found = true
		}
		return !found
	})
	return found
}

// NewHMACVerifiedWithEmptySecretRule creates hmac-verified-with-empty-secret:
// an HMAC verification keyed by a secret that comes from configuration with
// no check that it is set - with the variable missing the key is empty, and
// anyone computes a valid signature with the empty key:
//
//	mac := hmac.New(sha256.New, []byte(secret)) // secret = cfg.WebhookSecret, never required
func NewHMACVerifiedWithEmptySecretRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"hmac-verified-with-empty-secret",
			"patterns",
			"Detects an HMAC verification keyed by a configuration secret that no code requires to be non-empty — with the variable unset, a signature made with the empty key passes",
			core.SeverityHigh,
		),
		suggestion: "Refuse to start when the secret is empty (validate the configuration), or reject every request while it is",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		checked := emptyCheckedFields(decls)
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			if fn.Body == nil || !verifiesMAC(scope.info, fn.Body) {
				return nil
			}
			self := typedFuncDecl{decl: fn, info: scope.info}
			var findings []funcFinding
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 2 || !isPkgFunc(scope.info, call, "crypto/hmac", "New") {
					return true
				}
				key := identObject(scope.info, unconverted(call.Args[1]))
				if key == nil {
					return true
				}
				if source, ok := unguardedSecret(scope, self, key, checked, 0); ok {
					findings = append(findings, funcFinding{node: call, message: "The HMAC key comes from " + source + ", which no code requires to be set — with it unset, a signature made with the empty key passes"})
				}
				return true
			})
			return findings
		}
	}
	return r
}

// verifiesMAC reports a body comparing a MAC: hmac.Equal or a constant-time
// compare.
func verifiesMAC(info *types.Info, body ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && (isPkgFunc(info, call, "crypto/hmac", "Equal") || isPkgFunc(info, call, "crypto/subtle", "ConstantTimeCompare")) {
			found = true
		}
		return !found
	})
	return found
}

// unconverted strips a []byte(x) conversion.
func unconverted(expr ast.Expr) ast.Expr {
	if call, ok := ast.Unparen(expr).(*ast.CallExpr); ok && len(call.Args) == 1 {
		if arr, ok := call.Fun.(*ast.ArrayType); ok && arr.Len == nil {
			return call.Args[0]
		}
	}
	return expr
}

// maxSecretHops bounds how many callers up a secret parameter is followed.
const maxSecretHops = 5

// unguardedSecret follows a key parameter up through the callers to where it
// is read and returns that read when it is a configuration field no code
// checks for empty, or os.Getenv.
func unguardedSecret(scope funcScope, fn typedFuncDecl, key *types.Var, checked map[*types.Var]bool, hops int) (string, bool) {
	if hops > maxSecretHops || testsEmpty(fn.info, fn.decl.Body, func(e ast.Expr) bool { return mentionsObject(fn.info, e, key) }) {
		return "", false
	}
	index := -1
	for i, param := range paramObjects(fn) {
		if param == key {
			index = i
		}
	}
	obj, ok := fn.info.Defs[fn.decl.Name].(*types.Func)
	if index < 0 || !ok {
		return "", false
	}
	for _, site := range scope.callers[obj] {
		if index >= len(site.call.Args) {
			continue
		}
		arg := unconverted(site.call.Args[index])
		if call, ok := ast.Unparen(arg).(*ast.CallExpr); ok && isPkgFunc(site.caller.info, call, "os", "Getenv") {
			return "os.Getenv", true
		}
		if _, field, ok := fieldSelection(site.caller.info, arg); ok && !checked[field] {
			return field.Name(), true
		}
		if outer := identObject(site.caller.info, arg); outer != nil {
			if source, ok := unguardedSecret(scope, site.caller, outer, checked, hops+1); ok {
				return source, true
			}
		}
	}
	return "", false
}

// fieldSelection matches x.F of a struct field F.
func fieldSelection(info *types.Info, expr ast.Expr) (ast.Expr, *types.Var, bool) {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return nil, nil, false
	}
	selection := info.Selections[sel]
	if selection == nil || selection.Kind() != types.FieldVal {
		return nil, nil, false
	}
	field, ok := selection.Obj().(*types.Var)
	return sel.X, field, ok
}

// emptyCheckedFields returns the struct fields some body compares with ""
// (or whose length it tests), and the fields tagged as required.
func emptyCheckedFields(decls map[*types.Func]typedFuncDecl) map[*types.Var]bool {
	checked := make(map[*types.Var]bool)
	for _, decl := range decls {
		testsEmpty(decl.info, decl.decl.Body, func(e ast.Expr) bool {
			ast.Inspect(e, func(n ast.Node) bool {
				if expr, ok := n.(ast.Expr); ok {
					if _, field, ok := fieldSelection(decl.info, expr); ok {
						checked[field] = true
					}
				}
				return true
			})
			return false
		})
		ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
			if expr, ok := n.(ast.Expr); ok {
				if x, field, ok := fieldSelection(decl.info, expr); ok && requiredField(decl.info.TypeOf(x), field) {
					checked[field] = true
				}
			}
			return true
		})
	}
	return checked
}

// requiredField reports a field whose tag marks it required.
func requiredField(owner types.Type, field *types.Var) bool {
	if ptr, ok := owner.(*types.Pointer); ok {
		owner = ptr.Elem()
	}
	st, ok := owner.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := range st.NumFields() {
		if st.Field(i) != field {
			continue
		}
		tag := reflect.StructTag(st.Tag(i))
		return strings.Contains(tag.Get("validate"), "required") || tag.Get("required") == "true" || strings.Contains(tag.Get("env"), "required")
	}
	return false
}

// testsEmpty reports a comparison with "" or a length test of an
// expression match accepts.
func testsEmpty(info *types.Info, body *ast.BlockStmt, match func(ast.Expr) bool) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || found {
			return !found
		}
		switch bin.Op {
		case token.EQL, token.NEQ, token.GTR, token.LSS, token.GEQ, token.LEQ:
		default:
			return true
		}
		for _, pair := range [][2]ast.Expr{{bin.X, bin.Y}, {bin.Y, bin.X}} {
			side, other := ast.Unparen(pair[0]), ast.Unparen(pair[1])
			if lit, ok := other.(*ast.BasicLit); ok && lit.Value == `""` && match(side) {
				found = true
			}
			if call, ok := side.(*ast.CallExpr); ok && isIdentNamed(call.Fun, "len") && len(call.Args) == 1 && match(call.Args[0]) {
				found = true
			}
		}
		return !found
	})
	return found
}

// NewRequestSignatureWithoutTimestampOrTargetRule creates request-signature-without-timestamp-or-target:
// an inbound signature checked only when the request has a body - a POST or a
// DELETE without one passes unsigned:
//
//	if r.ContentLength != 0 {
//		body, _ := io.ReadAll(r.Body)
//		if !verifySignature(body, r.Header.Get("X-Signature"), secret) { ... }
//	}
//	next.ServeHTTP(w, r)
func NewRequestSignatureWithoutTimestampOrTargetRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"request-signature-without-timestamp-or-target",
			"patterns",
			"Detects an inbound request signature verified only when the request has a body — a request without one passes unsigned, and the signature binds neither the method nor the path",
			core.SeverityHigh,
		),
		suggestion: "Verify every request that changes state; sign the method, the path and a timestamp together with the body",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ifStmt, ok := n.(*ast.IfStmt)
			if !ok || ifStmt.Else != nil || !testsBodyPresent(scope.info, ifStmt.Cond) {
				return true
			}
			if checksSignature(scope, ifStmt.Body) {
				findings = append(findings, funcFinding{node: ifStmt, message: "The signature is verified only when the request has a body — a request without one passes unsigned"})
			}
			return true
		})
		return findings
	}
	return r
}

// testsBodyPresent matches a condition holding r.ContentLength != 0 or > 0
// of an *http.Request.
func testsBodyPresent(info *types.Info, cond ast.Expr) bool {
	found := false
	for _, term := range flattenAnd(cond) {
		bin, ok := ast.Unparen(term).(*ast.BinaryExpr)
		if !ok || (bin.Op != token.NEQ && bin.Op != token.GTR) {
			continue
		}
		sel, ok := ast.Unparen(bin.X).(*ast.SelectorExpr)
		lit, litOK := ast.Unparen(bin.Y).(*ast.BasicLit)
		if ok && litOK && lit.Value == "0" && sel.Sel.Name == "ContentLength" && isPointerToNamedType(info.TypeOf(sel.X), "net/http", "Request") {
			found = true
		}
	}
	return found
}

// checksSignature reports a block that compares a MAC itself or calls a
// function that does.
func checksSignature(scope funcScope, block *ast.BlockStmt) bool {
	if verifiesMAC(scope.info, block) {
		return true
	}
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if decl, ok := scope.callee(call); ok && verifiesMAC(decl.info, decl.decl.Body) {
				found = true
			}
		}
		return !found
	})
	return found
}

// NewJSONMarshalHTMLEscapingInSignedPayloadRule creates json-marshal-html-escaping-in-signed-payload:
// json.Marshal escapes <, > and & as <, > and &; bytes signed
// from it differ from the document the provider canonicalizes as soon as a
// value holds one of them:
//
//	data, _ := json.Marshal(body)
//	sig, _ := s.Sign(data)
func NewJSONMarshalHTMLEscapingInSignedPayloadRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"json-marshal-html-escaping-in-signed-payload",
			"patterns",
			"Detects json.Marshal output handed to a signer — Marshal escapes <, > and &, so a value holding one is signed in a form the other side does not produce",
			core.SeverityMedium,
		),
		suggestion: "Encode with json.NewEncoder and SetEscapeHTML(false), trim the trailing newline, and sign and send those bytes",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		obj, _ := scope.info.Defs[fn.Name].(*types.Func)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
				return true
			}
			call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
			data := identObject(scope.info, assign.Lhs[0])
			if !ok || data == nil || !isPkgFunc(scope.info, call, "encoding/json", "Marshal") {
				return true
			}
			if signedIn(scope.info, fn.Body, data) || (obj != nil && returned(scope.info, fn.Body, data) && callersSign(scope.callers[obj])) {
				findings = append(findings, funcFinding{node: call, message: "The output of json.Marshal is signed — Marshal escapes <, > and & as \\u003c, \\u003e and \\u0026, so a value holding one is signed in a form the other side does not produce"})
			}
			return true
		})
		return findings
	}
	return r
}

// signedIn reports a body passing the bytes to a signer. A digest of its own
// marshal (a fingerprint, a snapshot hash) is compared with the same
// marshal, and a MAC over the bytes sent verifies against those bytes.
func signedIn(info *types.Info, body *ast.BlockStmt, data types.Object) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found || !signsValue(call) {
			return !found
		}
		for _, arg := range call.Args {
			if identObject(info, arg) == data {
				found = true
			}
		}
		return !found
	})
	return found
}

// returned reports a body returning the variable.
func returned(info *types.Info, body *ast.BlockStmt, data types.Object) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if ret, ok := n.(*ast.ReturnStmt); ok {
			for _, result := range ret.Results {
				if identObject(info, result) == data {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// callersSign reports a caller that signs the bytes the call returns.
func callersSign(sites []funcCallSite) bool {
	for _, site := range sites {
		signed := false
		ast.Inspect(site.caller.decl.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || signed || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 || ast.Unparen(assign.Rhs[0]) != site.call {
				return !signed
			}
			if result := identObject(site.caller.info, assign.Lhs[0]); result != nil && signedIn(site.caller.info, site.caller.decl.Body, result) {
				signed = true
			}
			return !signed
		})
		if signed {
			return true
		}
	}
	return false
}
