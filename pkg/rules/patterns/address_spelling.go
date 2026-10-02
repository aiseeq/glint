package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewAddressComparedAsSpelledRule())
	rules.Register(NewAddressFoldedPastCanonicalKeyRule())
	rules.Register(NewAddressEntrySkipsCanonicalSpellingRule())
}

// addressWords name a value holding an account or token address: one
// account may come spelled several ways (case of a hex address, the raw and
// the friendly form of another chain's), and a project that knows it brings
// the spellings to one canonical form.
var addressWords = wordSet("address", "addr", "wallet", "contract")

// isAddressName reports a name whose head word is an address word:
// walletAddress, fromAddr, wallets, or one that leads with "address"
// (AddressOwner). A name qualifying something of an address (WalletCurrency,
// walletID) is not one.
func isAddressName(name string) bool {
	words := helpers.IdentifierWords(name)
	return len(words) > 0 && (addressWords[words[len(words)-1]] || words[0] == "address")
}

// isAddressCanonicalizer reports a function that brings an address to the
// project's one spelling or compares two in it: normalizeTronAddress,
// canonicalWalletSpelling, AddressKey, syncWalletKey, sameAccountAddress.
func isAddressCanonicalizer(name string) bool {
	words := helpers.IdentifierWords(name)
	if len(words) == 0 {
		return false
	}
	if len(words) >= 2 && addressWords[words[len(words)-2]] && words[len(words)-1] == "key" {
		return true
	}
	subject := false
	for _, word := range words[1:] {
		if addressWords[word] || word == "account" || word == "spelling" {
			subject = true
		}
	}
	switch words[0] {
	case "normalize", "normalise", "canonical", "canonicalize", "canonicalise", "same":
		return subject
	}
	return false
}

// isAddressKeyFunc reports the canonical key form of an address a module
// exports for every other place to use: AddressKey, NormalizeAddress. It
// takes an address and gives its key, with no error: a key of every address.
// A parser that fails on forms it does not know (NormalizeAddress(a) (string,
// error) of one chain) brings one chain's spellings together, not all.
func isAddressKeyFunc(fn *types.Func) bool {
	sig := fn.Signature()
	if !fn.Exported() || sig.Recv() != nil || sig.Params().Len() != 1 || sig.Results().Len() != 1 ||
		!isStringType(sig.Params().At(0).Type()) || !isStringType(sig.Results().At(0).Type()) {
		return false
	}
	words := helpers.IdentifierWords(fn.Name())
	n := len(words)
	return (n >= 2 && words[n-2] == "address" && words[n-1] == "key") ||
		(n >= 2 && (words[0] == "normalize" || words[0] == "canonical") && words[n-1] == "address")
}

// addressFuncs returns the address canonicalizers and canonical key
// functions the loaded packages declare, by name.
func addressFuncs(decls map[*types.Func]typedFuncDecl) (canonical, keys []string) {
	for fn := range decls {
		if isAddressCanonicalizer(fn.Name()) {
			canonical = append(canonical, fn.Name())
		}
		if isAddressKeyFunc(fn) {
			keys = append(keys, fn.Name())
		}
	}
	sort.Strings(canonical)
	sort.Strings(keys)
	return canonical, keys
}

// addressFlow is what a function's address values are: the variables that
// hold an address as some caller or record spelled it, and the variables and
// struct fields holding the canonical spelling (assigned from a canonicalizer
// anywhere in the function: wallet := AddressKey(w), key{wallet: AddressKey(w)}).
type addressFlow struct {
	info      *types.Info
	raw       map[types.Object]bool
	canonical map[types.Object]bool
	// lists are the variables ranged out of a list of address lists:
	// for _, list := range [][]string{envWallets, dbWallets}.
	lists map[types.Object]bool
}

// newAddressFlow walks fn's assignments: a variable assigned a canonicalizer
// result holds the canonical spelling, a variable copied from a raw address
// (directly, through TrimSpace, or ranged out of an address list) holds a raw one.
func newAddressFlow(info *types.Info, fn *ast.FuncDecl) *addressFlow {
	flow := &addressFlow{info: info, raw: map[types.Object]bool{}, canonical: map[types.Object]bool{}, lists: map[types.Object]bool{}}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				obj := info.ObjectOf(ident)
				if obj == nil {
					continue
				}
				// A fold into another variable is judged by the fold itself;
				// address = ToLower(address) still holds the address.
				if canonicalCall(node.Rhs[i]) || caseFold(info, node.Rhs[i]) && !mentionsObject(info, node.Rhs[i], obj) {
					flow.canonical[obj] = true
				}
			}
		case *ast.KeyValueExpr:
			if key, ok := node.Key.(*ast.Ident); ok && canonicalCall(node.Value) {
				if field, isField := info.ObjectOf(key).(*types.Var); isField && field.IsField() {
					flow.canonical[field] = true
				}
			}
		case *ast.RangeStmt:
			value, ok := node.Value.(*ast.Ident)
			if !ok {
				return true
			}
			obj := info.ObjectOf(value)
			if obj == nil {
				return true
			}
			if flow.addressList(node.X) {
				flow.raw[obj] = true
			}
			if lists, ok := ast.Unparen(node.X).(*ast.CompositeLit); ok && len(lists.Elts) > 0 {
				all := true
				for _, elt := range lists.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						elt = kv.Value
					}
					all = all && flow.addressList(elt)
				}
				flow.lists[obj] = all
			}
		}
		return true
	})
	// Copies of raw addresses: sender := strings.TrimSpace(*tx.FromAddress).
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			if obj := info.ObjectOf(ident); obj != nil && !flow.canonical[obj] && flow.isRaw(assign.Rhs[i]) {
				flow.raw[obj] = true
			}
		}
		return true
	})
	return flow
}

// canonicalCall reports a call of an address canonicalizer.
func canonicalCall(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return isAddressCanonicalizer(fun.Name)
	case *ast.SelectorExpr:
		return isAddressCanonicalizer(fun.Sel.Name)
	}
	return false
}

// caseFold reports strings.ToLower or ToUpper of a value: a spelling folded
// by hand, which address-folded-past-canonical-key judges, not a raw one.
func caseFold(info *types.Info, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	return ok && (isPkgFunc(info, call, "strings", "ToLower") || isPkgFunc(info, call, "strings", "ToUpper"))
}

// addressList reports a slice of strings named as addresses (wallets), or
// one ranged out of a list of them.
func (f *addressFlow) addressList(expr ast.Expr) bool {
	t := f.info.TypeOf(expr)
	if t == nil {
		return false
	}
	slice, ok := t.Underlying().(*types.Slice)
	if !ok || !isStringType(slice.Elem()) {
		return false
	}
	if ident, ok := ast.Unparen(expr).(*ast.Ident); ok && f.lists[f.info.ObjectOf(ident)] {
		return true
	}
	return isAddressName(exprName(expr))
}

// isRaw reports an expression holding an address as spelled outside: an
// address-named string variable or field that no canonicalizer produced,
// its dereference, or its TrimSpace. A field of a standard library type
// (mail.Address.Address) is not an account address.
func (f *addressFlow) isRaw(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if tv, ok := f.info.Types[expr]; !ok || tv.Value != nil || !isStringType(tv.Type) {
		return false
	}
	switch e := expr.(type) {
	case *ast.Ident:
		obj := f.info.ObjectOf(e)
		if obj == nil || f.canonical[obj] {
			return false
		}
		if _, isVar := obj.(*types.Var); !isVar {
			return false
		}
		return f.raw[obj] || isAddressName(e.Name)
	case *ast.SelectorExpr:
		field, isField := f.info.ObjectOf(e.Sel).(*types.Var)
		if !isField || f.canonical[field] || field.Pkg() == nil || stdlibPath(field.Pkg().Path()) {
			return false
		}
		return isAddressName(e.Sel.Name)
	case *ast.StarExpr:
		return isAddressName(exprName(e.X))
	case *ast.CallExpr:
		if isPkgFunc(f.info, e, "strings", "TrimSpace") && len(e.Args) == 1 {
			return f.isRaw(e.Args[0])
		}
	}
	return false
}

// isPkgFunc reports a call of the function name of package path.
func isPkgFunc(info *types.Info, call *ast.CallExpr, path, name string) bool {
	fn := staticFunc(info, call)
	return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == path && fn.Name() == name
}

// addressIndex is what the project declares about addresses: its
// canonicalizers, its exported canonical keys, and for each type the
// exported method that brings its address parameter to the canonical
// spelling.
type addressIndex struct {
	canonical []string
	keys      []string
	siblings  map[*types.TypeName][]string
}

// addressRule is a rule over the functions of a project whose check needs
// the project's address index.
type addressRule struct {
	*rules.BaseRule
	suggestion string
	check      func(scope funcScope, fn *ast.FuncDecl, index addressIndex) []funcFinding
}

// AnalyzeFile is a no-op: the check needs types.
func (r *addressRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough.
func (r *addressRule) RequiresSSA() bool { return false }

// AnalyzeGoProject runs the check with the project's address functions.
func (r *addressRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	decls, err := funcDeclsByObject(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	canonical, keys := addressFuncs(decls)
	if len(canonical) == 0 {
		return nil, nil
	}
	index := addressIndex{canonical: canonical, keys: keys, siblings: canonicalizingMethods(decls)}
	inner := &typedFuncRule{
		BaseRule:   r.BaseRule,
		suggestion: r.suggestion,
		check: func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			if isAddressCanonicalizer(fn.Name.Name) {
				return nil
			}
			return r.check(scope, fn, index)
		},
	}
	return inner.AnalyzeGoProject(ctx)
}

// NewAddressComparedAsSpelledRule creates address-compared-as-spelled: two
// addresses compared with == in a module that brings addresses to one
// spelling elsewhere:
//
//	if change.OwnerAddress != walletAddress { continue } // module has normalizeAddress
//
// The same account written two ways (a hex address in another case, the raw
// and the friendly form) does not match, and its records are dropped or
// booked as someone else's.
func NewAddressComparedAsSpelledRule() *addressRule {
	r := &addressRule{
		BaseRule: rules.NewBaseRule(
			"address-compared-as-spelled",
			"patterns",
			"Detects two addresses compared as spelled (==, !=) in a module that brings addresses to one canonical form elsewhere — one account written two ways does not match",
			core.SeverityMedium,
		),
		suggestion: "Compare the canonical forms (the project's address key or same-address helper)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl, index addressIndex) []funcFinding {
		flow := newAddressFlow(scope.info, fn)
		var findings []funcFinding
		loud := failingChecks(scope.info, fn.Body)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			bin, ok := n.(*ast.BinaryExpr)
			if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) || loud[bin] || elementsOfOneList(bin.X, bin.Y) {
				return true
			}
			if flow.isRaw(bin.X) && flow.isRaw(bin.Y) {
				findings = append(findings, funcFinding{node: bin, message: fmt.Sprintf(
					"Addresses compared as spelled while the module brings them to one form (%s) — the same account written another way does not match", strings.Join(index.canonical, ", "))})
			}
			return true
		})
		return findings
	}
	return r
}

// failingChecks returns the comparisons in the conditions of ifs that fail
// the call: a mismatch there is loud, nothing is dropped or misbooked.
func failingChecks(info *types.Info, body *ast.BlockStmt) map[*ast.BinaryExpr]bool {
	checks := map[*ast.BinaryExpr]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		check, ok := n.(*ast.IfStmt)
		if !ok || len(check.Body.List) != 1 {
			return true
		}
		ret, ok := check.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		last := ret.Results[len(ret.Results)-1]
		if t := info.TypeOf(last); isNilIdent(last) || t == nil || !implementsError(t) {
			return true
		}
		ast.Inspect(check.Cond, func(inner ast.Node) bool {
			if bin, ok := inner.(*ast.BinaryExpr); ok {
				checks[bin] = true
			}
			return true
		})
		return true
	})
	return checks
}

// elementsOfOneList reports the same field of two elements of one list,
// rows[i].Wallet != rows[j].Wallet: an ordering, not a match of two accounts.
func elementsOfOneList(left, right ast.Expr) bool {
	l, ok := ast.Unparen(left).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	r, ok := ast.Unparen(right).(*ast.SelectorExpr)
	if !ok || l.Sel.Name != r.Sel.Name {
		return false
	}
	li, ok := ast.Unparen(l.X).(*ast.IndexExpr)
	if !ok {
		return false
	}
	ri, ok := ast.Unparen(r.X).(*ast.IndexExpr)
	return ok && types.ExprString(li.X) == types.ExprString(ri.X)
}

// NewAddressFoldedPastCanonicalKeyRule creates address-folded-past-canonical-key:
// an address lower-cased by hand into a key, in a module that exports its
// canonical address key:
//
//	key := strings.ToLower(walletAddress) // module exports AddressKey
//
// The hand-made fold knows one form: it splits an account of a chain whose
// spellings differ otherwise, and it breaks a case-sensitive (base58) address.
// A fold that reads the address's form rather than keying it (a prefix test,
// a hex-only branch, a lower-case check) is left out.
func NewAddressFoldedPastCanonicalKeyRule() *addressRule {
	r := &addressRule{
		BaseRule: rules.NewBaseRule(
			"address-folded-past-canonical-key",
			"patterns",
			"Detects an address lower-cased by hand in a module that exports a canonical address key — the hand-made key splits the forms the canonical one joins and breaks case-sensitive addresses",
			core.SeverityLow,
		),
		suggestion: "Use the module's canonical address key instead of strings.ToLower",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl, index addressIndex) []funcFinding {
		if len(index.keys) == 0 {
			return nil
		}
		flow := newAddressFlow(scope.info, fn)
		notKeys := foldsNotKeys(scope.info, fn.Body)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 || notKeys[call] {
				return true
			}
			if !caseFold(scope.info, call) {
				return true
			}
			if flow.isRaw(call.Args[0]) {
				findings = append(findings, funcFinding{node: call, message: fmt.Sprintf(
					"Address lower-cased by hand while the module exports its canonical key (%s) — the hand-made key splits the forms the canonical one joins and breaks case-sensitive addresses", strings.Join(index.keys, ", "))})
			}
			return true
		})
		return findings
	}
	return r
}

// foldsNotKeys returns the folds of a body that read an address's form
// instead of keying it: one handed to a prefix or suffix test
// (HasPrefix(ToLower(a), "0x")), one stripped of the hex prefix
// (TrimPrefix(ToLower(a), "0x")), one under a test that the address is hex
// (if HasPrefix(a, "0x") { a = ToLower(a) }), and one compared with the
// address itself (a != ToLower(a): is it spelled in lower case).
func foldsNotKeys(info *types.Info, body *ast.BlockStmt) map[*ast.CallExpr]bool {
	folds := map[*ast.CallExpr]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if len(node.Args) == 0 {
				return true
			}
			inner, ok := ast.Unparen(node.Args[0]).(*ast.CallExpr)
			if !ok {
				return true
			}
			if isPkgFunc(info, node, "strings", "HasPrefix") || isPkgFunc(info, node, "strings", "HasSuffix") ||
				isPkgFunc(info, node, "strings", "TrimPrefix") && hexPrefixArg(info, node) {
				folds[inner] = true
			}
		case *ast.BinaryExpr:
			if node.Op != token.EQL && node.Op != token.NEQ {
				return true
			}
			for _, pair := range [][2]ast.Expr{{node.X, node.Y}, {node.Y, node.X}} {
				if fold, ok := ast.Unparen(pair[0]).(*ast.CallExpr); ok && len(fold.Args) == 1 && types.ExprString(fold.Args[0]) == types.ExprString(pair[1]) {
					folds[fold] = true
				}
			}
		case *ast.IfStmt:
			for _, address := range hexTestedValues(info, node.Cond) {
				ast.Inspect(node.Body, func(inner ast.Node) bool {
					if fold, ok := inner.(*ast.CallExpr); ok && len(fold.Args) == 1 && types.ExprString(fold.Args[0]) == address {
						folds[fold] = true
					}
					return true
				})
			}
		}
		return true
	})
	return folds
}

// hexPrefixArg reports a prefix call whose second argument is the hex prefix.
func hexPrefixArg(info *types.Info, call *ast.CallExpr) bool {
	if len(call.Args) != 2 {
		return false
	}
	prefix, ok := stringConstant(info, call.Args[1])
	return ok && strings.EqualFold(prefix, "0x")
}

// hexTestedValues returns the values a condition tests to be hex:
// strings.HasPrefix(a, "0x").
func hexTestedValues(info *types.Info, cond ast.Expr) []string {
	var values []string
	ast.Inspect(cond, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isPkgFunc(info, call, "strings", "HasPrefix") && hexPrefixArg(info, call) {
			values = append(values, types.ExprString(call.Args[0]))
		}
		return true
	})
	return values
}

// NewAddressEntrySkipsCanonicalSpellingRule creates
// address-entry-skips-canonical-spelling: an exported method that writes
// with the addresses its caller passed, while a sibling method of the same
// type brings its address to the canonical spelling first:
//
//	func (s *Service) SyncWallet(ctx, wallet string) { wallet = s.canonicalWalletSpelling(ctx, wallet); ... }
//	func (s *Service) BackfillGas(ctx, wallets []string) { for _, w := range wallets { s.repo.CreateBatch(...w...) } }
//
// A request spelling the address another way writes a second set of rows
// for the same account instead of updating its own.
func NewAddressEntrySkipsCanonicalSpellingRule() *addressRule {
	r := &addressRule{
		BaseRule: rules.NewBaseRule(
			"address-entry-skips-canonical-spelling",
			"patterns",
			"Detects an exported method that writes with the addresses its caller passed while a sibling method of the same type brings its address to the canonical spelling first — another spelling writes a second set of rows",
			core.SeverityMedium,
		),
		suggestion: "Bring the address to the canonical spelling at the start, as the sibling method does",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl, index addressIndex) []funcFinding {
		recv := methodReceiver(scope.info, fn)
		if recv == nil || !fn.Name.IsExported() || callsCanonicalizer(fn.Body) || !callsWrite(fn.Body) {
			return nil
		}
		siblings := index.siblings[recv.Obj()]
		if len(siblings) == 0 || slices.Contains(siblings, fn.Name.Name) {
			return nil
		}
		sibling := siblings[0]
		var findings []funcFinding
		for _, param := range addressParams(scope.info, fn) {
			use := firstAddressUse(scope.info, fn.Body, param)
			if use == nil {
				continue
			}
			findings = append(findings, funcFinding{node: use, message: fmt.Sprintf(
				"%s writes with %s as the caller spelled it, while %s brings its address to the canonical spelling first — another spelling of the same account writes a second set of rows", fn.Name.Name, param.Name(), sibling)})
		}
		return findings
	}
	return r
}

// methodReceiver returns the named type a declared method belongs to.
func methodReceiver(info *types.Info, fn *ast.FuncDecl) *types.Named {
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return nil
	}
	return receiverNamed(obj)
}

// callsCanonicalizer reports a body calling an address canonicalizer.
func callsCanonicalizer(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && canonicalCall(call) {
			found = true
		}
		return !found
	})
	return found
}

// callsWrite reports a body calling a method whose name leads with a write verb.
func callsWrite(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isWriteCall(call) {
			found = true
		}
		return !found
	})
	return found
}

// canonicalizingMethods returns, by receiver type, the exported methods
// that hand one of their own address parameters to a canonicalizer.
func canonicalizingMethods(decls map[*types.Func]typedFuncDecl) map[*types.TypeName][]string {
	methods := map[*types.TypeName][]string{}
	for obj, decl := range decls {
		if !obj.Exported() || obj.Signature().Recv() == nil {
			continue
		}
		recv := receiverNamed(obj)
		if recv == nil {
			continue
		}
		params := addressParams(decl.info, decl.decl)
		canonicalizes := false
		ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !canonicalCall(call) {
				return true
			}
			for _, arg := range call.Args {
				if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && slices.Contains(params, decl.info.ObjectOf(ident)) {
					canonicalizes = true
				}
			}
			return !canonicalizes
		})
		if canonicalizes {
			key := recv.Obj()
			methods[key] = append(methods[key], obj.Name())
		}
	}
	for key := range methods {
		sort.Strings(methods[key])
	}
	return methods
}

// addressParams returns the parameters of fn that hold addresses: an
// address-named string or slice of strings.
func addressParams(info *types.Info, fn *ast.FuncDecl) []types.Object {
	var params []types.Object
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			obj := info.Defs[name]
			if obj == nil || !isAddressName(name.Name) {
				continue
			}
			t := obj.Type()
			if slice, ok := t.Underlying().(*types.Slice); ok {
				t = slice.Elem()
			}
			if isStringType(t) {
				params = append(params, obj)
			}
		}
	}
	return params
}

// firstAddressUse returns where a body first takes the address parameter
// apart from a length or emptiness check: the range over it, or the first
// call it is handed to.
func firstAddressUse(info *types.Info, body *ast.BlockStmt, param types.Object) ast.Node {
	var use ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if use != nil {
			return false
		}
		switch node := n.(type) {
		case *ast.RangeStmt:
			if ident, ok := ast.Unparen(node.X).(*ast.Ident); ok && info.ObjectOf(ident) == param {
				use = node
			}
		case *ast.CallExpr:
			if isIdentNamed(node.Fun, "len") {
				return false
			}
			for _, arg := range node.Args {
				if mentionsObject(info, arg, param) {
					use = node
				}
			}
		}
		return use == nil
	})
	return use
}
