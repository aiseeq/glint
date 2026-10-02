package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewTokenAmountFixedDecimalsRule())
	rules.Register(NewTokenKeyedBySymbolRule())
}

// isTokenIdentityName reports a field naming which token a record is about:
// CoinType, Mint, Contract, Denom, TokenAddress. Unlike a symbol, it tells
// two tokens apart.
func isTokenIdentityName(name string) bool {
	words := map[string]bool{}
	for _, word := range helpers.IdentifierWords(name) {
		words[word] = true
	}
	return words["mint"] || words["denom"] || words["contract"] ||
		words["coin"] && words["type"] ||
		(words["token"] || words["asset"]) && words["address"]
}

// readsIdentityOf returns a selector of the body reading a token identity
// field of the value held by obj: b.CoinType, tx.TokenAddress.
func readsIdentityOf(info *types.Info, body ast.Node, obj types.Object) *ast.SelectorExpr {
	var found *ast.SelectorExpr
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || found != nil {
			return found == nil
		}
		field, isField := info.ObjectOf(sel.Sel).(*types.Var)
		if !isField || !field.IsField() || !isTokenIdentityName(sel.Sel.Name) {
			return true
		}
		if root := rootIdent(sel.X); root != nil && info.ObjectOf(root) == obj {
			found = sel
		}
		return found == nil
	})
	return found
}

// NewTokenAmountFixedDecimalsRule creates token-amount-fixed-decimals: a loop
// over records of different tokens that scales every raw amount by one
// power of ten:
//
//	for _, b := range balances {          // b.CoinType tells the tokens apart
//		amount = amount.Div(decimal.NewFromInt(1e9)) // every token has 9 decimals
//	}
//
// Tokens carry their own decimals (6 for a stablecoin, 18 for most ERC-20s):
// a token whose decimals differ from the native coin's is booked a thousand
// times too large or too small. A loop that reads a decimals value somewhere
// scales per token and is left out, as is a scale inside a branch of the loop
// (the branch picks the token it knows).
func NewTokenAmountFixedDecimalsRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"token-amount-fixed-decimals",
			"patterns",
			"Detects a loop over records of different tokens that scales every raw amount by one fixed power of ten — a token with other decimals is booked orders of magnitude off",
			core.SeverityMedium,
		),
		suggestion: "Scale each amount by its own token's decimals (from the token's metadata), not by the native coin's",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		divisors := powerOfTenDecimals(scope.info, fn.Body)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			loop, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			item, ok := loop.Value.(*ast.Ident)
			if !ok {
				return true
			}
			obj := scope.info.ObjectOf(item)
			identity := readsIdentityOf(scope.info, loop.Body, obj)
			if obj == nil || identity == nil || readsDecimals(scope.info, loop.Body) {
				return true
			}
			for _, stmt := range loop.Body.List {
				switch stmt.(type) {
				case *ast.AssignStmt, *ast.ExprStmt, *ast.DeclStmt:
				default:
					continue
				}
				ast.Inspect(stmt, func(inner ast.Node) bool {
					if _, isLit := inner.(*ast.FuncLit); isLit {
						return false
					}
					if call := fixedScale(scope.info, inner, divisors); call != nil {
						findings = append(findings, funcFinding{node: call, message: "Every token of the loop (told apart by " + identity.Sel.Name + ") is scaled by one fixed power of ten — a token with other decimals is booked orders of magnitude off"})
					}
					return true
				})
			}
			return true
		})
		return findings
	}
	return r
}

// fixedScale returns a decimal division of an amount by a fixed power of ten:
// amount.Div(decimal.NewFromInt(1e9)), amount.Div(divisor).
func fixedScale(info *types.Info, node ast.Node, divisors map[types.Object]bool) *ast.CallExpr {
	call, ok := node.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Div" && sel.Sel.Name != "DivRound") || !isShopspringDecimalType(info.TypeOf(sel.X)) {
		return nil
	}
	if ident, ok := ast.Unparen(call.Args[0]).(*ast.Ident); ok && divisors[info.ObjectOf(ident)] {
		return call
	}
	if powerOfTenDecimal(info, call.Args[0]) {
		return call
	}
	return nil
}

// powerOfTenDecimals returns the variables of a body assigned a decimal
// power of ten of at least 100: divisor := decimal.NewFromInt(1e9).
func powerOfTenDecimals(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	divisors := map[types.Object]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && powerOfTenDecimal(info, assign.Rhs[i]) {
				if obj := info.ObjectOf(ident); obj != nil {
					divisors[obj] = true
				}
			}
		}
		return true
	})
	return divisors
}

// powerOfTenDecimal reports a decimal made of a constant power of ten of at
// least 100: decimal.NewFromInt(1e9), decimal.NewFromFloat(1e6),
// decimal.New(1, 18).
func powerOfTenDecimal(info *types.Info, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	fn := staticFunc(info, call)
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != shopspringDecimalPath {
		return false
	}
	switch fn.Name() {
	case "NewFromInt", "NewFromInt32", "NewFromFloat", "NewFromFloat32":
		if len(call.Args) != 1 {
			return false
		}
		value := info.Types[call.Args[0]].Value
		return value != nil && isPowerOfTen(value) && constant.Compare(value, token.GEQ, constant.MakeInt64(100))
	case "New":
		if len(call.Args) != 2 {
			return false
		}
		coefficient, exponent := info.Types[call.Args[0]].Value, info.Types[call.Args[1]].Value
		return coefficient != nil && exponent != nil && constant.Compare(coefficient, token.EQL, constant.MakeInt64(1)) &&
			constant.Compare(exponent, token.GEQ, constant.MakeInt64(2))
	}
	return false
}

// readsDecimals reports a body reading a variable or field of decimals (not a
// constant, not one it only writes): metadata.Decimals, decimals.
func readsDecimals(info *types.Info, body *ast.BlockStmt) bool {
	written := map[*ast.Ident]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				switch target := lhs.(type) {
				case *ast.Ident:
					written[target] = true
				case *ast.SelectorExpr:
					written[target.Sel] = true
				}
			}
		}
		return true
	})
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok || found || written[ident] {
			return !found
		}
		if _, isVar := info.ObjectOf(ident).(*types.Var); !isVar {
			return true
		}
		for _, word := range helpers.IdentifierWords(ident.Name) {
			if word == "decimals" {
				found = true
			}
		}
		return !found
	})
	return found
}

// NewTokenKeyedBySymbolRule creates token-keyed-by-symbol: a key built from
// a token's symbol, out of a record that carries the token's address the
// function never reads:
//
//	symbol := transferSymbol(tx)                       // tx.TokenAddress is never read
//	key := ledgerKey{wallet: tx.Wallet, token: symbol}
//
// Symbols are not unique: two tokens named USDC (the real one and a copy, or
// two bridged versions) add up in one entry, and an entry keyed by symbol
// does not match one keyed by address elsewhere.
func NewTokenKeyedBySymbolRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"token-keyed-by-symbol",
			"patterns",
			"Detects a key built from a token's symbol out of a record that carries the token's address, which the function never reads — two tokens with one symbol share an entry",
			core.SeverityMedium,
		),
		suggestion: "Key the token by its address (mint, contract, coin type); keep the symbol for display",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isKeyType(scope.info.TypeOf(lit)) {
				return true
			}
			for _, elt := range lit.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					elt = kv.Value
				}
				if owner, field := symbolOwner(scope.info, fn.Body, elt); owner != nil {
					findings = append(findings, funcFinding{node: lit, message: "The key names the token by its symbol while " + owner.Name() + " carries its " + field + ", which the function never reads — two tokens with one symbol share an entry"})
					break
				}
			}
			return true
		})
		return findings
	}
	return r
}

// isKeyType reports a named struct whose name ends in Key: ledgerTokenKey.
func isKeyType(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return false
	}
	if _, isStruct := named.Underlying().(*types.Struct); !isStruct {
		return false
	}
	words := helpers.IdentifierWords(named.Obj().Name())
	return len(words) > 0 && words[len(words)-1] == "key"
}

// symbolOwner returns the record a symbol in expr comes from, when that
// record carries a token identity field the function never reads, with the
// field's name. The symbol is a field of the record (tx.TokenSymbol) or a
// variable assigned from an expression that reads the record.
func symbolOwner(info *types.Info, body *ast.BlockStmt, expr ast.Expr) (types.Object, string) {
	var owners []types.Object
	ast.Inspect(expr, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			// The callee's name is not a value: walk the arguments only.
			for _, arg := range node.Args {
				ast.Inspect(arg, func(inner ast.Node) bool {
					owners = append(owners, symbolSources(info, body, inner)...)
					return true
				})
			}
			return false
		default:
			owners = append(owners, symbolSources(info, body, n)...)
		}
		return true
	})
	for _, owner := range owners {
		field := identityField(owner.Type())
		if field != "" && readsIdentityOf(info, body, owner) == nil {
			return owner, field
		}
	}
	return nil, ""
}

// symbolSources returns the records a symbol node reads: the root of
// tx.TokenSymbol, or the variables read where a symbol variable is assigned.
func symbolSources(info *types.Info, body *ast.BlockStmt, node ast.Node) []types.Object {
	switch e := node.(type) {
	case *ast.SelectorExpr:
		if !hasCamelWord(e.Sel.Name, "symbol") {
			return nil
		}
		if root := rootIdent(e.X); root != nil {
			if obj, ok := info.ObjectOf(root).(*types.Var); ok {
				return []types.Object{obj}
			}
		}
	case *ast.Ident:
		obj, ok := info.ObjectOf(e).(*types.Var)
		if !ok || obj.IsField() || !hasCamelWord(e.Name, "symbol") {
			return nil
		}
		var sources []types.Object
		ast.Inspect(body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != len(assign.Rhs) {
				return true
			}
			for i, lhs := range assign.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && info.ObjectOf(ident) == obj {
					ast.Inspect(assign.Rhs[i], func(inner ast.Node) bool {
						if id, ok := inner.(*ast.Ident); ok {
							if v, isVar := info.ObjectOf(id).(*types.Var); isVar && !v.IsField() && v != obj {
								sources = append(sources, v)
							}
						}
						return true
					})
				}
			}
			return true
		})
		return sources
	}
	return nil
}

// identityField returns the token identity field of a struct (or a pointer
// to one), or "".
func identityField(t types.Type) string {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return ""
	}
	for i := range st.NumFields() {
		if field := st.Field(i); isTokenIdentityName(field.Name()) {
			return field.Name()
		}
	}
	return ""
}
