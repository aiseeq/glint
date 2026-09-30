package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDeterministicUUIDRule())
}

// DeterministicUUIDRule detects IDs computed from names or hashes instead of
// issued by the database: name-based UUIDs (google/uuid NewSHA1/NewMD5/NewHash,
// gofrs and satori NewV3/NewV5) and a UUID assembled with FromBytes from a
// crypto hash. Principle: "ID always comes from DB, never computed" — a
// computed ID collides for equal input and exists before the record does.
//
// Only the calls of the UUID libraries are recognized; a string that merely
// looks like an ID (a cache key, an ETag) is not one, and neither is a
// name-based UUID folded into a longer string such as an idempotency key.
type DeterministicUUIDRule struct {
	*rules.BaseRule
}

// NewDeterministicUUIDRule creates the rule
func NewDeterministicUUIDRule() *DeterministicUUIDRule {
	return &DeterministicUUIDRule{
		BaseRule: rules.NewBaseRule(
			"deterministic-uuid",
			"patterns",
			"Detects UUIDs computed from names or hashes (uuid.NewSHA1/NewMD5/NewHash, NewV3/NewV5, FromBytes of a hash) instead of real DB UUIDs",
			core.SeverityHigh,
		),
	}
}

// nameBasedUUIDFuncs lists, per UUID library, the constructors that derive
// the UUID from a name.
var nameBasedUUIDFuncs = map[string][]string{
	"github.com/google/uuid":    {"NewSHA1", "NewMD5", "NewHash"},
	"github.com/gofrs/uuid":     {"NewV3", "NewV5"},
	"github.com/gofrs/uuid/v5":  {"NewV3", "NewV5"},
	"github.com/satori/go.uuid": {"NewV3", "NewV5"},
}

// AnalyzeFile checks one file without type information: the UUID and hash
// packages are known through the file's imports.
func (r *DeterministicUUIDRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DeterministicUUIDRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file, with type information where the package
// has it.
func (r *DeterministicUUIDRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze reports the computed UUIDs of one file.
func (r *DeterministicUUIDRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		hashes := hashVariables(ctx.GoAST, info, fn.Body)
		keyParts := uuidsFoldedIntoText(ctx.GoAST, info, fn.Body)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || keyParts[call] {
				return true
			}
			if message, found := r.computedUUID(ctx.GoAST, info, call, hashes); found {
				line := ctx.LineFor(call)
				v := r.CreateViolation(ctx.RelPath, line, message)
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("IDs must come from the database (or uuid.New for a new record), never be computed from a name or a hash")
				v.WithContext("pattern", "deterministic_uuid")
				violations = append(violations, v)
			}
			return true
		})
	}
	return violations
}

// computedUUID reports whether the call derives a UUID from a name or a hash.
func (r *DeterministicUUIDRule) computedUUID(file *ast.File, info *types.Info, call *ast.CallExpr, hashes map[string]bool) (string, bool) {
	for pkgPath, constructors := range nameBasedUUIDFuncs {
		if isPackageFuncCall(file, info, call, pkgPath, constructors...) {
			return "Name-based UUID computed from input — use real UUID from DB", true
		}
		if isPackageFuncCall(file, info, call, pkgPath, "FromBytes") && len(call.Args) == 1 &&
			isHashDerived(file, info, call.Args[0], hashes) {
			return "UUID assembled from hash bytes — use real UUID from DB", true
		}
	}
	return "", false
}

// uuidsFoldedIntoText returns the calls whose UUID only becomes part of a
// longer string: concatenated with other text or formatted by fmt.Sprintf.
// Such a string is a key or a fingerprint - an idempotency key has to come
// out the same for the same input - and never a record ID, which is the UUID
// alone.
func uuidsFoldedIntoText(file *ast.File, info *types.Info, body *ast.BlockStmt) map[*ast.CallExpr]bool {
	folded := map[*ast.CallExpr]bool{}
	mark := func(expr ast.Expr) {
		expr = ast.Unparen(expr)
		if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) == 0 {
			if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && selector.Sel.Name == "String" {
				expr = ast.Unparen(selector.X)
			}
		}
		if call, ok := expr.(*ast.CallExpr); ok {
			folded[call] = true
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op == token.ADD {
				mark(node.X)
				mark(node.Y)
			}
		case *ast.CallExpr:
			if isPackageFuncCall(file, info, node, "fmt", "Sprintf") && len(node.Args) > 1 {
				for _, arg := range node.Args[1:] {
					mark(arg)
				}
			}
		}
		return true
	})
	return folded
}

// hashPackages are the packages whose functions return a digest.
var hashPackages = []string{"crypto/md5", "crypto/sha1", "crypto/sha256", "crypto/sha512"}

// isHashCall reports whether the call computes a digest: sha256.Sum256(b),
// md5.Sum(b), or h.Sum(nil) on a hash.Hash.
func isHashCall(file *ast.File, info *types.Info, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	for _, pkgPath := range hashPackages {
		if _, ok := packageFuncName(file, info, call, pkgPath); ok {
			return true
		}
	}
	if info == nil {
		return false
	}
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	return ok && fn.Name() == "Sum" && fn.Pkg() != nil && fn.Pkg().Path() == "hash"
}

// hashVariables returns the names the body assigns a digest to.
func hashVariables(file *ast.File, info *types.Info, body *ast.BlockStmt) map[string]bool {
	names := map[string]bool{}
	record := func(target, value ast.Expr) {
		if ident, ok := target.(*ast.Ident); ok && ident.Name != "_" && isHashCall(file, info, value) {
			names[ident.Name] = true
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Rhs) == 1 && len(node.Lhs) >= 1 {
				record(node.Lhs[0], node.Rhs[0])
			}
		case *ast.ValueSpec:
			if len(node.Values) == 1 && len(node.Names) >= 1 {
				record(node.Names[0], node.Values[0])
			}
		}
		return true
	})
	return names
}

// isHashDerived reports whether the bytes handed to FromBytes are a digest:
// the hash call itself or a variable holding one, sliced or not.
func isHashDerived(file *ast.File, info *types.Info, arg ast.Expr, hashes map[string]bool) bool {
	expr := ast.Unparen(arg)
	if slice, ok := expr.(*ast.SliceExpr); ok {
		expr = ast.Unparen(slice.X)
	}
	if isHashCall(file, info, expr) {
		return true
	}
	ident, ok := expr.(*ast.Ident)
	return ok && hashes[ident.Name]
}
