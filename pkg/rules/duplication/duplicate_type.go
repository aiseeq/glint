package duplication

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewDuplicateTypeAcrossPackagesRule())
}

// DuplicateTypeAcrossPackagesRule detects one type kept as two live copies:
// a struct of the same name declared in two packages of the module, both with
// a method of the same name and signature:
//
//	// cmd/app/main.go
//	type DepositHandler struct{ ... }
//	func (h *DepositHandler) ProcessDeposit(ctx context.Context, d *models.Deposit) (bool, error)
//
//	// routing/router.go
//	type DepositHandler struct{ ... }
//	func (h *DepositHandler) ProcessDeposit(ctx context.Context, d *models.Deposit) (bool, error)
//
// Every fix has to land twice and one copy misses it - an insert gains a
// column in one and goes on writing rows without it in the other.
// cross-file-duplicate compares text and stops seeing the pair once the copies
// diverge; the name and the method set still give it away. A method every
// type may have (String, Error, Close, ServeHTTP, Marshal…) and methods
// without parameters do not count; mock and fake packages are left out. A
// one-word name (Client, Service) is a role its package qualifies -
// alpha.Client and beta.Client behind one interface are two providers, not
// two copies.
type DuplicateTypeAcrossPackagesRule struct {
	*rules.BaseRule
}

// NewDuplicateTypeAcrossPackagesRule creates the rule
func NewDuplicateTypeAcrossPackagesRule() *DuplicateTypeAcrossPackagesRule {
	return &DuplicateTypeAcrossPackagesRule{BaseRule: rules.NewBaseRule(
		"duplicate-type-across-packages",
		"duplication",
		"Detects a struct declared in two packages under one name with a method of the same name and signature — two live copies of one implementation that drift apart",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the copies live in different packages.
func (r *DuplicateTypeAcrossPackagesRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DuplicateTypeAcrossPackagesRule) RequiresSSA() bool { return false }

// conventionalMethods are methods any type may carry: sharing one says
// nothing about the types being copies.
var conventionalMethods = map[string]bool{
	"String": true, "Error": true, "Close": true, "ServeHTTP": true, "Start": true, "Stop": true,
	"Run": true, "Name": true, "Validate": true, "Reset": true, "Len": true, "Less": true, "Swap": true,
	"MarshalJSON": true, "UnmarshalJSON": true, "MarshalText": true, "UnmarshalText": true,
	"Scan": true, "Value": true, "Shutdown": true, "Init": true, "Handle": true, "Write": true, "Read": true,
}

// AnalyzeGoProject reports each copy of a type duplicated across packages.
func (r *DuplicateTypeAcrossPackagesRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("duplicate type across packages: nil Go project context")
	}
	// A method key is the type name, the method name and its signature: the
	// copies of one type share a key across packages.
	byKey := make(map[string][]*types.Named)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.Types == nil {
			return nil, errors.New("duplicate type across packages: package has no types")
		}
		if testDoublePackage(pkg.Package.PkgPath) {
			continue
		}
		for _, named := range structsWithMethods(pkg.Package.Types.Scope()) {
			for _, key := range methodKeys(named) {
				byKey[key] = append(byKey[key], named)
			}
		}
	}
	twins := make(map[*types.TypeName]string)
	for _, key := range sortedKeys(byKey) {
		copies := byKey[key]
		method := key[strings.Index(key, ".")+1 : strings.Index(key, "|")]
		// The first copy is the twin of every copy from another package, and
		// the first copy from another package is the twin of the first one.
		first := copies[0].Obj().Pkg()
		var other *types.Package
		for _, c := range copies {
			if pkg := c.Obj().Pkg(); pkg != first {
				other = pkg
				break
			}
		}
		if other == nil {
			continue
		}
		for _, c := range copies {
			twin := first
			if c.Obj().Pkg() == first {
				twin = other
			}
			if twins[c.Obj()] == "" {
				twins[c.Obj()] = twin.Path() + " (" + method + ")"
			}
		}
	}
	if len(twins) == 0 {
		return nil, nil
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			obj, ok := info.Defs[spec.Name].(*types.TypeName)
			if !ok || twins[obj] == "" {
				return true
			}
			line := file.LineFor(spec)
			if file.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
				"Type %s has a twin in %s with the same method — two live copies of one implementation: a fix lands in one and the other drifts",
				spec.Name.Name, twins[obj]))
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Keep one implementation and use it from both places")
			violations = append(violations, v)
			return true
		})
		return violations
	})
}

// structsWithMethods returns the named structs of a scope that have methods
// and a name of more than one word.
func structsWithMethods(scope *types.Scope) []*types.Named {
	var out []*types.Named
	for _, name := range scope.Names() {
		typeName, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || typeName.IsAlias() {
			continue
		}
		named, ok := typeName.Type().(*types.Named)
		if !ok || named.NumMethods() == 0 || len(helpers.IdentifierWords(name)) < 2 {
			continue
		}
		if _, isStruct := named.Underlying().(*types.Struct); isStruct {
			out = append(out, named)
		}
	}
	return out
}

// methodKeys returns Type.Method|signature for the type's non-conventional
// methods with parameters. Types print with full package paths, so the same
// parameter imported under two names gives one key.
func methodKeys(named *types.Named) []string {
	var keys []string
	for i := range named.NumMethods() {
		method := named.Method(i)
		if conventionalMethods[method.Name()] {
			continue
		}
		sig, ok := method.Type().(*types.Signature)
		if !ok || sig.Params().Len() == 0 {
			continue
		}
		bare := types.NewSignatureType(nil, nil, nil, sig.Params(), sig.Results(), sig.Variadic())
		keys = append(keys, named.Obj().Name()+"."+method.Name()+"|"+types.TypeString(bare, nil))
	}
	return keys
}

func sortedKeys(m map[string][]*types.Named) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// testDoublePackage reports a package of test doubles.
func testDoublePackage(path string) bool {
	for _, part := range strings.Split(path, "/") {
		lower := strings.ToLower(part)
		if strings.Contains(lower, "mock") || strings.Contains(lower, "fake") || strings.Contains(lower, "stub") {
			return true
		}
	}
	return false
}
