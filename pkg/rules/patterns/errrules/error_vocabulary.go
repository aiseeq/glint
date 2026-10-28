package errrules

import (
	"go/ast"
	"slices"

	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// Shared vocabulary of the error-handling rules: how an error variable is
// spelled, which function names are predicates, where one camelCase word ends.
// File rules without type information decide by these spellings; every rule
// that asks the same question asks it here, so the rules cannot disagree.

// returnCarriesError reports whether any value of the return hands an error on.
func returnCarriesError(ret *ast.ReturnStmt) bool {
	return slices.ContainsFunc(ret.Results, patternkit.ExprCarriesError)
}

// predicatePrefixes are the leading words of a function whose bool result is
// its whole answer: IsEmpty, HasRole, CanWrite, ShouldRetry.
var predicatePrefixes = []string{
	"Is", "Has", "Can", "Should", "Must", "Will", "Was", "Does", "Did",
	"Contains", "Matches", "Exists", "Supports", "Equal", "Equals", "Valid",
}

// isPredicateName reports whether the function name starts with a predicate
// word followed by a word boundary: IsEmpty and isEmpty are predicates,
// HashPassword, CancelOrder, Issue and Validate are not.
func isPredicateName(name string) bool {
	for _, prefix := range predicatePrefixes {
		if helpers.HasLeadingWord(name, prefix) {
			return true
		}
	}
	return false
}

// nodeReadsIdent reports whether the node reads the named variable: an
// identifier with that name occurs anywhere except as a direct target of an
// assignment (`err = nil` overwrites the error, it does not look at it).
func nodeReadsIdent(node ast.Node, name string) bool {
	targets := make(map[*ast.Ident]bool)
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		switch current := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range current.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					targets[ident] = true
				}
			}
		case *ast.Ident:
			found = current.Name == name && !targets[current]
		}
		return !found
	})
	return found
}
