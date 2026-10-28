package patternkit

import (
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// highRiskParamWords are the words of a parameter name that mark a
// dependency a constructor cannot work without.
var highRiskParamWords = map[string]bool{
	"logger": true, "log": true,
	"service": true, "svc": true,
	"repo": true, "repository": true,
	"storage": true, "store": true,
	"handler": true, "controller": true,
	"client": true, "conn": true,
	"db": true, "database": true,
	"cache":     true,
	"metrics":   true,
	"validator": true,
	"manager":   true,
	"getter":    true,
	"provider":  true,
	"adapter":   true,
	"deps":      true, "dependencies": true,
}

// IsDependencyName reports a name one of whose words marks a dependency.
func IsDependencyName(paramHint string) bool {
	for _, word := range helpers.IdentifierWords(paramHint) {
		// A plural names several of the same dependency: loggers, repos.
		if highRiskParamWords[word] || highRiskParamWords[strings.TrimSuffix(word, "s")] {
			return true
		}
	}
	return false
}
