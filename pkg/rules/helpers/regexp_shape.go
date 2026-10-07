package helpers

import "regexp"

// regexpShape is regular-expression syntax a literal value has no use for:
// a bracket class with a range ([A-Za-z0-9_]) or a POSIX class ([[:space:]]),
// a counted repetition ({20,}, {8,64}), a class escape (\d, \w, \S) or a
// repeated wildcard (.*, .+).
var regexpShape = regexp.MustCompile(`\[\^?[^\]]*[A-Za-z0-9]-[A-Za-z0-9][^\]]*\]|\[\^?\[:[a-z]+:\]|\{\d+(?:,\d*)?\}|\\[dwsDWS]|\.[*+]`)

// LooksLikeRegexpShape reports a value written as a regular expression — the
// shape of a secret a scanner searches for, not a secret.
func LooksLikeRegexpShape(value string) bool {
	return regexpShape.MatchString(value)
}
