package helpers

import "strings"

// IsTestSupportPackage reports a package that exists for tests: Go does not
// share _test.go files between packages, so helpers the tests of several
// packages use live in a package of their own — testutil, testdb,
// testhelpers, testing, or the stdlib convention of a …test suffix (httptest,
// fstest). Its exported doubles serve tests, not production.
func IsTestSupportPackage(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "test") {
		return true
	}
	for _, suffix := range []string{"test", "testing", "testutil", "testutils", "testhelper", "testhelpers"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
