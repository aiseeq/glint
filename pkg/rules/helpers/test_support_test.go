package helpers

import "testing"

func TestIsTestSupportPackage(t *testing.T) {
	for name, want := range map[string]bool{
		"testutil": true, "testdb": true, "testhelpers": true, "testing": true,
		"httptest": true, "dbtestutil": true, "apitesting": true,
		"payments": false, "attestation": false, "mocks": false,
	} {
		if got := IsTestSupportPackage(name); got != want {
			t.Errorf("IsTestSupportPackage(%q) = %v, want %v", name, got, want)
		}
	}
}
