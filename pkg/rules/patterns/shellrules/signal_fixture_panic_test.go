package shellrules

import "testing"

func TestSingleKillFixtureMalformedFunction(t *testing.T) {
	if singleKillFixture("(){}") {
		t.Fatal("malformed function is not a kill fixture")
	}
}
