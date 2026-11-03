package shellrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestHandRolledDotenvParserReportsOnGoFiles(t *testing.T) {
	if !NewHandRolledDotenvParserRule().ReportsOn(core.NewFileContext("config.go", ".", nil, nil)) {
		t.Fatal("ReportsOn(config.go)=false, want true")
	}
}
