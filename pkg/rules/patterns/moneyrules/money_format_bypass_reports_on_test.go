package moneyrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestMoneyFormatBypassesFormatterReportsOnFrontendFiles(t *testing.T) {
	rule := NewMoneyFormatBypassesFormatterRule()
	for _, path := range []string{"src/view.ts", "src/view.tsx", "src/view.js", "src/view.jsx"} {
		if !rule.ReportsOn(core.NewFileContext(path, ".", nil, nil)) {
			t.Errorf("ReportsOn(%q)=false, want true", path)
		}
	}
}
