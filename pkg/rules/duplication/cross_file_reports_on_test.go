package duplication

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestCrossFileDuplicateReportsOnEverySupportedSource(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	for _, tc := range []struct {
		path string
		data []byte
	}{{"src/view.tsx", nil}, {"src/view.ts", nil}, {"src/view.js", nil}, {"src/view.jsx", nil}, {"scripts/check.sh", []byte("#!/bin/sh\n")}} {
		if !rule.ReportsOn(core.NewFileContext(tc.path, ".", tc.data, nil)) {
			t.Errorf("ReportsOn(%q)=false, want true", tc.path)
		}
	}
}
