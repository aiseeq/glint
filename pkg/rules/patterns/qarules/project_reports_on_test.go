package qarules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestProjectQARulesReportOnFrontendTests(t *testing.T) {
	contexts := []*core.FileContext{
		core.NewFileContext("src/example.test.ts", ".", nil, nil),
		core.NewFileContext("src/example.test.tsx", ".", nil, nil),
		core.NewFileContext("src/example.test.js", ".", nil, nil),
		core.NewFileContext("src/example.test.jsx", ".", nil, nil),
	}
	for _, rule := range []interface{ ReportsOn(*core.FileContext) bool }{NewSkippedTestRule(), NewUnfalsifiableTestCaseRule()} {
		for _, ctx := range contexts {
			if !rule.ReportsOn(ctx) {
				t.Errorf("%T.ReportsOn(%q)=false, want true", rule, ctx.RelPath)
			}
		}
	}
}
