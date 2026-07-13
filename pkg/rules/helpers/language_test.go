package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestAnalyzeGoAndFrontendDispatchesByLanguage(t *testing.T) {
	goCalls := 0
	frontendCalls := 0
	analyzeGo := func(*core.FileContext) []*core.Violation {
		goCalls++
		return nil
	}
	analyzeFrontend := func(*core.FileContext) []*core.Violation {
		frontendCalls++
		return nil
	}

	for _, path := range []string{"service.go", "component.ts", "component.tsx", "script.js", "script.jsx", "README.md"} {
		ctx := core.NewFileContext(path, ".", nil, nil)
		AnalyzeGoAndFrontend(ctx, analyzeGo, analyzeFrontend)
	}

	require.Equal(t, 1, goCalls)
	require.Equal(t, 4, frontendCalls)
}
