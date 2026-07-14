package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/require"
)

func TestOrphanedInterfaceSkipsRuleCapabilityInterface(t *testing.T) {
	ctx, err := core.NewFileContextChecked(
		"rule.go",
		".",
		[]byte("package rules\n\ntype ProjectRule interface { AnalyzeProject() error }\n"),
		core.DefaultConfig(),
	)
	require.NoError(t, err)
	fset, file, err := core.NewParser().ParseGoFile(ctx.Path, ctx.Content)
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)

	require.Empty(t, NewOrphanedInterfaceRule().AnalyzeFile(ctx))
}
