package patterntest

import (
	"github.com/aiseeq/glint/pkg/core"
)

type FileRule interface {
	AnalyzeFile(ctx *core.FileContext) []*core.Violation
}
