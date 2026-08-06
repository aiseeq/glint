package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// Репро с ipop (playwright_backup.go): внутри err-ветки команда перезапускается
// другим скриптом, err переприсваивается результатом вызова и проверяется ниже.
// Ошибка не игнорируется — это retry, а не fallback-присваивание; сопутствующие
// присваивания (cmd.Dir = ".") находкой быть не должны.
func TestFallbackReturnRule_RetryReassignsErrIsNotIgnoring(t *testing.T) {
	rule := NewFallbackReturnRule()

	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			name: "retry with err reassigned from call - not flagged",
			code: `package main

import "os/exec"

func runScript(url string) ([]byte, error) {
	cmd := exec.Command("node", "enhanced.js", url)
	output, err := cmd.Output()
	if err != nil {
		cmd = exec.Command("node", "basic.js", url)
		cmd.Dir = "."
		output, err = cmd.Output()
		if err != nil {
			return nil, err
		}
	}
	return output, nil
}`,
			wantCount: 0,
		},
		{
			name: "err silenced with nil literal - still flagged",
			code: `package main

func getValue() int {
	val, err := parseValue()
	if err != nil {
		val = 0
		err = nil
	}
	return val
}`,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := rulestest.GoFile(t, "retry.go", tt.code)
			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d", len(violations), tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s at line %d", v.Message, v.Line)
				}
			}
		})
	}
}
