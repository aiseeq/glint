package patterns

import (
	"fmt"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalAfterFailedCheckpointRule_Metadata(t *testing.T) {
	rule := NewTerminalAfterFailedCheckpointRule()
	assert.Equal(t, "terminal-after-failed-checkpoint", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestTerminalAfterFailedCheckpointRule_OldProPayRegression(t *testing.T) {
	code := `package payments

func (s *Service) finalizePayout(ctx context.Context, payout *Payout) error {
	if err := s.repo.SaveProgress(ctx, payout); err != nil {
		s.logger.Error("failed to persist payout progress", "error", err)
	}

	return s.repo.MarkCompleted(ctx, payout.ID)
}`

	ctx := terminalAfterFailedCheckpointContext(t, "payout.go", code)
	violations := NewTerminalAfterFailedCheckpointRule().AnalyzeFile(ctx)

	require.Len(t, violations, 1)
	v := violations[0]
	require.Equal(t, core.SeverityHigh, v.Severity)
	require.Equal(t, 4, v.Line)
	require.NotEmpty(t, v.Code)
	require.NotEmpty(t, v.Suggestion)
	require.Equal(t, "terminal_after_failed_checkpoint", v.Context["pattern"])
	require.Equal(t, "finalizePayout", v.Context["function"])
	require.Equal(t, "SaveProgress", v.Context["checkpoint_method"])
	require.Equal(t, "MarkCompleted", v.Context["terminal_method"])
	require.Equal(t, 8, v.Context["terminal_line"])
}

func TestTerminalAfterFailedCheckpointRule_Methods(t *testing.T) {
	checkpointNames := []string{"SaveProgress", "SaveCheckpoint", "PersistProgress", "UpdateCheckpoint"}
	terminalNames := []string{"Finish", "Complete", "MarkDone", "MarkCompleted"}

	for i, checkpoint := range checkpointNames {
		terminal := terminalNames[i]
		t.Run(checkpoint+"_then_"+terminal, func(t *testing.T) {
			code := fmt.Sprintf(`package jobs
func run() {
	if saveErr := store.%s(); nil != saveErr {
		_ = saveErr
	}
	store.%s()
}`, checkpoint, terminal)
			ctx := terminalAfterFailedCheckpointContext(t, "job.go", code)
			violations := NewTerminalAfterFailedCheckpointRule().AnalyzeFile(ctx)
			require.Len(t, violations, 1)
			assert.Equal(t, checkpoint, violations[0].Context["checkpoint_method"])
			assert.Equal(t, terminal, violations[0].Context["terminal_method"])
		})
	}
}

func TestTerminalAfterFailedCheckpointRule_NonTerminatingAndTerminatingBranches(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "empty error branch continues",
			code: `package jobs
func run() {
	if err := store.SaveProgress(); err != nil {}
	store.Finish()
}`,
			want: 1,
		},
		{
			name: "success branch with logged failure else continues",
			code: `package jobs
func run() {
	if err := repo.SaveCheckpoint(); err == nil {
		logger.Info("checkpoint saved")
	} else {
		logger.Error(err)
	}
	repo.Complete()
}`,
			want: 1,
		},
		{
			name: "conditional return leaves a failure path",
			code: `package jobs
func run(strict bool) error {
	if err := store.SaveCheckpoint(); err != nil {
		if strict { return err }
		logger.Error(err)
	}
	return store.Complete()
}`,
			want: 1,
		},
		{
			name: "error branch returns",
			code: `package jobs
func run() error {
	if err := store.PersistProgress(); err != nil {
		return err
	}
	return store.MarkDone()
}`,
			want: 0,
		},
		{
			name: "error branch panics",
			code: `package jobs
func run() {
	if err := store.UpdateCheckpoint(); err != nil {
		panic(err)
	}
	store.MarkCompleted()
}`,
			want: 0,
		},
		{
			name: "all nested branches terminate",
			code: `package jobs
func run(retry bool) error {
	if err := store.SaveProgress(); err != nil {
		if retry {
			return err
		} else {
			panic(err)
		}
	}
	return store.Finish()
}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := terminalAfterFailedCheckpointContext(t, "job.go", tt.code)
			assert.Len(t, NewTerminalAfterFailedCheckpointRule().AnalyzeFile(ctx), tt.want)
		})
	}
}

func TestTerminalAfterFailedCheckpointRule_ScopeAndGuards(t *testing.T) {
	tests := []struct {
		name string
		path string
		code string
		want int
	}{
		{
			name: "terminal absent",
			path: "job.go",
			code: `package jobs
func run() {
	if err := store.SaveProgress(); err != nil { logger.Error(err) }
}`,
		},
		{
			name: "checkpoint returned directly",
			path: "job.go",
			code: `package jobs
func checkpoint() error { return store.SaveCheckpoint() }
func finish() { store.Finish() }`,
		},
		{
			name: "terminal only on checkpoint success",
			path: "job.go",
			code: `package jobs
func run() error {
	if err := store.PersistProgress(); err == nil {
		return store.Complete()
	} else {
		return err
	}
}`,
		},
		{
			name: "terminal in success else branch",
			path: "job.go",
			code: `package jobs
func run() error {
	if err := store.SaveProgress(); err != nil {
		logger.Error(err)
	} else {
		return store.Finish()
	}
	return nil
}`,
		},
		{
			name: "terminal before checkpoint",
			path: "job.go",
			code: `package jobs
func run() {
	store.MarkDone()
	if err := store.UpdateCheckpoint(); err != nil { logger.Error(err) }
}`,
		},
		{
			name: "different functions",
			path: "job.go",
			code: `package jobs
func checkpoint() {
	if err := store.SaveProgress(); err != nil { logger.Error(err) }
}
func finish() { store.MarkCompleted() }`,
		},
		{
			name: "terminal in nested closure",
			path: "job.go",
			code: `package jobs
func run() {
	if err := store.SaveCheckpoint(); err != nil { logger.Error(err) }
	callback := func() { store.Finish() }
	_ = callback
}`,
		},
		{
			name: "checkpoint in nested closure",
			path: "job.go",
			code: `package jobs
func run() {
	callback := func() {
		if err := store.SaveProgress(); err != nil { logger.Error(err) }
	}
	_ = callback
	store.Complete()
}`,
		},
		{
			name: "similar method names are outside narrow rule",
			path: "job.go",
			code: `package jobs
func run() {
	if err := store.SaveProgressBestEffort(); err != nil { logger.Error(err) }
	store.FinishLater()
}`,
		},
		{
			name: "test files skipped",
			path: "job_test.go",
			code: `package jobs
func run() {
	if err := store.SaveProgress(); err != nil { logger.Error(err) }
	store.Finish()
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := terminalAfterFailedCheckpointContext(t, tt.path, tt.code)
			assert.Len(t, NewTerminalAfterFailedCheckpointRule().AnalyzeFile(ctx), tt.want)
		})
	}
}

func TestTerminalAfterFailedCheckpointRule_StructuredControlFlow(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "checkpoint assignment before error guard",
			code: `package jobs
func run() {
	err := repo.SaveCheckpoint()
	if err != nil {
		logger.Error(err)
	}
	repo.Complete()
}`,
			want: 1,
		},
		{
			name: "compound error guard",
			code: `package jobs
func run() {
	if err := repo.SaveCheckpoint(); err != nil && retryable(err) {
		logger.Error(err)
	}
	repo.Complete()
}`,
			want: 1,
		},
		{
			name: "compound error guard return leaves non-retryable failure path",
			code: `package jobs
func run() {
	if err := repo.SaveCheckpoint(); err != nil && retryable(err) {
		return
	}
	repo.Complete()
}`,
			want: 1,
		},
		{
			name: "different terminal receiver",
			code: `package jobs
func run() {
	if err := repo.SaveCheckpoint(); err != nil {
		logger.Error(err)
	}
	span.Finish()
}`,
			want: 0,
		},
		{
			name: "terminal in mutually exclusive branch",
			code: `package jobs
func run(save bool) {
	if save {
		if err := repo.SaveCheckpoint(); err != nil {
			logger.Error(err)
		}
	} else {
		repo.Complete()
	}
}`,
			want: 0,
		},
		{
			name: "complete sequence in closure",
			code: `package jobs
func run() {
	callback := func() {
		if err := repo.SaveCheckpoint(); err != nil {
			logger.Error(err)
		}
		repo.Complete()
	}
	_ = callback
}`,
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := terminalAfterFailedCheckpointContext(t, "job.go", tt.code)
			assert.Len(t, NewTerminalAfterFailedCheckpointRule().AnalyzeFile(ctx), tt.want)
		})
	}
}

func TestTerminalAfterFailedCheckpointRule_NestedStructuredControlFlow(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "for",
			code: `package jobs
func run() {
	for i := 0; i < 1; i++ {
		if err := repo.SaveCheckpoint(); err != nil { logger.Error(err) }
		repo.Complete()
	}
}`,
			want: 1,
		},
		{
			name: "range",
			code: `package jobs
func run(items []int) {
	for range items {
		if err := repo.SaveCheckpoint(); err != nil { logger.Error(err) }
		repo.Complete()
	}
}`,
			want: 1,
		},
		{
			name: "switch",
			code: `package jobs
func run(kind int) {
	switch kind {
	case 1:
		if err := repo.SaveCheckpoint(); err != nil { logger.Error(err) }
		repo.Complete()
	}
}`,
			want: 1,
		},
		{
			name: "type switch",
			code: `package jobs
func run(value any) {
	switch value.(type) {
	case string:
		if err := repo.SaveCheckpoint(); err != nil { logger.Error(err) }
		repo.Complete()
	}
}`,
			want: 1,
		},
		{
			name: "select",
			code: `package jobs
func run(ready <-chan struct{}) {
	select {
	case <-ready:
		if err := repo.SaveCheckpoint(); err != nil { logger.Error(err) }
		repo.Complete()
	}
}`,
			want: 1,
		},
		{
			name: "merged switch paths report once",
			code: `package jobs
func run(kind int) {
	if err := repo.SaveCheckpoint(); err != nil { logger.Error(err) }
	switch kind {
	case 1:
		logger.Info("one")
	case 2:
		logger.Info("two")
	}
	repo.Complete()
}`,
			want: 1,
		},
		{
			name: "repeated guard reports checkpoint once",
			code: `package jobs
func run() {
	err := repo.SaveCheckpoint()
	if err != nil { logger.Error(err) }
	if err != nil { logger.Error(err) }
	repo.Complete()
}`,
			want: 1,
		},
		{
			name: "if init restores shadowed checkpoint receiver",
			code: `package jobs
func run() {
	err := other.SaveCheckpoint()
	if err := repo.SaveCheckpoint(); err != nil { return }
	if err != nil { logger.Error(err) }
	other.Complete()
}`,
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := terminalAfterFailedCheckpointContext(t, "job.go", tt.code)
			assert.Len(t, NewTerminalAfterFailedCheckpointRule().AnalyzeFile(ctx), tt.want)
		})
	}
}

func TestTerminalAfterFailedCheckpointRule_LexicalShadowing(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "ordinary block restores outer checkpoint error",
			code: `package jobs
func run() {
	err := outer.SaveCheckpoint()
	{
		err := inner.SaveCheckpoint()
		if err != nil { return }
	}
	if err != nil { logger.Error(err) }
	outer.Complete()
}`,
			want: 1,
		},
		{
			name: "for init restores outer checkpoint error",
			code: `package jobs
func run() {
	err := outer.SaveCheckpoint()
	for err := inner.SaveCheckpoint(); err == nil; {
		break
	}
	if err != nil { logger.Error(err) }
	outer.Complete()
}`,
			want: 1,
		},
		{
			name: "switch init restores outer checkpoint error",
			code: `package jobs
func run() {
	err := outer.SaveCheckpoint()
	switch err := inner.SaveCheckpoint(); {
	default:
		_ = err
	}
	if err != nil { logger.Error(err) }
	outer.Complete()
}`,
			want: 1,
		},
		{
			name: "assignment in same scope replaces checkpoint error",
			code: `package jobs
func run() {
	err := outer.SaveCheckpoint()
	err = inner.SaveCheckpoint()
	if err != nil { return }
	outer.Complete()
}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := terminalAfterFailedCheckpointContext(t, "job.go", tt.code)
			assert.Len(t, NewTerminalAfterFailedCheckpointRule().AnalyzeFile(ctx), tt.want)
		})
	}
}

func TestTerminalAfterFailedCheckpointRule_StandardSuppression(t *testing.T) {
	code := `package jobs
func run() {
	//nolint:terminal-after-failed-checkpoint // remote terminal status is authoritative
	if err := store.SaveProgress(); err != nil { logger.Error(err) }
	store.Finish()
}`

	ctx := terminalAfterFailedCheckpointContext(t, "job.go", code)
	assert.Empty(t, NewTerminalAfterFailedCheckpointRule().AnalyzeFile(ctx))
}

func terminalAfterFailedCheckpointContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := core.NewFileContext(path, ".", []byte(code), nil)
	parser := core.NewParser()
	fset, file, err := parser.ParseGoFile(path, []byte(code))
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)
	return ctx
}
