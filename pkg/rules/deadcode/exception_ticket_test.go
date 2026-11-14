package deadcode

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/require"
)

func TestDuplicateTicketWorstStatus(t *testing.T) {
	for _, rejectedFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(rejectedFirst), func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", root)
			dir := filepath.Join(root, "tickets")
			require.NoError(t, os.MkdirAll(dir, 0755))
			require.NoError(t, os.MkdirAll(filepath.Join(root, "glint"), 0755))
			require.NoError(t, os.WriteFile(filepath.Join(root, "glint", "config.yaml"), []byte("tickets_dir: "+dir+"\n"), 0644))
			a, b := "20260101-0100-HIGH-same.md", "20260102-0100-HIGH-same.md"
			first, second := "открыт", "отклонён"
			if rejectedFirst {
				first, second = second, first
			}
			require.NoError(t, os.WriteFile(filepath.Join(dir, a), []byte("Статус: "+first+"\n"), 0644))
			require.NoError(t, os.WriteFile(filepath.Join(dir, b), []byte("Статус: "+second+"\n"), 0644))
			cfg, err := core.LoadConfigWithDefaults(root)
			require.NoError(t, err)
			ctx := core.NewFileContext(filepath.Join(root, "run.sh"), root, []byte("#nolint:never-assigned-func-var // glint#same\n"), cfg)
			found, err := NewExceptionTicketClosedRule().Check(StaleSuppressionRun{Contexts: []*core.FileContext{ctx}, Config: cfg})
			require.NoError(t, err)
			require.Len(t, found, 1)
			require.Equal(t, core.SeverityHigh, found[0].Severity)
			require.Contains(t, found[0].Message, a)
			require.Contains(t, found[0].Message, b)
			require.Contains(t, found[0].Message, "unambiguous")
			require.Contains(t, found[0].Suggestion, "unambiguous")
			require.NoError(t, os.WriteFile(filepath.Join(dir, a), []byte("Статус: готово\n"), 0644))
			require.NoError(t, os.WriteFile(filepath.Join(dir, b), []byte("Статус: открыт\n"), 0644))
			found, err = NewExceptionTicketClosedRule().Check(StaleSuppressionRun{Contexts: []*core.FileContext{ctx}, Config: cfg})
			require.NoError(t, err)
			require.Len(t, found, 1)
			require.Equal(t, core.SeverityMedium, found[0].Severity)
		})
	}
}

func TestTicketStateAndReferences(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	state, err := TicketState()
	require.NoError(t, err)
	stateAgain, err := TicketState()
	require.NoError(t, err)
	require.Equal(t, state, stateAgain)
	dir := filepath.Join(root, "tickets")
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "glint"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "glint", "config.yaml"), []byte("tickets_dir: "+dir+"\n"), 0644))
	path := filepath.Join(dir, "20261114-0100-HIGH-ARCH-example-bug.md")
	require.NoError(t, os.WriteFile(path, []byte("Статус: открыт\n"), 0644))
	duplicate := filepath.Join(dir, "20261113-0100-HIGH-example-bug.md")
	require.NoError(t, os.WriteFile(duplicate, []byte("Статус: открыт\n"), 0644))
	beforeDuplicate, err := TicketState()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(duplicate, []byte("Статус: готово\n"), 0644))
	afterDuplicate, err := TicketState()
	require.NoError(t, err)
	require.NotEqual(t, beforeDuplicate, afterDuplicate)
	before, err := TicketState()
	require.NoError(t, err)
	tickets, err := readTicketStatuses()
	require.NoError(t, err)
	require.Equal(t, "готово", tickets.statuses["example-bug"])
	require.Equal(t, []string{"example-bug"}, ticketReferences("reason glint#example-bug."))
	require.NoError(t, os.WriteFile(path, []byte("Статус: отклонён\n"), 0644))
	after, err := TicketState()
	require.NoError(t, err)
	require.NotEqual(t, before, after)
	tickets, err = readTicketStatuses()
	require.NoError(t, err)
	require.Equal(t, "отклонён", tickets.statuses["example-bug"])
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	ctx := core.NewFileContext(filepath.Join(root, "sample.sh"), root, []byte("#nolint:never-assigned-func-var // glint#example-bug\n"), cfg)
	found, err := NewExceptionTicketClosedRule().Check(StaleSuppressionRun{Contexts: []*core.FileContext{ctx}, Config: cfg})
	require.NoError(t, err)
	require.Len(t, found, 1)
	require.Equal(t, core.SeverityHigh, found[0].Severity)
}

func TestClosedTicketSuppressions(t *testing.T) {
	root := t.TempDir()
	configHome := filepath.Join(root, "config")
	t.Setenv("XDG_CONFIG_HOME", configHome)
	dir := filepath.Join(root, "tickets")
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(configHome, "glint"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configHome, "glint", "config.yaml"), []byte("tickets_dir: "+dir+"\n"), 0644))
	writeTicket := func(slug, status string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "20261114-0100-MED-"+slug+".md"), []byte("Статус: "+status+"\n"), 0644))
	}
	writeTicket("open", "открыт")
	writeTicket("done", "готово")
	writeTicket("rejected", "отклонён")
	config := `categories:
  deadcode:
    rules:
      never-assigned-func-var:
        exceptions:
          - file: example.go
            reason: "glint#rejected"
`
	require.NoError(t, os.WriteFile(filepath.Join(root, ".glint.yaml"), []byte(config), 0644))
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	source := "# nolint:never-assigned-func-var // glint#open\n# never-assigned-func-var: safe — glint#done\n# nolint:empty-go-file // glint#done\n# nolint:never-assigned-func-var // glint#rejected\n# nolint:never-assigned-func-var // glint#missing\n# nolint:never-assigned-func-var // reason\n"
	ctx := core.NewFileContext(filepath.Join(root, "example.sh"), root, []byte(source), cfg)
	check := NewExceptionTicketClosedRule()
	run := StaleSuppressionRun{Contexts: []*core.FileContext{ctx}, Config: cfg, WholeRoot: true}
	found, err := check.Check(run)
	require.NoError(t, err)
	require.Len(t, found, 4)
	require.Equal(t, core.SeverityMedium, found[0].Severity)
	require.Equal(t, core.SeverityLow, found[1].Severity)
	require.Equal(t, core.SeverityHigh, found[2].Severity)
	require.Contains(t, found[2].Suggestion, "fix the code")
	require.Equal(t, ".glint.yaml", found[3].File)
	require.Equal(t, 6, found[3].Line)
	require.Equal(t, core.SeverityHigh, found[3].Severity)
	writeTicket("open", "отклонён")
	found, err = check.Check(run)
	require.NoError(t, err)
	require.Len(t, found, 5)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "missing"))
	found, err = check.Check(run)
	require.NoError(t, err)
	require.Empty(t, found)
}

func TestTicketConfigurationErrorsAreVisible(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	_, err := TicketState()
	require.NoError(t, err)
	check := NewExceptionTicketClosedRule()
	found, err := check.Check(StaleSuppressionRun{})
	require.NoError(t, err)
	require.Empty(t, found)

	configDir := filepath.Join(root, "glint")
	require.NoError(t, os.MkdirAll(configDir, 0755))
	configPath := filepath.Join(configDir, "config.yaml")
	require.NoError(t, os.Mkdir(configPath, 0755))
	_, err = TicketState()
	require.Error(t, err)
	found, err = check.Check(StaleSuppressionRun{})
	require.Error(t, err)
	require.Empty(t, found)

	require.NoError(t, os.Remove(configPath))
	ticketsFile := filepath.Join(root, "not-a-directory")
	require.NoError(t, os.WriteFile(ticketsFile, nil, 0644))
	require.NoError(t, os.WriteFile(configPath, []byte("tickets_dir: "+ticketsFile+"\n"), 0644))
	_, err = TicketState()
	require.Error(t, err)
}
