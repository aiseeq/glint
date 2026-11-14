package deadcode

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"gopkg.in/yaml.v3"
)

func init() { rules.Register(NewExceptionTicketClosedRule()) }

// ExceptionTicketClosedRule reports suppressions tied to closed tickets.
type ExceptionTicketClosedRule struct{ *rules.BaseRule }

// NewExceptionTicketClosedRule creates the closed-ticket suppression rule.
func NewExceptionTicketClosedRule() *ExceptionTicketClosedRule {
	return &ExceptionTicketClosedRule{rules.NewBaseRule("exception-ticket-closed", "deadcode", "Reports suppressions referring to closed tickets with glint#<slug>; set tickets_dir in <UserConfigDir>/glint/config.yaml (XDG_CONFIG_HOME/glint/config.yaml on Linux)", core.SeverityMedium)}
}

// AnalyzeFile has no per-file findings; Check handles suppressions project-wide.
func (r *ExceptionTicketClosedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

var ticketFile = regexp.MustCompile(`^[0-9]{8}-[0-9]{4}-(?:LOW|MED|HIGH|CRIT)(?:-(?:DO|HUNT|ARCH))?-(.+)\.md$`)
var ticketRef = regexp.MustCompile(`\bglint#([a-z0-9]+(?:-[a-z0-9]+)*)`)

func ticketReferences(reason string) []string {
	var result []string
	for _, match := range ticketRef.FindAllStringSubmatch(reason, -1) {
		result = append(result, match[1])
	}
	return result
}

// TicketsConfigured reports whether the optional ticket directory is available.
func TicketsConfigured() (bool, error) {
	dir, err := ticketsDirectory()
	if err != nil {
		return false, err
	}
	if dir == "" {
		return false, nil
	}
	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat tickets directory %q: %w", dir, err)
	}
	return info.IsDir(), nil
}

func ticketsDirectory() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find glint user config directory: %w", err)
	}
	configPath := filepath.Join(configDir, "glint", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read glint user config %q: %w", configPath, err)
	}
	var config struct {
		TicketsDir string `yaml:"tickets_dir"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("parse glint user config %q: %w", configPath, err)
	}
	return config.TicketsDir, nil
}

type ticketStatusData struct {
	statuses map[string]string
	files    map[string]string
	names    map[string][]string
}

func readTicketStatuses() (ticketStatusData, error) {
	data := ticketStatusData{statuses: make(map[string]string), files: make(map[string]string), names: make(map[string][]string)}
	dir, err := ticketsDirectory()
	if err != nil {
		return ticketStatusData{}, err
	}
	if dir == "" {
		return data, nil
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return data, nil // the ticket repository is not on this machine: the rule is off, as without a config
	}
	if err != nil {
		return ticketStatusData{}, fmt.Errorf("read tickets directory %q: %w", dir, err)
	}
	for _, entry := range entries {
		match := ticketFile.FindStringSubmatch(entry.Name())
		if entry.IsDir() || match == nil {
			continue
		}
		data.names[match[1]] = append(data.names[match[1]], entry.Name())
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return ticketStatusData{}, fmt.Errorf("read ticket %q: %w", filepath.Join(dir, entry.Name()), err)
		}
		for line := range strings.SplitSeq(string(content), "\n") {
			if status, ok := strings.CutPrefix(line, "Статус:"); ok {
				status = strings.TrimSpace(status)
				if previous, ok := data.statuses[match[1]]; !ok || ticketStatusRank(status) > ticketStatusRank(previous) {
					data.statuses[match[1]] = status
				}
				data.files[entry.Name()] = status
				break
			}
		}
	}
	return data, nil
}

func ticketStatusRank(status string) int {
	switch status {
	case "отклонён":
		return 2
	case "готово":
		return 1
	default:
		return 0
	}
}

// ticketExceptionInScope tests files the scoped walk can report, including an
// explicitly named file that has no analyzable extension.
func ticketExceptionInScope(exc core.Exception, run StaleSuppressionRun) bool {
	if exc.File == "" && exc.Files == "" {
		return true
	}
	for _, ctx := range run.Contexts {
		if exc.NamesFile(filepath.ToSlash(ctx.RelPath)) {
			return true
		}
	}
	root := filepath.Dir(run.Config.ConfigPath())
	for _, scope := range run.Scopes {
		info, err := os.Stat(scope)
		if err != nil || info.IsDir() {
			continue
		}
		rel, err := filepath.Rel(root, scope)
		if err == nil && exc.NamesFile(filepath.ToSlash(rel)) {
			return true
		}
	}
	return false
}

// TicketState is a stable fingerprint of all configured ticket statuses.
func TicketState() (string, error) {
	data, err := readTicketStatuses()
	if err != nil {
		return "", err
	}
	keys := slices.Sorted(maps.Keys(data.files))
	hash := sha256.New()
	for _, key := range keys {
		hash.Write([]byte(key + "\x00" + data.files[key] + "\x00")) // hash.Hash.Write never returns an error
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// Check reads ticket statuses afresh even when source findings come from cache.
func (r *ExceptionTicketClosedRule) Check(run StaleSuppressionRun) ([]*core.Violation, error) {
	tickets, err := readTicketStatuses()
	if err != nil {
		return nil, err
	}
	if len(tickets.statuses) == 0 {
		return nil, nil
	}
	var found []*core.Violation
	add := func(file string, line int, name, reason string) {
		rule, ok := rules.Get(name)
		if !ok {
			return
		}
		severity := rule.DefaultSeverity()
		if configured, ok, err := run.Config.SeverityOverrideFor(rule.Category(), name); err == nil && ok {
			severity = configured
		}
		for _, slug := range ticketReferences(reason) {
			status := tickets.statuses[slug]
			if status != "готово" && status != "отклонён" {
				continue
			}
			level := severity
			suggestion := "Remove the suppression"
			if status == "готово" && level > core.SeverityMedium {
				level = core.SeverityMedium
			}
			if status == "отклонён" {
				suggestion = "Remove the suppression and fix the code"
			}
			message := fmt.Sprintf("Ticket glint#%s is %s; suppression of %s must be removed", slug, status, name)
			if len(tickets.names[slug]) > 1 {
				message += "; matching tickets: " + strings.Join(tickets.names[slug], ", ") + "; use an unambiguous ticket reference"
				suggestion += "; use an unambiguous ticket reference"
			}
			v := r.CreateViolation(file, line, message)
			v.Severity = level
			v.WithSuggestion(suggestion)
			found = append(found, v)
		}
	}
	for _, ctx := range run.Contexts {
		if !bytes.Contains(ctx.Content, []byte("glint#")) || ctx.IsGenerated() {
			continue
		}
		for _, marker := range suppressionMarkers(ctx) {
			for _, name := range marker.Rules {
				add(ctx.RelPath, marker.Line, name, marker.Text)
			}
		}
	}
	if run.Config.AnalyzesConfigDir() {
		exceptions := run.Config.Exceptions()
		for i := range exceptions {
			item := &exceptions[i]
			exc := item.Exception
			if !run.WholeRoot && !ticketExceptionInScope(exc, run) {
				continue
			}
			file, err := filepath.Rel(filepath.Dir(run.Config.ConfigPath()), exc.Source())
			if err == nil {
				add(file, exc.DeclaredAt(), item.Rule, exc.Reason)
			}
		}
	}
	return found, nil
}
