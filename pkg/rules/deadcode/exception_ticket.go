package deadcode

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"gopkg.in/yaml.v3"
)

func init() { rules.Register(NewExceptionTicketClosedRule()) }

type ExceptionTicketClosedRule struct{ *rules.BaseRule }

func NewExceptionTicketClosedRule() *ExceptionTicketClosedRule {
	return &ExceptionTicketClosedRule{rules.NewBaseRule("exception-ticket-closed", "deadcode", "Reports suppressions referring to closed tickets with glint#<slug>; set tickets_dir in <UserConfigDir>/glint/config.yaml (XDG_CONFIG_HOME/glint/config.yaml on Linux)", core.SeverityMedium)}
}

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

func ticketStatuses() map[string]string {
	statuses, _, _ := readTicketStatuses()
	return statuses
}

// TicketsConfigured reports whether the optional ticket directory is available.
func TicketsConfigured() bool {
	dir := ticketsDirectory()
	if dir == "" {
		return false
	}
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}

func ticketsDirectory() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(configDir, "glint", "config.yaml"))
	if err != nil {
		return ""
	}
	var config struct {
		TicketsDir string `yaml:"tickets_dir"`
	}
	if yaml.Unmarshal(data, &config) != nil {
		return ""
	}
	return config.TicketsDir
}

func readTicketStatuses() (map[string]string, map[string]string, map[string][]string) {
	statuses := make(map[string]string)
	files := make(map[string]string)
	names := make(map[string][]string)
	dir := ticketsDirectory()
	if dir == "" {
		return statuses, files, names
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return statuses, files, names
	}
	for _, entry := range entries {
		match := ticketFile.FindStringSubmatch(entry.Name())
		if entry.IsDir() || match == nil {
			continue
		}
		names[match[1]] = append(names[match[1]], entry.Name())
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if status, ok := strings.CutPrefix(line, "Статус:"); ok {
				status = strings.TrimSpace(status)
				if previous, ok := statuses[match[1]]; !ok || ticketStatusRank(status) > ticketStatusRank(previous) {
					statuses[match[1]] = status
				}
				files[entry.Name()] = status
				break
			}
		}
	}
	return statuses, files, names
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
func TicketState() string {
	_, files, _ := readTicketStatuses()
	keys := make([]string, 0, len(files))
	for key := range files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hash := sha256.New()
	for _, key := range keys {
		hash.Write([]byte(key + "\x00" + files[key] + "\x00")) // hash.Hash.Write never returns an error
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// Check reads ticket statuses afresh even when source findings come from cache.
func (r *ExceptionTicketClosedRule) Check(run StaleSuppressionRun) []*core.Violation {
	statuses, _, names := readTicketStatuses()
	if len(statuses) == 0 {
		return nil
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
			status := statuses[slug]
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
			if len(names[slug]) > 1 {
				message += "; matching tickets: " + strings.Join(names[slug], ", ") + "; use an unambiguous ticket reference"
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
		for _, item := range run.Config.Exceptions() {
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
	return found
}
