package patterns

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewModelNotApprovedRule())
}

// defaultApprovedModels is the list of the approved models: one model a
// line, "<name> <id>", # starts a comment.
const defaultApprovedModels = "~/.config/models/approved"

// ModelNotApprovedRule detects a language model named in code that is not on
// the approved list:
//
//	TriageModel: "sonnet",
//	exec.Command("claude", "-p", "--model", "haiku")
//	codex exec -m gpt-5 "$prompt"
//
// A default left at an older or unreviewed model keeps running it after the
// list moved on. A Go, TypeScript or JavaScript test calls no model: there
// only a --model or -m of a process the test starts counts, the models in
// the rest of it are the data of the code under test. The value has to look
// like a model (claude-*, gpt-*, sonnet, ...), so a commit message after -m
// or a car model in a Model field is not taken for one.
type ModelNotApprovedRule struct {
	*rules.BaseRule
	path     string
	approved func() (*approvedModels, error)
}

// approvedModels is the approved list: the names and ids it accepts, and
// both in the order of the file for the message.
type approvedModels struct {
	accepted map[string]bool
	names    []string
}

// NewModelNotApprovedRule creates the rule
func NewModelNotApprovedRule() *ModelNotApprovedRule {
	r := &ModelNotApprovedRule{BaseRule: rules.NewBaseRule(
		"model-not-approved",
		"patterns",
		"Detects a language model named in Go, TypeScript, JavaScript or shell code (a *model key, --model, -m) that is not on the approved list (approved_file, "+defaultApprovedModels+": \"<name> <id>\" a line)",
		core.SeverityHigh,
	)}
	r.setPath(defaultApprovedModels)
	return r
}

// Configure reads approved_file, the path of the approved list.
func (r *ModelNotApprovedRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	value, present := settings["approved_file"]
	if !present {
		return nil
	}
	path, ok := value.(string)
	if !ok || path == "" {
		return fmt.Errorf("configure %s: approved_file must be a non-empty path, got %v", r.Name(), value)
	}
	r.setPath(path)
	return nil
}

func (r *ModelNotApprovedRule) setPath(path string) {
	r.path = path
	r.approved = sync.OnceValues(func() (*approvedModels, error) { return readApprovedModels(path) })
}

// ReadsOtherFiles reports that the findings depend on the approved list.
func (r *ModelNotApprovedRule) ReadsOtherFiles() bool { return true }

// CheckTools fails when the files hold code and the approved list cannot be
// read: without it every model would pass.
func (r *ModelNotApprovedRule) CheckTools(files []*core.FileContext) error {
	if slices.ContainsFunc(files, modelCodeFile) {
		_, err := r.approved()
		return err
	}
	return nil
}

// AnalyzeFile reports the lines naming a model off the approved list.
func (r *ModelNotApprovedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !modelCodeFile(ctx) {
		return nil
	}
	approved, err := r.approved()
	if err != nil {
		v := r.CreateViolation(ctx.RelPath, 1, "the approved models could not be read, so no model in this file was checked: "+err.Error())
		return []*core.Violation{v.WithSuggestion("Fix the approved list or approved_file")}
	}
	patterns := []*regexp.Regexp{modelFlag, modelKey}
	testData := ctx.IsTestFile() && !ctx.IsShellFile()
	if testData {
		patterns = patterns[:1]
	}
	var violations []*core.Violation
	for i, code := range modelCodeLines(ctx) {
		if testData && !processLaunch.MatchString(code) {
			continue
		}
		// modelFlag needs "-m", modelKey "model" in any case.
		if !strings.Contains(code, "-m") && !containsAnyFold(code, []string{"model"}) {
			continue
		}
		model := unapprovedModel(code, patterns, approved.accepted)
		if model == "" || ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, fmt.Sprintf("Model %q is not on the approved list (%s)", model, strings.Join(approved.names, ", ")))
		v.WithCode(ctx.GetLine(i + 1))
		v.WithSuggestion("Use an approved model by its name or id; a model off the list is taken only after a benchmark and the owner's approval of the list")
		violations = append(violations, v)
	}
	return violations
}

// modelCodeFile reports Go, TypeScript, JavaScript, shell and make files.
func modelCodeFile(ctx *core.FileContext) bool {
	return ctx.IsGoFile() || ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile() || ctx.IsShellFile() || ctx.IsMakefile()
}

// modelCodeLines returns the lines of the file without their comments.
func modelCodeLines(ctx *core.FileContext) []string {
	if ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile() {
		return helpers.FileJSText(ctx)
	}
	lines := make([]string, len(ctx.Lines))
	for i, line := range ctx.Lines {
		lines[i] = strings.TrimSuffix(line, ctx.CommentOf(line))
	}
	return lines
}

// modelToken is a literal value: a quote may open it, $ or ${ does not.
const modelToken = `["'` + "`" + `]?([A-Za-z0-9][\w.:/\[\]-]*)`

var (
	// --model sonnet, --model=sonnet, "--model", "sonnet"; -m likewise.
	modelFlag = regexp.MustCompile(`(?:^|[\s"'` + "`" + `(\[,])(?:--model|-m)(?:=|\s+|["']\s*,\s*["'])` + modelToken)
	// Model: "sonnet", model: 'sonnet', MODEL=sonnet, model := "sonnet".
	modelKey = regexp.MustCompile(`(?i)\w*model\w*["']?\s*(?::=|:|=)\s*` + modelToken)
	// A process a Go, TypeScript or JavaScript test starts: the only line
	// of a test that runs a model, the rest is the data of the code under
	// test.
	processLaunch = regexp.MustCompile(`\b(?:exec\.Command(?:Context)?|spawn(?:Sync)?|execFile(?:Sync)?|execSync|execa)\s*\(`)
	// The families of the language models, after an optional provider/.
	modelFamily = regexp.MustCompile(`(?i)^(?:[\w.-]+/)*(?:claude|anthropic|sonnet|haiku|opus|fable|gpt|chatgpt|o[1-9]|codex|gemini|gemma|llama|mistral|mixtral|codestral|qwen|deepseek|grok|kimi|glm|sol|luna)(?:$|[-.:_\d\[])`)
)

// unapprovedModel returns the first model the patterns find in the code off
// the approved list, "" when there is none.
func unapprovedModel(code string, patterns []*regexp.Regexp, approved map[string]bool) string {
	for _, pattern := range patterns {
		for _, m := range pattern.FindAllStringSubmatch(code, -1) {
			model := m[1]
			if modelFamily.MatchString(model) && !approved[modelKeyOf(model)] {
				return model
			}
		}
	}
	return ""
}

// modelKeyOf drops the provider (openai/), the context window suffix ([1m])
// and the case.
func modelKeyOf(model string) string {
	model = model[strings.LastIndexByte(model, '/')+1:]
	if i := strings.IndexByte(model, '['); i > 0 {
		model = model[:i]
	}
	return strings.ToLower(model)
}

// readApprovedModels reads the approved list.
func readApprovedModels(path string) (*approvedModels, error) {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("locate the approved models %s: %w", path, err)
		}
		path = filepath.Join(home, rest)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the approved models: %w", err)
	}
	list := &approvedModels{accepted: map[string]bool{}}
	for n, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: want \"<name> <id>\", got %q", path, n+1, strings.TrimSpace(line))
		}
		for _, f := range fields {
			list.accepted[strings.ToLower(f)] = true
			list.names = append(list.names, f)
		}
	}
	if len(list.names) == 0 {
		return nil, errors.New(path + ": no approved models")
	}
	return list, nil
}
