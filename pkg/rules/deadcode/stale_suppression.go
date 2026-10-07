package deadcode

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewStaleSuppressionRule())
}

// StaleSuppressionRule detects suppressions that silence nothing:
//
//	x := load() //nolint:ignored-error  — the rule reports nothing on this line or the next
//	//nolint                            — names no rule; glint honors only nolint:<rule>
//	//nolint:errcheck                   — not a glint rule, and the project has no golangci-lint
//	//nolint:glint                      — the tool, not a rule: golangci-lint has no such linter either
//	exceptions: [{file: a.go, function: gone}]  — matched no finding of the run
//	exceptions: [{files: "**/*_test.go"}]       — the rule finds nothing in those files
//
// A marker outlives the finding it was written for: the code moved, the rule
// was narrowed. It then sits there until a real finding of that rule appears
// on its line, and silences that one unseen. An exception whose files do not
// exist is dead-config-exception's; here an exception counts as stale when the
// files exist and the run produced no finding it matched.
//
// Judged only against rules the run executed: a marker of a rule the
// configuration or --rule left out, or on a file a file exception keeps the
// rule off, is not. Names that are not glint rules, but for glint itself, are
// taken for golangci-lint's when the project configures golangci-lint.
// Exceptions are judged only when the run covers the whole directory of their
// configuration; a file-only exception by running the rule on the files it
// names, except for a rule whose analysis of one file feeds its findings on
// others (rules.AccumulatesAcrossFiles), which is not run there.
type StaleSuppressionRule struct {
	*rules.BaseRule
}

// NewStaleSuppressionRule creates the rule.
func NewStaleSuppressionRule() *StaleSuppressionRule {
	return &StaleSuppressionRule{BaseRule: rules.NewBaseRule(
		"stale-suppression",
		"deadcode",
		"Detects inline suppressions and configuration exceptions that silence no finding — they wait to hide the next real one",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: whether a marker is needed is known only after
// every rule has run.
func (r *StaleSuppressionRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// StaleSuppressionRun is what one analyzed root tells about its suppressions.
type StaleSuppressionRun struct {
	Contexts []*core.FileContext
	// Suppressions are the entries of the findings the run silenced
	// (core.Violation.Suppression), files relative to the root.
	Suppressions core.ViolationList
	// Executed are the rules the run executed, by name.
	Executed map[string]rules.Rule
	Config   *core.Config
	// WholeRoot is set when the run covered the root's whole tree.
	WholeRoot bool
}

// Check reports the stale suppressions of one root: inline markers, files
// relative to the root, and exceptions, at their line of the configuration
// file relative to the root.
func (r *StaleSuppressionRule) Check(run StaleSuppressionRun) ([]*core.Violation, error) {
	used := map[string]bool{}
	for _, entry := range run.Suppressions {
		used[suppressionKey(entry.File, entry.Rule, entry.Line, entry.Suppression)] = true
	}
	golangci := false
	if len(run.Contexts) > 0 {
		found, err := hasGolangciConfig(run.Contexts[0].ProjectRoot)
		if err != nil {
			return nil, err
		}
		golangci = found
	}
	var violations []*core.Violation
	for _, ctx := range run.Contexts {
		if ctx.IsGenerated() {
			continue
		}
		for _, marker := range suppressionMarkers(ctx) {
			if marker.Bare {
				violations = append(violations, r.markerViolation(ctx, marker.Line,
					"Bare nolint names no rule — glint honors only nolint:<rule>, so it silences nothing here",
					"Name the rules it is meant for (nolint:<rule>) or delete it"))
			}
			for _, name := range marker.Rules {
				if v := r.judgeName(ctx, marker.Line, name, run, used, golangci); v != nil {
					violations = append(violations, v)
				}
			}
		}
	}
	if run.WholeRoot && run.Config.AnalyzesConfigDir() {
		stale, err := r.staleExceptions(run, used)
		if err != nil {
			return nil, err
		}
		violations = append(violations, stale...)
	}
	return violations, nil
}

// judgeName reports a rule name of a marker that silences nothing: a name
// that is no glint rule (unless golangci-lint is configured, whose linters it
// may name), or an executed rule that reported nothing the marker covers.
func (r *StaleSuppressionRule) judgeName(ctx *core.FileContext, line int, name string, run StaleSuppressionRun, used map[string]bool, golangci bool) *core.Violation {
	rule, known := rules.Get(name)
	if name == toolName {
		return r.markerViolation(ctx, line,
			fmt.Sprintf("Suppression names %q, the tool rather than a rule — glint honors only nolint:<rule>, and golangci-lint knows no such linter, so it silences nothing", name),
			"Name the glint rules it is meant for (nolint:<rule>) or delete it")
	}
	if !known {
		if golangci {
			return nil
		}
		return r.markerViolation(ctx, line,
			fmt.Sprintf("Suppression names %q, which is no glint rule, and the project configures no golangci-lint — it silences nothing", name),
			"Fix the rule name (glint rules lists them) or delete the marker")
	}
	// Its own markers are honored after this check, by the run.
	if _, ran := run.Executed[name]; !ran || name == r.Name() || run.Config.IsFileExcepted(rule.Category(), name, ctx.RelPath) {
		return nil
	}
	if used[suppressionKey(ctx.RelPath, name, line, core.SuppressionInline)] {
		return nil
	}
	return r.markerViolation(ctx, line,
		fmt.Sprintf("Suppression of %s silences nothing: the rule reports nothing on this line or the next", name),
		"Delete the marker; if the finding moved, put the marker where the rule reports it now")
}

// toolName is the name of the tool, which a nolint list may name in the
// belief that it silences every glint rule.
const toolName = "glint"

// staleExceptions reports the exceptions of executed rules that matched no
// finding, leaving to dead-config-exception those whose files do not exist.
func (r *StaleSuppressionRule) staleExceptions(run StaleSuppressionRun, used map[string]bool) ([]*core.Violation, error) {
	files, err := run.Config.ConfigFiles()
	if err != nil {
		return nil, fmt.Errorf("list the files of the configuration's directory: %w", err)
	}
	usedExceptions := map[string]bool{}
	for key := range used {
		if _, exception, ok := strings.Cut(key, "\x00"+core.SuppressionExceptionPrefix); ok {
			usedExceptions[exception] = true
		}
	}
	var violations []*core.Violation
	for _, ruleException := range run.Config.Exceptions() {
		exc := ruleException.Exception
		rule, ran := run.Executed[ruleException.Rule]
		// Its own findings are filtered after this check, by the run.
		if !ran || usedExceptions[exc.Key()] || ruleException.Rule == r.Name() {
			continue
		}
		if exc.IsFileOnly() && rules.AccumulatesAcrossFiles(rule) {
			continue // not run on the files it names
		}
		if (exc.File != "" || exc.Files != "") && !slices.ContainsFunc(files, exc.NamesFile) {
			continue // the files do not exist: dead-config-exception's finding
		}
		source, err := filepath.Rel(filepath.Dir(run.Config.ConfigPath()), exc.Source())
		if err != nil {
			return nil, fmt.Errorf("name configuration %q relative to its directory: %w", exc.Source(), err)
		}
		v := r.CreateViolation(source, exc.DeclaredAt(),
			fmt.Sprintf("Exception of %s matched no finding of this run — it silences nothing and waits for the next real one", ruleException.Rule))
		v.WithSuggestion("Delete the exception, or narrow it to the finding it was written for")
		v.WithContext("category", ruleException.Category)
		violations = append(violations, v)
	}
	return violations, nil
}

func (r *StaleSuppressionRule) markerViolation(ctx *core.FileContext, line int, message, suggestion string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(suggestion)
	return v
}

// suppressionMarker is an inline suppression comment of a line: the rule
// names it lists, or a bare nolint that names none.
type suppressionMarker struct {
	Line  int
	Rules []string
	Bare  bool
}

// suppressionMarkers returns the markers of the file's comments: of the
// syntax tree for Go, of the lines outside literals for TypeScript and
// JavaScript. Other files are not read: a marker quoted in documentation is
// an example.
func suppressionMarkers(ctx *core.FileContext) []suppressionMarker {
	var markers []suppressionMarker
	add := func(line int, comment string) {
		if names, bare := core.ParseSuppressionComment(comment); len(names) > 0 || bare {
			markers = append(markers, suppressionMarker{Line: line, Rules: names, Bare: bare})
		}
	}
	switch {
	case ctx.IsGoFile() && ctx.HasGoAST():
		for _, group := range ctx.GoAST.Comments {
			for _, comment := range group.List {
				first := ctx.LineForPos(comment.Pos())
				for i, text := range strings.Split(comment.Text, "\n") {
					// A Go doc code block (//<tab>) quotes an example.
					if !strings.HasPrefix(text, "//\t") {
						add(first+i, text)
					}
				}
			}
		}
	case ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile():
		text := helpers.FileJSText(ctx)
		for i, line := range ctx.Lines {
			comment := core.CommentPart(line)
			start := len(line) - len(comment)
			// The comment masked away in the text view is a comment, not
			// a "//" inside a literal.
			if comment != "" && i < len(text) && start < len(text[i]) && text[i][start] == ' ' {
				add(i+1, comment)
			}
		}
	}
	return markers
}

// suppressionKey identifies a suppression entry: an inline marker by its file,
// rule and line, an exception by its key.
func suppressionKey(file, rule string, line int, suppression string) string {
	if strings.HasPrefix(suppression, core.SuppressionExceptionPrefix) {
		return "\x00" + suppression
	}
	return fmt.Sprintf("%s\x00%s\x00%d", file, rule, line)
}

// golangciConfigNames are the configuration files golangci-lint reads.
var golangciConfigNames = []string{".golangci.yml", ".golangci.yaml", ".golangci.toml", ".golangci.json"}

// hasGolangciConfig reports whether golangci-lint is configured in dir or a
// directory above it.
func hasGolangciConfig(dir string) (bool, error) {
	for {
		for _, name := range golangciConfigNames {
			_, err := os.Stat(filepath.Join(dir, name))
			if err == nil {
				return true, nil
			}
			if !os.IsNotExist(err) {
				return false, fmt.Errorf("look for the golangci-lint configuration: %w", err)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false, nil
		}
		dir = parent
	}
}
