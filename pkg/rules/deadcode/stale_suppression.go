package deadcode

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewStaleSuppressionRule())
}

// SuppressionWithoutReasonRule requires explanations after inline suppression markers.
type SuppressionWithoutReasonRule struct{ *rules.BaseRule }

// NewSuppressionWithoutReasonRule constructs the suppression reason rule.
func NewSuppressionWithoutReasonRule() *SuppressionWithoutReasonRule {
	return &SuppressionWithoutReasonRule{rules.NewBaseRule("suppression-without-reason", "deadcode", "Requires a reason after inline suppression markers", core.SeverityLow)}
}

// RuleCacheReadsRegistry: only a marker that names a registered rule is judged.
func (r *SuppressionWithoutReasonRule) RuleCacheReadsRegistry() {}

// AnalyzeFile reports suppression markers that have no explanation.
func (r *SuppressionWithoutReasonRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.markersWithoutReason(ctx, func(string) bool { return true })
}

// MarkersWithoutReasonFor reports markers in ctx that name one of names
// without a reason. A file read only for some rules — a YAML file for
// exception-ticket-closed, an excluded instruction file for instruction-size
// — can hide nothing but their findings, so only their markers are judged
// there.
func (r *SuppressionWithoutReasonRule) MarkersWithoutReasonFor(ctx *core.FileContext, names ...string) []*core.Violation {
	return r.markersWithoutReason(ctx, func(name string) bool { return slices.Contains(names, name) })
}

// markersWithoutReason reports each marker that names a judged rule without
// a reason, with those rules (MarkerRules): the finding is as severe as what
// the marker silenced of them. Markers of one line with the same message —
// two bare nolint markers — are one finding, with the rules of both.
func (r *SuppressionWithoutReasonRule) markersWithoutReason(ctx *core.FileContext, judged func(string) bool) []*core.Violation {
	type place struct {
		line    int
		message string
	}
	var found []*core.Violation
	at := map[place]*core.Violation{}
	for _, marker := range ctx.SuppressionMarkers() {
		var names []string
		for _, name := range marker.Rules {
			if _, ok := rules.Get(name); ok && judged(name) && !core.SuppressionHasReason(marker.Text, name) {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			continue
		}
		message := "Suppression has no reason after safe"
		if strings.HasPrefix(core.SuppressionCommentText(marker.Text), "nolint:") {
			message = "Suppression has no reason; add a short explanation after the rule name"
		}
		if v, ok := at[place{marker.Line, message}]; ok {
			v.MarkerRules = append(v.MarkerRules, names...)
			continue
		}
		v := r.CreateViolation(ctx.RelPath, marker.Line, message)
		v.MarkerRules = names
		at[place{marker.Line, message}] = v
		found = append(found, v)
	}
	return found
}

// BroadExclusionRule reports project configuration that excludes broad source areas.
type BroadExclusionRule struct{ *rules.BaseRule }

// NewBroadExclusionRule constructs the broad exclusion rule.
func NewBroadExclusionRule() *BroadExclusionRule {
	return &BroadExclusionRule{rules.NewBaseRule("broad-exclusion", "deadcode", "Reports exclusions that hide an entire source directory, every file or every test of a language, or a category", core.SeverityLow)}
}

// AnalyzeFile is a no-op because broad exclusions are checked against project configuration.
func (*BroadExclusionRule) AnalyzeFile(*core.FileContext) []*core.Violation { return nil }

func init() {
	rules.Register(NewSuppressionWithoutReasonRule())
	rules.Register(NewBroadExclusionRule())
}

// StaleSuppressionRule detects suppressions that silence nothing:
//
//	x := load() //nolint:ignored-error  — the rule reports nothing on this line
//	//nolint:ignored-error              — of its own line: nothing on this line or the next
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
// names.
type StaleSuppressionRule struct {
	*rules.BaseRule
}

// staleSuppressionName is the name of stale-suppression.
const staleSuppressionName = "stale-suppression"

// RuleCacheReadsRegistry: a marker naming no registered rule is stale.
func (r *StaleSuppressionRule) RuleCacheReadsRegistry() {}

// NewStaleSuppressionRule creates the rule.
func NewStaleSuppressionRule() *StaleSuppressionRule {
	return &StaleSuppressionRule{BaseRule: rules.NewBaseRule(
		staleSuppressionName,
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
	// Scopes are the explicit paths of a partial run, absolute.
	Scopes []string
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
		for _, marker := range ctx.SuppressionMarkers() {
			if marker.Bare {
				violations = append(violations, r.markerViolation(ctx, marker.Line,
					"Bare nolint names no rule — glint honors only nolint:<rule>, so it silences nothing here",
					"Name the rules it is meant for (nolint:<rule>) or delete it"))
			}
			for _, name := range marker.Rules {
				if v := r.judgeName(ctx, marker, name, run, used, golangci); v != nil {
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
func (r *StaleSuppressionRule) judgeName(ctx *core.FileContext, marker core.SuppressionMarker, name string, run StaleSuppressionRun, used map[string]bool, golangci bool) *core.Violation {
	line := marker.Line
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
	covered := "this line or the next"
	if marker.LineOnly {
		covered = "this line" // a marker after code or at the end of embedded text covers its line only
	}
	return r.markerViolation(ctx, line,
		fmt.Sprintf("Suppression of %s silences nothing: the rule reports nothing on %s", name, covered),
		"Delete the marker; if the finding moved, put the marker where the rule reports it now")
}

// toolName is the name of the tool, which a nolint list may name in the
// belief that it silences every glint rule.
const toolName = "glint"

// staleExceptions reports the exceptions of executed rules that matched no
// finding, leaving to dead-config-exception those whose files do not exist.
func (r *StaleSuppressionRule) staleExceptions(run StaleSuppressionRun, used map[string]bool) ([]*core.Violation, error) {
	usedExceptions := map[string]bool{}
	for key := range used {
		if _, exception, ok := strings.Cut(key, "\x00"+core.SuppressionExceptionPrefix); ok {
			usedExceptions[exception] = true
		}
	}
	judged, err := judgedExceptions(run.Config, func(ruleException *core.RuleException) bool {
		_, ran := run.Executed[ruleException.Rule]
		return ran && !usedExceptions[run.Config.ExceptionKey(ruleException.Exception)]
	})
	if err != nil {
		return nil, err
	}
	violations := make([]*core.Violation, 0, len(judged))
	for _, exception := range judged {
		var target []string
		if exception.Exception.File != "" {
			target = append(target, fmt.Sprintf("file %q", exception.Exception.File))
		}
		if exception.Exception.Files != "" {
			target = append(target, fmt.Sprintf("files %q", exception.Exception.Files))
		}
		if exception.Exception.Function != "" {
			target = append(target, fmt.Sprintf("function %q", exception.Exception.Function))
		}
		if exception.Exception.Pattern != "" {
			target = append(target, fmt.Sprintf("pattern %q", exception.Exception.Pattern))
		}
		if exception.Exception.Line > 0 {
			target = append(target, fmt.Sprintf("line %d", exception.Exception.Line))
		}
		if len(target) == 0 {
			// The configuration refuses an exception that names none of these,
			// but a negative line passes it and narrows nothing.
			target = append(target, "every finding")
		}

		v := r.CreateViolation(exception.place.File, exception.place.Line,
			fmt.Sprintf("Exception of %s for %s matched no finding of this run — it silences nothing and waits for the next real one", exception.Rule, strings.Join(target, ", ")))
		v.WithSuggestion("Delete the exception, or narrow it to the finding it was written for")
		v.WithContext("category", exception.Category)
		violations = append(violations, v)
	}
	return violations, nil
}

// ExceptionPlace is where stale-suppression reports an exception that
// matched no finding: the configuration file that declares it, relative to
// the configuration's directory, and the line that declares it.
type ExceptionPlace struct {
	File string
	Line int
}

// StaleExceptionPlaces returns the places stale-suppression reports the
// exceptions of the configuration at when they match no finding of a run of
// the executed rules, by name: an exception of stale-suppression excepts its
// findings there. A rule the run does not execute, one the configuration
// switches off among them, has none.
func StaleExceptionPlaces(cfg *core.Config, executed map[string]rules.Rule) ([]ExceptionPlace, error) {
	judged, err := judgedExceptions(cfg, func(ruleException *core.RuleException) bool {
		_, ran := executed[ruleException.Rule]
		return ran
	})
	if err != nil {
		return nil, err
	}
	places := make([]ExceptionPlace, 0, len(judged))
	for _, exception := range judged {
		places = append(places, exception.place)
	}
	return places, nil
}

// judgedException is an exception stale-suppression judges, at the place it
// reports it.
type judgedException struct {
	*core.RuleException
	place ExceptionPlace
}

// judgedExceptions returns the exceptions of the configuration that wanted
// accepts and stale-suppression judges: those of other rules - its own
// findings are filtered after this check, by the run - that name no file or
// a file a whole-root run analyzes, leaving to dead-config-exception those
// whose files do not exist.
func judgedExceptions(cfg *core.Config, wanted func(*core.RuleException) bool) ([]judgedException, error) {
	files, err := cfg.ConfigFiles()
	if err != nil {
		return nil, fmt.Errorf("list the files of the configuration's directory: %w", err)
	}
	nested, err := core.NestedRepositories(filepath.Dir(cfg.ConfigPath()))
	if err != nil {
		return nil, fmt.Errorf("find the nested repositories of the configuration's directory: %w", err)
	}
	var judged []judgedException
	exceptions := cfg.Exceptions()
	for i := range exceptions {
		ruleException := &exceptions[i]
		exc := ruleException.Exception
		if ruleException.Rule == staleSuppressionName || !wanted(ruleException) {
			continue
		}
		if exc.File != "" || exc.Files != "" {
			reached, err := reachedFile(files, exc, nested)
			if err != nil {
				return nil, err
			}
			if !reached {
				// The files do not exist, dead-config-exception's finding, or
				// lie in nested repositories, which only a run scoped to them
				// analyzes.
				continue
			}
		}
		source, err := filepath.Rel(filepath.Dir(cfg.ConfigPath()), exc.Source())
		if err != nil {
			return nil, fmt.Errorf("name configuration %q relative to its directory: %w", exc.Source(), err)
		}
		judged = append(judged, judgedException{RuleException: ruleException, place: ExceptionPlace{File: filepath.ToSlash(source), Line: exc.DeclaredAt()}})
	}
	return judged, nil
}

// reachedFile reports whether an exception names a file a whole-root run
// analyzes: one that exists outside the nested repositories.
func reachedFile(files []string, exc core.Exception, nested func(string) (bool, error)) (bool, error) {
	for _, file := range files {
		if !exc.CoversFile(file) {
			continue
		}
		inNested, err := nested(file)
		if err != nil {
			return false, err
		}
		if !inNested {
			return true, nil
		}
	}
	return false, nil
}

func (r *StaleSuppressionRule) markerViolation(ctx *core.FileContext, line int, message, suggestion string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(suggestion)
	return v
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
