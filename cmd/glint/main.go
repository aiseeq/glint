package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/fix"
	"github.com/aiseeq/glint/pkg/output"
	"github.com/aiseeq/glint/pkg/rules"

	// Rule packages - imported for init() registration
	_ "github.com/aiseeq/glint/pkg/rules/architecture"
	_ "github.com/aiseeq/glint/pkg/rules/deadcode"
	_ "github.com/aiseeq/glint/pkg/rules/doccheck"
	_ "github.com/aiseeq/glint/pkg/rules/duplication"
	_ "github.com/aiseeq/glint/pkg/rules/naming"
	_ "github.com/aiseeq/glint/pkg/rules/patterns"
	_ "github.com/aiseeq/glint/pkg/rules/security"
	_ "github.com/aiseeq/glint/pkg/rules/typesafety"
)

var version = "dev"

// resolveVersion prefers the version injected by graft build and falls back to the
// module version Go stamps into `go install`-built binaries — otherwise every
// binary a user installs from a pseudo-version reports itself as "dev" and
// there is no way to tell which commit they actually got. Explicit by-design
// fallback: "dev" survives only for builds that carry no version at all
// (plain `go build` in the repo).
func resolveVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

const (
	defaultFilePermissions = 0644
)

// CLI flags
var (
	flagCategory    string
	flagRule        string
	flagMinSeverity string
	flagOutput      string
	flagVerbose     bool
	flagDebug       bool
	flagNoColor     bool
	flagTolerant    bool
	flagTiming      bool
	flagCPUProfile  string
	flagNoCache     bool
	// Fix command flags
	flagDryRun  bool
	flagForce   bool
	flagFixRule string
)

// timings collects per-phase and per-rule durations under --timing; nil (the
// default) disables collection at every call site. A package-level variable,
// like the flags above, so the rule funnel does not grow a parameter that
// every test would have to pass.
var timings *timingCollector

func main() {
	if err := rootCmd.Execute(); err != nil {
		// Findings were already printed by the reporter; only real failures
		// need an error line.
		if !errors.Is(err, errFindingsReported) {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "glint",
	Short: "Glint - Unified Code Analyzer",
	Long: `Glint is a fast, configurable static analyzer for Go and TypeScript projects.
Originally built to help AI agents understand codebases.`,
	Version: resolveVersion(),
	// A failed analysis is not a usage mistake: printing the full help text
	// after every error buries the message that explains what went wrong.
	// main reports the error itself, so cobra must not print it a second time.
	SilenceUsage:  true,
	SilenceErrors: true,
}

var checkCmd = &cobra.Command{
	Use:   "check [paths...]",
	Short: "Analyze code for issues",
	Long:  "Analyze code in the specified paths (or current directory if none specified).",
	RunE:  runCheck,
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List available rules",
	RunE:  runRules,
}

var explainCmd = &cobra.Command{
	Use:   "explain <rule>",
	Short: "Explain a specific rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runExplain,
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize .glint.yaml configuration",
	RunE:  runInit,
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration commands",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show effective configuration",
	RunE:  runConfigShow,
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration",
	RunE:  runConfigValidate,
}

var fixCmd = &cobra.Command{
	Use:   "fix [paths...]",
	Short: "Auto-fix issues that have fixers available",
	Long: `Auto-fix issues that have fixers available.
By default runs in dry-run mode to show what would be fixed.
Use --dry-run=false to actually apply fixes.

Findings silenced by configuration exceptions or by inline suppression
comments are left alone, exactly as 'glint check' reports them.

Available fixers:
  - interface-any: Replace the empty interface type with any (Go 1.18+)
  - deprecated-ioutil: Replace io/ioutil with io/os
  - bool-compare: Simplify boolean comparisons (x == true -> x)
  - md-line-break, md-list-after-label: Markdown formatting`,
	RunE: runFix,
}

func init() {
	// Check command flags
	checkCmd.Flags().StringVarP(&flagCategory, "category", "c", "", "Run only specified category")
	checkCmd.Flags().StringVarP(&flagRule, "rule", "r", "", "Run only specified rule")
	checkCmd.Flags().StringVarP(&flagMinSeverity, "min-severity", "s", "", "Minimum severity (low, medium, high, critical)")
	// Empty default: a non-empty one would be indistinguishable from an
	// explicit -o and would override settings.output from the config.
	checkCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output format: console, json, summary (default from config, else console)")
	checkCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show analyzed files")
	checkCmd.Flags().BoolVar(&flagDebug, "debug", false, "Enable debug output")
	checkCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Disable colored output")
	checkCmd.Flags().BoolVar(&flagTolerant, "tolerate-broken-packages", false, "Analyze packages that type-check and report the ones that do not, instead of failing (for trees that do not compile as a whole)")
	checkCmd.Flags().BoolVar(&flagTiming, "timing", false, "Report per-rule timings to stderr; on Ctrl+C also names the rule and file still running")
	checkCmd.Flags().StringVar(&flagCPUProfile, "cpuprofile", "", "Write a CPU profile of the run to this file (go tool pprof)")
	checkCmd.Flags().BoolVar(&flagNoCache, "no-cache", false, "Analyze every file instead of reusing the findings of unchanged files from the previous run")

	// Rules command flags
	rulesCmd.Flags().StringVarP(&flagCategory, "category", "c", "", "Filter by category")

	// Config subcommands
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configValidateCmd)

	// Fix command flags
	fixCmd.Flags().BoolVar(&flagDryRun, "dry-run", true, "Show what would be fixed without applying (default: true)")
	fixCmd.Flags().BoolVar(&flagForce, "force", false, "Apply fixes even with uncommitted changes")
	fixCmd.Flags().StringVarP(&flagFixRule, "rule", "r", "", "Fix only specified rule")
	fixCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show detailed output")
	fixCmd.Flags().BoolVar(&flagTolerant, "tolerate-broken-packages", false, "Fix the packages that type-check and report the ones that do not, instead of failing")

	// Root commands
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(explainCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(fixCmd)
}

func runCheck(_ *cobra.Command, args []string) error {
	startTime := time.Now()

	if flagTiming {
		timings = newTimingCollector()
		stop := reportTimingsOnInterrupt(timings)
		defer stop()
	}
	if flagCPUProfile != "" {
		stop, err := startCPUProfile(flagCPUProfile)
		if err != nil {
			return err
		}
		defer stop()
	}

	projectRoots, err := getProjectRoots(args)
	if err != nil {
		return err
	}

	findings := newFindingSet()
	// Roots of one Go module share its typed load.
	loader := core.NewGoProjectLoader()
	analyzedFiles := make(map[string]struct{})
	var stats output.Stats
	outputFormat := ""
	// Different roots can enable different rule sets; the reported count is
	// how many distinct rules ran overall.
	rulesRun := make(map[string]struct{})

	for _, projectRoot := range projectRoots {
		cfg, enabledRules, err := loadConfig(projectRoot)
		if err != nil {
			return err
		}

		if len(enabledRules) == 0 {
			return fmt.Errorf("no rules enabled for %s — every category is disabled in the configuration", projectRoot)
		}
		if outputFormat == "" {
			outputFormat = cfg.Settings.Output
		}

		loadDone := timings.phase("load " + projectRoot)
		contexts, walker, project, err := prepareAnalysis(loader, projectRoot, cfg, enabledRules)
		loadDone()
		if err != nil {
			return err
		}

		// Rules are process-wide singletons: cross-file state from a previous
		// root must not influence this one.
		rules.ResetState(enabledRules)

		cache := openRootCache(projectRoot, cfg, project != nil)
		analyzeDone := timings.phase("analyze " + projectRoot)
		violations, err := analyzeProject(contexts, enabledRules, cfg, project, cache)
		analyzeDone()
		if err != nil {
			return err
		}
		if cache != nil {
			if err := cache.save(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: result cache of %s not saved: %v\n", projectRoot, err)
			}
			if flagTiming {
				fmt.Fprintf(os.Stderr, "result cache %s: %d of %d files unchanged\n", projectRoot, cache.reused, len(contexts))
			}
		}
		minSeverity, err := cfg.GetMinSeverity()
		if err != nil {
			return err
		}
		findings.add(projectRoot, violations.BySeverity(minSeverity))

		for _, ctx := range contexts {
			analyzedFiles[ctx.Path] = struct{}{}
		}
		stats.FilesSkipped += walker.Stats().SkippedFiles
		if project != nil {
			stats.PackagesSkipped += len(project.SkippedPackages)
		}
		for _, rule := range enabledRules {
			rulesRun[rule.Name()] = struct{}{}
		}
	}
	stats.RulesRun = len(rulesRun)
	// Overlapping roots (./backend and ./backend/auth) walk the same file twice.
	stats.FilesAnalyzed = len(analyzedFiles)
	allViolations := findings.list
	stats.Duration = time.Since(startTime).Seconds()
	if err := timings.report(os.Stderr); err != nil {
		return fmt.Errorf("write timing report: %w", err)
	}

	if err := outputResults(outputFormat, allViolations, stats); err != nil {
		return fmt.Errorf("output error: %w", err)
	}

	if shouldFailAnalysis(allViolations) {
		return errFindingsReported
	}

	return nil
}

// errFindingsReported signals that the analysis itself succeeded but reported
// findings severe enough to fail the run. Returning it instead of calling
// os.Exit keeps the exit path in one place and lets cobra unwind normally.
var errFindingsReported = errors.New("findings at or above high severity")

// findingSet collects the findings of every analyzed root and drops the ones
// that overlapping roots (./backend and ./backend/auth) report twice. A
// finding's File is relative to the root that produced it, so identity is
// keyed on the absolute path: the same file reached from two roots has two
// different relative names. The message is part of the identity: one rule can
// legitimately report several distinct problems on the same line.
type findingSet struct {
	seen map[findingKey]struct{}
	list core.ViolationList
}

type findingKey struct {
	file    string
	line    int
	column  int
	rule    string
	message string
}

func newFindingSet() *findingSet {
	return &findingSet{seen: make(map[findingKey]struct{})}
}

// add records the findings of one root; the first root to report a finding
// keeps it, with its own relative path.
func (s *findingSet) add(root string, violations core.ViolationList) {
	for _, violation := range violations {
		file := violation.File
		if !filepath.IsAbs(file) {
			file = filepath.Join(root, file)
		}
		k := findingKey{
			file:    file,
			line:    violation.Line,
			column:  violation.Column,
			rule:    violation.Rule,
			message: violation.Message,
		}
		if _, ok := s.seen[k]; ok {
			continue
		}
		s.seen[k] = struct{}{}
		s.list = append(s.list, violation)
	}
}

func getProjectRoots(args []string) ([]string, error) {
	paths := args
	if len(paths) == 0 {
		paths = []string{"."}
	}

	roots := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		root, err := resolveProjectRoot(path)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}
	return roots, nil
}

// resolveProjectRoot turns a path argument into an absolute directory. A Go
// package pattern ("./...", "./internal/...") names the directory it starts
// from: glint always walks a root recursively.
func resolveProjectRoot(path string) (string, error) {
	projectRoot := path
	if projectRoot == "..." {
		projectRoot = "."
	}
	projectRoot = strings.TrimSuffix(projectRoot, "/...")
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		return "", fmt.Errorf("make project root %q absolute: %w", projectRoot, err)
	}
	projectRoot = filepath.Clean(absRoot)
	info, err := os.Stat(projectRoot)
	if err != nil {
		return "", fmt.Errorf("invalid project root %q: %w", projectRoot, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("invalid project root %q: not a directory", projectRoot)
	}
	return projectRoot, nil
}

func loadConfig(projectRoot string) (*core.Config, []rules.Rule, error) {
	cfg, err := core.LoadConfigWithDefaults(projectRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load config: %w", err)
	}

	if flagMinSeverity != "" {
		cfg.Settings.MinSeverity = flagMinSeverity
	}
	if flagOutput != "" {
		cfg.Settings.Output = flagOutput
	}
	// Command-line values go through the same validation as the file: an
	// unknown -o must not quietly fall back to the console report.
	if err := cfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid configuration: %w", err)
	}
	if err := rules.ValidateConfig(cfg); err != nil {
		return nil, nil, fmt.Errorf("invalid configuration: %w", err)
	}

	if err := rules.ConfigureAll(cfg); err != nil {
		return nil, nil, fmt.Errorf("failed to configure rules: %w", err)
	}

	enabledRules, err := getEnabledRules(cfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, enabledRules, nil
}

// getEnabledRules resolves the rule set for this run. An unknown --rule or
// --category is an error: silently falling back to "all rules" made glint
// report findings the caller never asked for.
func getEnabledRules(cfg *core.Config) ([]rules.Rule, error) {
	enabledRules := rules.GetEnabled(cfg)

	if flagCategory != "" {
		categoryRules := rules.GetByCategory(flagCategory)
		if len(categoryRules) == 0 {
			return nil, fmt.Errorf("unknown category %q; known categories: %s",
				flagCategory, strings.Join(rules.Categories(), ", "))
		}
		// Asking for a category runs it even if the configuration switched
		// the category off, but a rule the configuration disabled by name
		// stays off: it was disabled for a reason the flag does not revisit.
		enabledRules = enabledRules[:0:0]
		for _, rule := range categoryRules {
			if !cfg.IsRuleDisabled(rule.Category(), rule.Name()) {
				enabledRules = append(enabledRules, rule)
			}
		}
	}

	if flagRule != "" {
		rule, ok := rules.Get(flagRule)
		if !ok {
			return nil, fmt.Errorf("unknown rule %q; run 'glint rules' to list them", flagRule)
		}
		if flagDebug {
			fmt.Printf("DEBUG: Found rule %s in category %s\n", rule.Name(), rule.Category())
		}
		enabledRules = []rules.Rule{rule}
	}

	if flagVerbose {
		fmt.Printf("Running %d rules...\n", len(enabledRules))
	}

	return enabledRules, nil
}

func walkWithWalker(walker *core.Walker) ([]*core.FileContext, *core.Walker, error) {
	contexts, walkErrors := walker.WalkSync()
	sort.Slice(contexts, func(i, j int) bool { return contexts[i].Path < contexts[j].Path })

	if flagVerbose {
		stats := walker.Stats()
		fmt.Printf("Found %d files to analyze\n", stats.TotalFiles)
	}

	if len(walkErrors) > 0 {
		// Несогласованное дерево (исторический срез, битый симлинк, файл без
		// прав) не должно останавливать анализ целиком: под флагом файлы,
		// которые не читаются, называются и пропускаются.
		if !flagTolerant {
			return nil, walker, fmt.Errorf("walk project files: %w", errors.Join(walkErrors...))
		}
		fmt.Fprintf(os.Stderr, "Skipped %d unreadable file(s)\n", len(walkErrors))
		if flagVerbose {
			for _, walkErr := range walkErrors {
				fmt.Fprintf(os.Stderr, "  %v\n", walkErr)
			}
		}
	}

	return contexts, walker, nil
}

func prepareAnalysis(loader *core.GoProjectLoader, projectRoot string, cfg *core.Config, enabledRules []rules.Rule) ([]*core.FileContext, *core.Walker, *core.GoProjectContext, error) {
	projectRuleCount := 0
	requireSSA := false
	for _, rule := range enabledRules {
		projectRule, ok := rule.(rules.GoProjectRule)
		if !ok {
			continue
		}
		projectRuleCount++
		requireSSA = requireSSA || projectRule.RequiresSSA()
	}

	walker := core.NewWalker(projectRoot, cfg).WithGoParsing(projectRuleCount == 0)
	contexts, walker, err := walkWithWalker(walker)
	if err != nil {
		return nil, walker, nil, err
	}
	// Дерево без Go-файлов (например, frontend): Go-project правилам нечего
	// анализировать, а загрузка Go-контекста упала бы с "no packages found".
	if projectRuleCount == 0 || !hasGoFiles(contexts) {
		return contexts, walker, nil, nil
	}
	project, err := loader.Load(projectRoot, contexts, core.GoProjectOptions{
		RequireSSA:             requireSSA,
		TolerateBrokenPackages: flagTolerant,
	})
	if err != nil {
		return nil, walker, nil, fmt.Errorf("load Go project context: %w", err)
	}
	reportSkippedPackages(project, cfg.Settings.Output)
	return contexts, walker, project, nil
}

// reportSkippedPackages keeps a tolerated load honest: whatever was left out of
// typed analysis is named, so findings are never read as full coverage.
func reportSkippedPackages(project *core.GoProjectContext, outputFormat string) {
	if project == nil || len(project.SkippedPackages) == 0 {
		return
	}
	if outputFormat == "json" {
		return
	}
	fmt.Fprintf(os.Stderr, "Skipped %d package(s) that do not type-check; their files are analyzed without type information\n", len(project.SkippedPackages))
	if !flagVerbose {
		return
	}
	for _, pkg := range project.SkippedPackages {
		fmt.Fprintf(os.Stderr, "  %s: %s\n", pkg.PkgPath, pkg.Reason)
	}
}

func shouldFailAnalysis(violations core.ViolationList) bool {
	for _, violation := range violations {
		if violation.Severity >= core.SeverityHigh {
			return true
		}
	}
	return false
}

// severityOverrides maps a rule name to the severity configured for it. It is
// resolved once per project root so that analysis never has to parse — and
// never has to silently ignore — a severity string.
type severityOverrides map[string]core.Severity

func buildSeverityOverrides(cfg *core.Config, enabledRules []rules.Rule) (severityOverrides, error) {
	overrides := make(severityOverrides)
	for _, rule := range enabledRules {
		severity, ok, err := cfg.SeverityOverrideFor(rule.Category(), rule.Name())
		if err != nil {
			return nil, fmt.Errorf("severity for rule %q: %w", rule.Name(), err)
		}
		if ok {
			overrides[rule.Name()] = severity
		}
	}
	return overrides, nil
}

// apply overrides the violation's severity when the configuration asks for it.
func (o severityOverrides) apply(violation *core.Violation) {
	if severity, ok := o[violation.Rule]; ok {
		violation.Severity = severity
	}
}

// analyzeFiles runs every rule over every file. Stateless rules run in
// parallel across files; rules that accumulate cross-file state run in a fixed
// file order afterwards. Findings are collected per (file, rule) and only then
// flattened, so the output does not depend on scheduling.
// analyzeFiles runs the file rules. With a cache, an unchanged file gets the
// stored findings of its file-local rules back, and every file's findings are
// stored for the next run.
func analyzeFiles(contexts []*core.FileContext, enabledRules []rules.Rule, cfg *core.Config, overrides severityOverrides, cache *resultCache) (core.ViolationList, error) {
	if len(contexts) == 0 || len(enabledRules) == 0 {
		return nil, nil
	}

	stateful := make([]bool, len(enabledRules))
	statefulCount := 0
	for i, rule := range enabledRules {
		if _, ok := rule.(rules.StatefulRule); ok {
			stateful[i] = true
			statefulCount++
		}
	}

	found := make([][]core.ViolationList, len(contexts))
	for i := range found {
		found[i] = make([]core.ViolationList, len(enabledRules))
	}
	failures := make([]error, len(contexts))

	local := fileLocalRules(enabledRules)
	var contents [][sha256.Size]byte
	var reuse []map[string][]core.Violation
	if cache != nil {
		contents = make([][sha256.Size]byte, len(contexts))
		reuse = make([]map[string][]core.Violation, len(contexts))
		for i, ctx := range contexts {
			contents[i] = sha256.Sum256(ctx.Content)
			reuse[i] = cache.lookup(ctx.RelPath, contents[i])
		}
	}

	if statefulCount < len(enabledRules) {
		run := statelessRun{rules: enabledRules, stateful: stateful, local: local, reuse: reuse, cfg: cfg, overrides: overrides}
		run.execute(contexts, found, failures)
	}
	if statefulCount > 0 {
		for fileIndex, ctx := range contexts {
			for ruleIndex, rule := range enabledRules {
				if !stateful[ruleIndex] {
					continue
				}
				violations, err := runRule(ctx, rule, cfg, overrides)
				found[fileIndex][ruleIndex] = violations
				failures[fileIndex] = errors.Join(failures[fileIndex], err)
			}
		}
	}
	if err := errors.Join(failures...); err != nil {
		return nil, err
	}
	if cache != nil {
		for fileIndex, ctx := range contexts {
			cache.storeFile(ctx.RelPath, contents[fileIndex], enabledRules, local, found[fileIndex], reuse[fileIndex])
		}
	}

	var allViolations core.ViolationList
	for _, perRule := range found {
		for _, violations := range perRule {
			allViolations = append(allViolations, violations...)
		}
	}
	return allViolations, nil
}

// statelessRun is one pass of the stateless file rules. reuse, when set,
// holds per file the cached findings by rule name; a file-local rule found
// there is not run.
type statelessRun struct {
	rules     []rules.Rule
	stateful  []bool
	local     []bool
	reuse     []map[string][]core.Violation
	cfg       *core.Config
	overrides severityOverrides
}

// execute spreads the files over a worker per CPU. Each worker owns its own
// row of the result matrix, so no synchronization is needed beyond the wait
// group.
func (s statelessRun) execute(contexts []*core.FileContext, found [][]core.ViolationList, failures []error) {
	workers := runtime.NumCPU()
	if workers > len(contexts) {
		workers = len(contexts)
	}
	if workers < 1 {
		workers = 1
	}

	var next atomic.Int64
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				fileIndex := int(next.Add(1)) - 1
				if fileIndex >= len(contexts) {
					return
				}
				for ruleIndex, rule := range s.rules {
					if s.stateful[ruleIndex] {
						continue
					}
					if s.local[ruleIndex] && s.reuse != nil {
						if stored, ok := s.reuse[fileIndex][rule.Name()]; ok {
							found[fileIndex][ruleIndex] = cachedViolations(stored)
							continue
						}
					}
					violations, err := runRule(contexts[fileIndex], rule, s.cfg, s.overrides)
					found[fileIndex][ruleIndex] = violations
					failures[fileIndex] = errors.Join(failures[fileIndex], err)
				}
			}
		}()
	}
	wg.Wait()
}

// runRule applies one rule to one file and filters the findings the same way
// for every caller: generated files, rule exceptions, inline suppression,
// severity overrides. A panicking rule fails the run with the rule and the
// file named, instead of a bare stack trace from a worker goroutine.
func runRule(ctx *core.FileContext, rule rules.Rule, cfg *core.Config, overrides severityOverrides) (kept core.ViolationList, err error) {
	if cfg.IsFileExcepted(rule.Category(), rule.Name(), ctx.RelPath) || ctx.IsGenerated() {
		return nil, nil
	}

	defer timings.track(rule.Name(), ctx.RelPath)()
	defer func() {
		if recovered := recover(); recovered != nil {
			kept = nil
			err = fmt.Errorf("rule %q panicked on %s: %v\n%s", rule.Name(), ctx.RelPath, recovered, debug.Stack())
		}
	}()
	violations := rule.AnalyzeFile(ctx)
	if len(violations) == 0 {
		return nil, nil
	}

	honorsSuppression := rules.HonorsSuppression(rule)
	kept = make(core.ViolationList, 0, len(violations))
	for _, violation := range violations {
		ctx.AnnotateFunction(violation)
		if cfg.IsViolationExcepted(rule.Category(), rule.Name(), ctx.RelPath, violation) {
			continue
		}
		if honorsSuppression && ctx.IsSuppressed(violation.Line, rule.Name()) {
			continue
		}
		overrides.apply(violation)
		kept = append(kept, violation)
	}
	return kept, nil
}

func hasGoFiles(contexts []*core.FileContext) bool {
	for _, ctx := range contexts {
		if ctx != nil && ctx.IsGoFile() {
			return true
		}
	}
	return false
}

func analyzeProject(contexts []*core.FileContext, enabledRules []rules.Rule, cfg *core.Config, project *core.GoProjectContext, cache *resultCache) (core.ViolationList, error) {
	overrides, err := buildSeverityOverrides(cfg, enabledRules)
	if err != nil {
		return nil, err
	}

	var allViolations core.ViolationList
	fileRules := make([]rules.Rule, 0, len(enabledRules))
	for _, rule := range enabledRules {
		projectRule, ok := rule.(rules.GoProjectRule)
		if !ok {
			fileRules = append(fileRules, rule)
			continue
		}
		if project == nil {
			if !hasGoFiles(contexts) {
				// Дерево без Go-файлов: Go-project правилам нечего анализировать.
				continue
			}
			return nil, fmt.Errorf("analyze Go project with rule %q: project context is nil", rule.Name())
		}
		violations, err := runProjectRule(projectRule, project)
		if err != nil {
			return nil, fmt.Errorf("analyze Go project with rule %q: %w", rule.Name(), err)
		}
		for _, violation := range violations {
			if violation == nil {
				return nil, fmt.Errorf("analyze Go project with rule %q: nil violation", rule.Name())
			}
			fileCtx, err := project.File(violation.File)
			if err != nil {
				return nil, fmt.Errorf("map finding from Go project rule %q: %w", rule.Name(), err)
			}
			fileCtx.AnnotateFunction(violation)
			if fileCtx.IsGenerated() ||
				cfg.IsFileExcepted(rule.Category(), rule.Name(), fileCtx.RelPath) ||
				cfg.IsViolationExcepted(rule.Category(), rule.Name(), fileCtx.RelPath, violation) ||
				(rules.HonorsSuppression(rule) && fileCtx.IsSuppressed(violation.Line, rule.Name())) {
				continue
			}
			violation.File = fileCtx.RelPath
			overrides.apply(violation)
			allViolations = append(allViolations, violation)
		}
	}
	fileViolations, err := analyzeFiles(contexts, fileRules, cfg, overrides, cache)
	if err != nil {
		return nil, err
	}
	return append(allViolations, fileViolations...), nil
}

// runProjectRule runs one Go project rule; a panic becomes an error that names
// the rule.
func runProjectRule(rule rules.GoProjectRule, project *core.GoProjectContext) (violations []*core.Violation, err error) {
	defer timings.track(rule.Name(), "(go project)")()
	defer func() {
		if recovered := recover(); recovered != nil {
			violations = nil
			err = fmt.Errorf("panic: %v\n%s", recovered, debug.Stack())
		}
	}()
	return rule.AnalyzeGoProject(project)
}

func outputResults(format string, violations core.ViolationList, stats output.Stats) error {
	switch format {
	case "json":
		out := output.NewJSONOutput().WithWriter(os.Stdout)
		return out.Write(violations, stats)
	case "summary":
		out := output.NewSummaryOutput().WithWriter(os.Stdout)
		return out.Write(violations, stats)
	case "console", "":
		out := output.NewConsoleOutput().
			WithWriter(os.Stdout).
			WithNoColor(flagNoColor)
		return out.Write(violations, stats)
	default:
		return fmt.Errorf("unknown output format %q (known: %s)", format, strings.Join(core.OutputFormats, ", "))
	}
}

func runRules(_ *cobra.Command, _ []string) error {
	allRules := rules.All()

	if flagCategory != "" {
		allRules = rules.GetByCategory(flagCategory)
	}

	if len(allRules) == 0 {
		fmt.Println("No rules found.")
		return nil
	}

	fmt.Println("AVAILABLE RULES")
	fmt.Println("===============")
	fmt.Println()

	currentCategory := ""
	for _, r := range allRules {
		if r.Category() != currentCategory {
			currentCategory = r.Category()
			fmt.Printf("\n[%s]\n", currentCategory)
		}

		info := rules.GetRuleInfo(r)
		autofix := ""
		// fix.DefaultRegistry is the authority on auto-fix: a rule-side
		// interface check used to mark 1 of the 7 fixable rules.
		if _, ok := fix.DefaultRegistry.Get(info.Name); ok {
			autofix = " (auto-fix)"
		}

		fmt.Printf("  %-20s %s [%s]%s\n",
			info.Name,
			info.Description,
			info.Severity.Label(),
			autofix,
		)
	}

	fmt.Printf("\nTotal: %d rules\n", len(allRules))
	return nil
}

func runExplain(_ *cobra.Command, args []string) error {
	ruleName := args[0]

	rule, ok := rules.Get(ruleName)
	if !ok {
		return fmt.Errorf("unknown rule: %s", ruleName)
	}

	info := rules.GetRuleInfo(rule)

	fmt.Printf("RULE: %s\n", info.Name)
	fmt.Printf("CATEGORY: %s\n", info.Category)
	fmt.Printf("SEVERITY: %s\n", info.Severity.Label())
	if _, ok := fix.DefaultRegistry.Get(info.Name); ok {
		fmt.Println("AUTO-FIX: Available")
	}
	fmt.Println()
	fmt.Println("DESCRIPTION:")
	fmt.Printf("  %s\n", info.Description)

	return nil
}

func runInit(_ *cobra.Command, _ []string) error {
	var b strings.Builder
	b.WriteString(`# Glint configuration
# See: https://github.com/aiseeq/glint

version: 1

settings:
  exclude:
    - vendor/**
    - node_modules/**
    - "**/*_test.go"
  min_severity: medium
  output: console

categories:
`)
	// The registry is the authority on categories; a hardcoded list here went
	// stale (it named a nonexistent "config" and knew nothing of security).
	for _, category := range rules.Categories() {
		fmt.Fprintf(&b, "  %s:\n    enabled: true\n", category)
	}
	configContent := b.String()

	filename := ".glint.yaml"
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("%s already exists", filename)
	}

	if err := os.WriteFile(filename, []byte(configContent), defaultFilePermissions); err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}

	fmt.Printf("Created %s\n", filename)
	return nil
}

func runConfigShow(_ *cobra.Command, _ []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	cfg, err := core.LoadConfigWithDefaults(cwd)
	if err != nil {
		return err
	}

	fmt.Println("Effective configuration:")
	fmt.Println()
	fmt.Printf("Min severity: %s\n", cfg.Settings.MinSeverity)
	fmt.Printf("Output: %s\n", cfg.Settings.Output)
	fmt.Println()
	fmt.Println("Excluded patterns:")
	for _, p := range cfg.Settings.Exclude {
		fmt.Printf("  - %s\n", p)
	}
	fmt.Println()
	fmt.Println("Categories:")
	names := make([]string, 0, len(cfg.Categories))
	for name := range cfg.Categories {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		status := "enabled"
		if !cfg.Categories[name].Enabled {
			status = "disabled"
		}
		fmt.Printf("  %s: %s\n", name, status)
	}

	return nil
}

func runConfigValidate(_ *cobra.Command, _ []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	configPath, err := core.FindConfig(cwd)
	if err != nil {
		return err
	}

	if configPath == "" {
		fmt.Println("No configuration file found")
		return nil
	}

	cfg, err := core.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if err := rules.ValidateConfig(cfg); err != nil {
		return fmt.Errorf("invalid configuration %q: %w", configPath, err)
	}

	fmt.Printf("Configuration valid: %s\n", configPath)
	return nil
}

func runFix(_ *cobra.Command, args []string) error {
	projectRoots, err := getProjectRoots(args)
	if err != nil {
		return err
	}

	if flagFixRule != "" {
		if _, ok := rules.Get(flagFixRule); !ok {
			return fmt.Errorf("unknown rule %q; run 'glint rules' to list them", flagFixRule)
		}
	}

	for _, projectRoot := range projectRoots {
		if err := fixProjectRoot(projectRoot); err != nil {
			return err
		}
	}
	return nil
}

func fixProjectRoot(projectRoot string) error {
	// Whether this root is fixed in place is decided per root: a dirty working
	// tree here must not silence the fixes for the roots that follow.
	dryRun := flagDryRun
	state, err := fix.NewEngine(fix.DefaultRegistry, dryRun).CheckWorkingTree(projectRoot)
	if err != nil {
		return fmt.Errorf("check working tree: %w", err)
	}

	if !dryRun && !flagForce {
		switch state {
		case fix.WorkingTreeDirty:
			fmt.Printf("WARNING: %s has uncommitted changes.\n", projectRoot)
			fmt.Println("Use --force to apply fixes anyway, or commit your changes first.")
			fmt.Println("Running in dry-run mode instead.")
			dryRun = true
		case fix.WorkingTreeUntracked:
			fmt.Printf("WARNING: %s is not inside a git repository — fixes could not be reverted.\n", projectRoot)
			fmt.Println("Use --force to apply fixes anyway.")
			fmt.Println("Running in dry-run mode instead.")
			dryRun = true
		case fix.WorkingTreeClean:
		}
	}
	engine := fix.NewEngine(fix.DefaultRegistry, dryRun)

	// Load config and get enabled rules
	cfg, enabledRules, err := loadConfig(projectRoot)
	if err != nil {
		return err
	}

	// Filter to only rules that have fixers
	var fixableRules []rules.Rule
	for _, r := range enabledRules {
		if flagFixRule != "" && r.Name() != flagFixRule {
			continue
		}
		if _, ok := fix.DefaultRegistry.Get(r.Name()); ok {
			fixableRules = append(fixableRules, r)
		}
	}

	if len(fixableRules) == 0 {
		if flagFixRule != "" {
			fmt.Printf("No fixer available for rule: %s\n", flagFixRule)
		} else {
			fmt.Println("No fixable rules enabled.")
		}
		return nil
	}

	if flagVerbose {
		fmt.Printf("Running %d fixable rules...\n", len(fixableRules))
	}

	if dryRun {
		fixes, err := collectFixes(projectRoot, cfg, fixableRules, engine)
		if err != nil || len(fixes) == 0 {
			return err
		}
		fmt.Print(engine.Preview(fixes))
		return nil
	}
	return applyFixesUntilStable(projectRoot, cfg, fixableRules, engine)
}

// maxFixPasses bounds the analyze-and-fix loop. A fix that overlaps another
// one is deferred to the next pass; a chain longer than this means the fixers
// keep producing work and the run must say so rather than stop silently.
const maxFixPasses = 5

// applyFixesUntilStable applies fixes, analyzes the fixed files again and
// repeats while a pass still applies something: overlapping fixes are deferred
// by the engine and only the fresh analysis of the changed text finds them anew.
func applyFixesUntilStable(projectRoot string, cfg *core.Config, fixableRules []rules.Rule, engine *fix.Engine) error {
	totalFixed := 0
	fixedFiles := make(map[string]struct{})
	for pass := 1; pass <= maxFixPasses; pass++ {
		fixes, err := collectFixes(projectRoot, cfg, fixableRules, engine)
		if err != nil {
			return err
		}
		if len(fixes) == 0 {
			if pass > 1 {
				fmt.Printf("\nApplied %d fixes in %d files.\n", totalFixed, len(fixedFiles))
			}
			return nil
		}
		if pass == 1 {
			fmt.Print(engine.Preview(fixes))
		}

		applied, deferred := 0, 0
		var failures []error
		results := engine.ApplyFixes(fixes)
		for _, result := range results {
			deferred += len(result.Deferred)
			if result.Error != nil {
				failures = append(failures, fmt.Errorf("fix %s: %w", result.File, result.Error))
				continue
			}
			if result.FixesApplied > 0 {
				applied += result.FixesApplied
				fixedFiles[result.File] = struct{}{}
				if flagVerbose {
					fmt.Printf("Fixed %d issues in %s\n", result.FixesApplied, result.File)
				}
			}
		}
		totalFixed += applied
		if len(failures) > 0 {
			fmt.Printf("\nApplied %d fixes in %d files.\n", totalFixed, len(fixedFiles))
			return fmt.Errorf("%d of %d files could not be fixed: %w", len(failures), len(results), errors.Join(failures...))
		}
		if deferred == 0 {
			fmt.Printf("\nApplied %d fixes in %d files.\n", totalFixed, len(fixedFiles))
			return nil
		}
		if applied == 0 {
			return fmt.Errorf("%d overlapping fixes could not be applied", deferred)
		}
		if flagVerbose {
			fmt.Printf("%d overlapping fixes deferred to pass %d\n", deferred, pass+1)
		}
	}
	fmt.Printf("\nApplied %d fixes in %d files.\n", totalFixed, len(fixedFiles))
	return fmt.Errorf("fixes still overlapping after %d passes; run glint fix again", maxFixPasses)
}

// collectFixes analyzes the root through the same pipeline as `check` — project
// rules run, configuration exceptions and inline suppressions are honored — and
// returns the fixes for what it finds. Files are read afresh on every call.
func collectFixes(projectRoot string, cfg *core.Config, fixableRules []rules.Rule, engine *fix.Engine) ([]*fix.Fix, error) {
	contexts, _, project, err := prepareAnalysis(core.NewGoProjectLoader(), projectRoot, cfg, fixableRules)
	if err != nil {
		return nil, err
	}
	contextMap := make(map[string]*core.FileContext, 2*len(contexts))
	for _, ctx := range contexts {
		contextMap[ctx.Path] = ctx
		contextMap[ctx.RelPath] = ctx
	}

	rules.ResetState(fixableRules)
	violations, err := analyzeProject(contexts, fixableRules, cfg, project, nil)
	if err != nil {
		return nil, err
	}
	if len(violations) == 0 {
		fmt.Println("No issues found that can be fixed.")
		return nil, nil
	}
	fixes := engine.GenerateFixes(violations, contextMap)
	if len(fixes) == 0 {
		fmt.Println("No automatic fixes available for the found issues.")
	}
	return fixes, nil
}
