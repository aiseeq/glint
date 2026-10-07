package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
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
	"github.com/aiseeq/glint/pkg/rules/deadcode"
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
	flagRules       []string
	flagMinSeverity string
	flagOutput      string
	flagVerbose     bool
	flagDebug       bool
	flagNoColor     bool
	flagTolerant    bool
	flagJobs        int
	flagTiming      bool
	flagCPUProfile  string
	flagNoCache     bool
	// Fix command flags
	flagDryRun   bool
	flagForce    bool
	flagFixRules []string
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
	checkCmd.Flags().StringSliceVarP(&flagRules, "rule", "r", nil, "Run only the specified rules (repeat the flag or separate names with commas)")
	checkCmd.Flags().StringVarP(&flagMinSeverity, "min-severity", "s", "", "Minimum severity (low, medium, high, critical)")
	// Empty default: a non-empty one would be indistinguishable from an
	// explicit -o and would override settings.output from the config.
	checkCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output format: console, json, summary (default from config, else console)")
	checkCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show analyzed files")
	checkCmd.Flags().BoolVar(&flagDebug, "debug", false, "Enable debug output")
	checkCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Disable colored output")
	checkCmd.Flags().IntVarP(&flagJobs, "jobs", "j", defaultJobs, "Threads the run may use (type checking and the rules)")
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
	fixCmd.Flags().StringSliceVarP(&flagFixRules, "rule", "r", nil, "Fix only the specified rules (repeat the flag or separate names with commas)")
	fixCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show detailed output")
	fixCmd.Flags().IntVarP(&flagJobs, "jobs", "j", defaultJobs, "Threads the run may use (type checking and the rules)")
	fixCmd.Flags().BoolVar(&flagTolerant, "tolerate-broken-packages", false, "Fix the packages that type-check and report the ones that do not, instead of failing")

	// Root commands
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(explainCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(fixCmd)
}

// defaultJobs is how many threads a run takes unless --jobs says otherwise:
// glint runs in gates next to builds and tests on a shared machine, and every
// CPU at once slows them down for little gain.
const defaultJobs = 4

// applyJobs limits the run to --jobs threads: GOMAXPROCS bounds type checking,
// and the walker and the rule workers size their pools by it.
func applyJobs() error {
	if flagJobs < 1 {
		return fmt.Errorf("--jobs must be at least 1, got %d", flagJobs)
	}
	runtime.GOMAXPROCS(flagJobs)
	return nil
}

func runCheck(_ *cobra.Command, args []string) error {
	startTime := time.Now()
	if err := applyJobs(); err != nil {
		return err
	}

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

	roots, err := analysisRoots(args)
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
	// The configurations of the roots whose rules include the dead
	// exception check, by file: each is checked once.
	deadCheckConfigs := make(map[string]*core.Config)
	var deadRule *deadcode.DeadConfigExceptionRule

	for _, root := range roots {
		projectRoot := root.dir
		cfg, enabledRules, err := loadConfig(projectRoot)
		if err != nil {
			return err
		}
		for _, rule := range enabledRules {
			if dead, ok := rule.(*deadcode.DeadConfigExceptionRule); ok && cfg.ConfigPath() != "" {
				deadRule = dead
				deadCheckConfigs[cfg.ConfigPath()] = cfg
			}
		}

		if len(enabledRules) == 0 {
			return fmt.Errorf("no rules enabled for %s — every category is disabled in the configuration", projectRoot)
		}
		if outputFormat == "" {
			outputFormat = cfg.Settings.Output
		}

		loadDone := timings.phase("load " + projectRoot)
		prepared, err := prepareScopedAnalysis(loader, root, cfg, enabledRules, !flagNoCache)
		loadDone()
		if err != nil {
			return err
		}
		contexts, cache := prepared.contexts, prepared.cache

		// Rules are process-wide singletons: cross-file state from a previous
		// root must not influence this one.
		rules.ResetState(enabledRules)

		analyzeDone := timings.phase("analyze " + projectRoot)
		violations, err := analyzeProject(contexts, enabledRules, cfg, prepared.project, cache)
		analyzeDone()
		if err != nil {
			return err
		}
		if cache != nil {
			if err := cache.save(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: result cache of %s not saved: %v\n", projectRoot, err)
			}
			if flagTiming {
				fmt.Fprintf(os.Stderr, "result cache %s: %d of %d files unchanged, project rules %s\n",
					projectRoot, cache.reused, len(contexts), cache.projectState())
			}
		}
		violations, suppressions := core.SplitSuppressions(violations)
		stale, err := staleSuppressions(enabledRules, deadcode.StaleSuppressionRun{
			Contexts: contexts, Suppressions: suppressions, Config: cfg, WholeRoot: root.wholeRoot(),
		})
		if err != nil {
			return err
		}
		violations = append(violations, stale...)
		minSeverity, err := cfg.GetMinSeverity()
		if err != nil {
			return err
		}
		findings.add(projectRoot, violations.BySeverity(minSeverity))

		for _, ctx := range contexts {
			analyzedFiles[ctx.Path] = struct{}{}
		}
		stats.FilesSkipped += prepared.walker.Stats().SkippedFiles
		stats.PackagesSkipped += len(prepared.skipped)
		for _, rule := range enabledRules {
			rulesRun[rule.Name()] = struct{}{}
		}
	}
	if err := addDeadExceptions(findings, deadRule, deadCheckConfigs); err != nil {
		return err
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

// staleSuppressions runs the stale-suppression check over one analyzed root
// when it is among the enabled rules, and filters its findings like any rule's.
func staleSuppressions(enabledRules []rules.Rule, run deadcode.StaleSuppressionRun) (core.ViolationList, error) {
	var check *deadcode.StaleSuppressionRule
	run.Executed = make(map[string]rules.Rule, len(enabledRules))
	for _, rule := range enabledRules {
		run.Executed[rule.Name()] = rule
		if stale, ok := rule.(*deadcode.StaleSuppressionRule); ok {
			check = stale
		}
	}
	if check == nil {
		return nil, nil
	}
	found, err := check.Check(run)
	if err != nil {
		return nil, fmt.Errorf("check stale suppressions: %w", err)
	}
	overrides, err := buildSeverityOverrides(run.Config, []rules.Rule{check})
	if err != nil {
		return nil, err
	}
	contexts := make(map[string]*core.FileContext, len(run.Contexts))
	for _, ctx := range run.Contexts {
		contexts[ctx.RelPath] = ctx
	}
	var kept core.ViolationList
	for _, violation := range found {
		if run.Config.IsFileExcepted(check.Category(), check.Name(), violation.File) ||
			run.Config.IsViolationExcepted(check.Category(), check.Name(), violation.File, violation) {
			continue
		}
		if ctx, ok := contexts[violation.File]; ok && ctx.IsSuppressed(violation.Line, check.Name()) {
			continue
		}
		overrides.apply(violation)
		kept = append(kept, violation)
	}
	return kept, nil
}

// addDeadExceptions reports the exceptions of each configuration that match
// no file under its directory, named relative to the working directory.
func addDeadExceptions(findings *findingSet, rule *deadcode.DeadConfigExceptionRule, configs map[string]*core.Config) error {
	if len(configs) == 0 {
		return nil
	}
	base, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve working directory: %w", err)
	}
	for _, path := range slices.Sorted(maps.Keys(configs)) {
		cfg := configs[path]
		files, err := cfg.ConfigFiles()
		if err != nil {
			return err
		}
		violations, err := rule.CheckConfig(cfg, files, base)
		if err != nil {
			return err
		}
		minSeverity, err := cfg.GetMinSeverity()
		if err != nil {
			return err
		}
		findings.add(base, core.ViolationList(violations).BySeverity(minSeverity))
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

// analysisRoot is a root analyzed as one project: its directory, and the
// directories under it the run walks — none for the whole root.
type analysisRoot struct {
	dir    string
	scopes []string
}

// analysisRoots groups the path arguments by the configuration that governs
// them: the paths under one .glint.yaml are walked as scopes of its directory,
// so findings name files relative to it, the project rules see the files of
// every path together, and the run keeps one result cache. A path no
// configuration governs is a root of its own.
func analysisRoots(args []string) ([]analysisRoot, error) {
	dirs, err := getProjectRoots(args)
	if err != nil {
		return nil, err
	}
	var roots []analysisRoot
	index := make(map[string]int)
	for _, dir := range dirs {
		configPath, err := core.FindConfig(dir)
		if err != nil {
			return nil, err
		}
		base := dir
		if configPath != "" {
			base = filepath.Dir(configPath)
		}
		i, ok := index[base]
		if !ok {
			i = len(roots)
			index[base] = i
			roots = append(roots, analysisRoot{dir: base})
		}
		roots[i].addScope(dir, dir == base)
	}
	return roots, nil
}

// addScope adds a directory to the walk of a root; the root itself, or a
// directory a scope already covers, makes the walk wider instead.
func (r *analysisRoot) addScope(dir string, whole bool) {
	if r.wholeRoot() {
		return
	}
	if whole {
		r.scopes = []string{r.dir}
		return
	}
	kept := r.scopes[:0]
	for _, scope := range r.scopes {
		if within(dir, scope) {
			return
		}
		if !within(scope, dir) {
			kept = append(kept, scope)
		}
	}
	r.scopes = append(kept, dir)
}

// wholeRoot reports a root walked in full.
func (r *analysisRoot) wholeRoot() bool {
	return len(r.scopes) == 1 && r.scopes[0] == r.dir
}

// walkScopes returns the scopes the walker takes: none for the whole root.
func (r analysisRoot) walkScopes() []string {
	if r.wholeRoot() {
		return nil
	}
	return r.scopes
}

// within reports a path at or below dir.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
	if warning := excludedTestRulesWarning(cfg, enabledRules); warning != "" {
		fmt.Fprintln(os.Stderr, warning)
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

	if len(flagRules) > 0 {
		requested, err := requestedRules(flagRules)
		if err != nil {
			return nil, err
		}
		if flagDebug {
			for _, rule := range requested {
				fmt.Printf("DEBUG: Found rule %s in category %s\n", rule.Name(), rule.Category())
			}
		}
		enabledRules = requested
	}

	if flagVerbose {
		fmt.Printf("Running %d rules...\n", len(enabledRules))
	}

	return enabledRules, nil
}

// requestedRules resolves the --rule names, each once, in the order given.
func requestedRules(names []string) ([]rules.Rule, error) {
	var requested []rules.Rule
	seen := make(map[string]bool)
	for _, name := range names {
		rule, ok := rules.Get(name)
		if !ok {
			return nil, fmt.Errorf("unknown rule %q; run 'glint rules' to list them", name)
		}
		if !seen[name] {
			seen[name] = true
			requested = append(requested, rule)
		}
	}
	return requested, nil
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

// preparedRoot is a walked project root ready for analysis.
type preparedRoot struct {
	contexts []*core.FileContext
	walker   *core.Walker
	// project is the typed load, nil when no project rule runs, the root has
	// no Go files, or the cache holds the project findings for unchanged
	// inputs; the Go files have their syntax trees in every case.
	project *core.GoProjectContext
	// skipped are the packages left out of typed analysis, from the load or
	// from the cache.
	skipped []core.SkippedPackage
	cache   *resultCache
}

// prepareAnalysis prepares a whole root.
func prepareAnalysis(loader *core.GoProjectLoader, projectRoot string, cfg *core.Config, enabledRules []rules.Rule, useCache bool) (*preparedRoot, error) {
	return prepareScopedAnalysis(loader, analysisRoot{dir: projectRoot}, cfg, enabledRules, useCache)
}

// prepareScopedAnalysis walks the scopes of a root and loads what its rules
// need.
func prepareScopedAnalysis(loader *core.GoProjectLoader, root analysisRoot, cfg *core.Config, enabledRules []rules.Rule, useCache bool) (*preparedRoot, error) {
	projectRoot := root.dir
	var projectRules []string
	requireSSA := false
	for _, rule := range enabledRules {
		projectRule, ok := rule.(rules.GoProjectRule)
		if !ok {
			continue
		}
		projectRules = append(projectRules, rule.Name())
		requireSSA = requireSSA || projectRule.RequiresSSA()
	}
	slices.Sort(projectRules)
	projectRuleCount := len(projectRules)

	walker := core.NewWalker(projectRoot, cfg).WithGoParsing(projectRuleCount == 0).WithScopes(root.walkScopes())
	contexts, walker, err := walkWithWalker(walker)
	prepared := &preparedRoot{contexts: contexts, walker: walker}
	if err != nil {
		return prepared, err
	}
	// Дерево без Go-файлов (например, frontend): Go-project правилам нечего
	// анализировать, а загрузка Go-контекста упала бы с "no packages found".
	needProject := projectRuleCount > 0 && hasGoFiles(contexts)
	if useCache {
		prepared.cache = openRootCache(projectRoot, root.walkScopes(), cfg, needProject)
	}
	if !needProject {
		return prepared, nil
	}
	if hit, err := prepared.cachedProject(loader, projectRoot, projectRules); err != nil || hit {
		return prepared, err
	}
	project, err := loader.Load(projectRoot, contexts, core.GoProjectOptions{
		RequireSSA:             requireSSA,
		TolerateBrokenPackages: flagTolerant,
	})
	if err != nil {
		return prepared, fmt.Errorf("load Go project context: %w", err)
	}
	prepared.project = project
	prepared.skipped = project.SkippedPackages
	reportSkippedPackages(prepared.skipped, cfg.Settings.Output)
	return prepared, nil
}

// cachedProject takes the project findings from the cache when no input of
// the typed load changed and the same project rules run, and gives the Go files the syntax trees the load
// would have given them. An input hash that cannot be computed is reported and
// the project is loaded.
func (p *preparedRoot) cachedProject(loader *core.GoProjectLoader, projectRoot string, projectRules []string) (bool, error) {
	if p.cache == nil {
		return false, nil
	}
	inputs, cacheable, err := loader.GoInputs(projectRoot, p.contexts, flagTolerant)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: project findings of %s not cached: %v\n", projectRoot, err)
		return false, nil
	}
	if !cacheable {
		return false, nil
	}
	hit := p.cache.keyProject(inputs, projectRules)
	if hit == nil {
		return false, nil
	}
	if err := core.ParseGoFiles(projectRoot, p.contexts, flagTolerant); err != nil {
		return false, fmt.Errorf("parse Go files of %s: %w", projectRoot, err)
	}
	p.skipped = hit.Skipped
	return true, nil
}

// reportSkippedPackages keeps a tolerated load honest: whatever was left out of
// typed analysis is named, so findings are never read as full coverage.
func reportSkippedPackages(skipped []core.SkippedPackage, outputFormat string) {
	if len(skipped) == 0 {
		return
	}
	if outputFormat == "json" {
		return
	}
	fmt.Fprintf(os.Stderr, "Skipped %d package(s) that do not type-check; their files are analyzed without type information\n", len(skipped))
	if !flagVerbose {
		return
	}
	for _, pkg := range skipped {
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

// execute spreads the files over a worker per thread the run may use. Each worker owns its own
// row of the result matrix, so no synchronization is needed beyond the wait
// group.
func (s statelessRun) execute(contexts []*core.FileContext, found [][]core.ViolationList, failures []error) {
	workers := runtime.GOMAXPROCS(0)
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
	if ctx.IsGenerated() {
		return nil, nil
	}
	fileException, excepted := cfg.FileException(rule.Category(), rule.Name(), ctx.RelPath)
	if excepted && rules.AccumulatesAcrossFiles(rule) {
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
	if excepted {
		// Markers in the file are not judged: drop the ones the rule consulted.
		ctx.TakeSuppressionHits(rule.Name())
		return fileExceptionSuppression(ctx.RelPath, rule, fileException, violations), nil
	}

	honorsSuppression := rules.HonorsSuppression(rule)
	kept = make(core.ViolationList, 0, len(violations))
	for _, violation := range violations {
		ctx.AnnotateFunction(violation)
		if suppression := exceptionSuppression(cfg, rule, ctx.RelPath, violation); suppression != nil {
			kept = append(kept, suppression)
			continue
		}
		if honorsSuppression && ctx.IsSuppressed(violation.Line, rule.Name()) {
			continue
		}
		overrides.apply(violation)
		kept = append(kept, violation)
	}
	kept = append(kept, inlineSuppressions(ctx, rule)...)
	if len(kept) == 0 {
		return nil, nil
	}
	return kept, nil
}

// exceptionSuppression returns the suppression entry of a finding a configured
// exception silences, nil when none does.
func exceptionSuppression(cfg *core.Config, rule rules.Rule, relPath string, violation *core.Violation) *core.Violation {
	exc, ok := cfg.MatchingException(rule.Category(), rule.Name(), relPath, violation)
	if !ok {
		return nil
	}
	return core.NewSuppressionEntry(rule.Name(), rule.Category(), relPath, violation.Line, core.SuppressionExceptionPrefix+exc.Key())
}

// fileExceptionSuppression returns the suppression entry of a file a file-only
// exception keeps the rule off, when the rule found anything there: the rule
// runs on such a file only for stale-suppression to know whether the
// exception silences something.
func fileExceptionSuppression(relPath string, rule rules.Rule, exc core.Exception, violations []*core.Violation) core.ViolationList {
	if len(violations) == 0 {
		return nil
	}
	return core.ViolationList{core.NewSuppressionEntry(rule.Name(), rule.Category(), relPath, violations[0].Line, core.SuppressionExceptionPrefix+exc.Key())}
}

// inlineSuppressions turns the markers that silenced the rule's findings in
// the file — in the rule itself or above — into suppression entries.
func inlineSuppressions(ctx *core.FileContext, rule rules.Rule) core.ViolationList {
	var entries core.ViolationList
	for _, line := range ctx.TakeSuppressionHits(rule.Name()) {
		entries = append(entries, core.NewSuppressionEntry(rule.Name(), rule.Category(), ctx.RelPath, line, core.SuppressionInline))
	}
	return entries
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
	cachedProject := cache != nil && cache.projectHit != nil
	if cachedProject {
		allViolations = cachedViolations(cache.projectHit.Violations)
	}
	for _, rule := range enabledRules {
		projectRule, ok := rule.(rules.GoProjectRule)
		if !ok {
			fileRules = append(fileRules, rule)
			continue
		}
		if cachedProject {
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
			if fileCtx.IsGenerated() {
				continue
			}
			if exc, ok := cfg.FileException(rule.Category(), rule.Name(), fileCtx.RelPath); ok {
				allViolations = append(allViolations, fileExceptionSuppression(fileCtx.RelPath, rule, exc, []*core.Violation{violation})...)
				continue
			}
			if suppression := exceptionSuppression(cfg, rule, fileCtx.RelPath, violation); suppression != nil {
				allViolations = append(allViolations, suppression)
				continue
			}
			if rules.HonorsSuppression(rule) && fileCtx.IsSuppressed(violation.Line, rule.Name()) {
				continue
			}
			violation.File = fileCtx.RelPath
			overrides.apply(violation)
			allViolations = append(allViolations, violation)
		}
		for _, fileCtx := range project.Files {
			allViolations = append(allViolations, inlineSuppressions(fileCtx, rule)...)
		}
	}
	if cache != nil && project != nil {
		cache.storeProject(allViolations, project.SkippedPackages)
	}
	for _, rule := range fileRules {
		if projectFiles, ok := rule.(rules.ProjectFilesRule); ok {
			projectFiles.UseProjectFiles(contexts)
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
	if err := applyJobs(); err != nil {
		return err
	}
	projectRoots, err := getProjectRoots(args)
	if err != nil {
		return err
	}

	if _, err := requestedRules(flagFixRules); err != nil {
		return err
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
		if len(flagFixRules) > 0 && !slices.Contains(flagFixRules, r.Name()) {
			continue
		}
		if _, ok := fix.DefaultRegistry.Get(r.Name()); ok {
			fixableRules = append(fixableRules, r)
		}
	}

	if len(fixableRules) == 0 {
		if len(flagFixRules) > 0 {
			fmt.Printf("No fixer available for rules: %s\n", strings.Join(flagFixRules, ", "))
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
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), projectRoot, cfg, fixableRules, false)
	if err != nil {
		return nil, err
	}
	contexts, project := prepared.contexts, prepared.project
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
	violations, _ = core.SplitSuppressions(violations)
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
