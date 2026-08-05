package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	// Fix command flags
	flagDryRun  bool
	flagForce   bool
	flagFixRule string
)

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
	Version: version,
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

	projectRoots, err := getProjectRoots(args)
	if err != nil {
		return err
	}

	var allViolations core.ViolationList
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

		contexts, walker, project, err := prepareAnalysis(projectRoot, cfg, enabledRules)
		if err != nil {
			return err
		}

		// Rules are process-wide singletons: cross-file state from a previous
		// root must not influence this one.
		rules.ResetState(enabledRules)

		violations, err := analyzeProject(contexts, enabledRules, cfg, project)
		if err != nil {
			return err
		}
		minSeverity, err := cfg.GetMinSeverity()
		if err != nil {
			return err
		}
		allViolations = append(allViolations, violations.BySeverity(minSeverity)...)

		stats.FilesAnalyzed += len(contexts)
		stats.FilesSkipped += walker.Stats().SkippedFiles
		if project != nil {
			stats.PackagesSkipped += len(project.SkippedPackages)
		}
		for _, rule := range enabledRules {
			rulesRun[rule.Name()] = struct{}{}
		}
	}
	stats.RulesRun = len(rulesRun)

	// Пересекающиеся пути (./backend и ./backend/auth) дают одну и ту же находку дважды.
	allViolations = dedupeViolations(allViolations)
	stats.Duration = time.Since(startTime).Seconds()

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

// dedupeViolations drops findings that overlapping paths reported twice. The
// message is part of the identity: one rule can legitimately report several
// distinct problems on the same line.
func dedupeViolations(violations core.ViolationList) core.ViolationList {
	type key struct {
		file    string
		line    int
		column  int
		rule    string
		message string
	}
	seen := make(map[key]struct{}, len(violations))
	unique := make(core.ViolationList, 0, len(violations))
	for _, violation := range violations {
		k := key{
			file:    violation.File,
			line:    violation.Line,
			column:  violation.Column,
			rule:    violation.Rule,
			message: violation.Message,
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		unique = append(unique, violation)
	}
	return unique
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

func resolveProjectRoot(path string) (string, error) {
	projectRoot := path
	if projectRoot == "." || projectRoot == "./..." {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get working directory: %w", err)
		}
	}
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
		enabledRules = rules.GetByCategory(flagCategory)
		if len(enabledRules) == 0 {
			return nil, fmt.Errorf("unknown category %q; known categories: %s",
				flagCategory, strings.Join(rules.Categories(), ", "))
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

func prepareAnalysis(projectRoot string, cfg *core.Config, enabledRules []rules.Rule) ([]*core.FileContext, *core.Walker, *core.GoProjectContext, error) {
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
	project, err := core.LoadGoProject(projectRoot, contexts, core.GoProjectOptions{
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
func analyzeFiles(contexts []*core.FileContext, enabledRules []rules.Rule, cfg *core.Config, overrides severityOverrides) core.ViolationList {
	if len(contexts) == 0 || len(enabledRules) == 0 {
		return nil
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

	if statefulCount < len(enabledRules) {
		runStatelessRules(contexts, enabledRules, stateful, cfg, overrides, found)
	}
	if statefulCount > 0 {
		for fileIndex, ctx := range contexts {
			for ruleIndex, rule := range enabledRules {
				if stateful[ruleIndex] {
					found[fileIndex][ruleIndex] = runRule(ctx, rule, cfg, overrides)
				}
			}
		}
	}

	var allViolations core.ViolationList
	for _, perRule := range found {
		for _, violations := range perRule {
			allViolations = append(allViolations, violations...)
		}
	}
	return allViolations
}

// runStatelessRules spreads the files over a worker per CPU. Each worker owns
// its own row of the result matrix, so no synchronization is needed beyond the
// wait group.
func runStatelessRules(contexts []*core.FileContext, enabledRules []rules.Rule, stateful []bool,
	cfg *core.Config, overrides severityOverrides, found [][]core.ViolationList) {
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
				for ruleIndex, rule := range enabledRules {
					if stateful[ruleIndex] {
						continue
					}
					found[fileIndex][ruleIndex] = runRule(contexts[fileIndex], rule, cfg, overrides)
				}
			}
		}()
	}
	wg.Wait()
}

// runRule applies one rule to one file and filters the findings the same way
// for every caller: rule exceptions, inline suppression, severity overrides.
func runRule(ctx *core.FileContext, rule rules.Rule, cfg *core.Config, overrides severityOverrides) core.ViolationList {
	if cfg.IsFileExcepted(rule.Category(), rule.Name(), ctx.RelPath) {
		return nil
	}

	violations := rule.AnalyzeFile(ctx)
	if len(violations) == 0 {
		return nil
	}

	honorsSuppression := rules.HonorsSuppression(rule)
	kept := make(core.ViolationList, 0, len(violations))
	for _, violation := range violations {
		if cfg.IsViolationExcepted(rule.Category(), rule.Name(), ctx.RelPath, violation) {
			continue
		}
		if honorsSuppression && ctx.IsSuppressed(violation.Line, rule.Name()) {
			continue
		}
		overrides.apply(violation)
		kept = append(kept, violation)
	}
	return kept
}

func hasGoFiles(contexts []*core.FileContext) bool {
	for _, ctx := range contexts {
		if ctx != nil && ctx.IsGoFile() {
			return true
		}
	}
	return false
}

func analyzeProject(contexts []*core.FileContext, enabledRules []rules.Rule, cfg *core.Config, project *core.GoProjectContext) (core.ViolationList, error) {
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
		violations, err := projectRule.AnalyzeGoProject(project)
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
			if cfg.IsFileExcepted(rule.Category(), rule.Name(), fileCtx.RelPath) ||
				cfg.IsViolationExcepted(rule.Category(), rule.Name(), fileCtx.RelPath, violation) ||
				(rules.HonorsSuppression(rule) && fileCtx.IsSuppressed(violation.Line, rule.Name())) {
				continue
			}
			violation.File = fileCtx.RelPath
			overrides.apply(violation)
			allViolations = append(allViolations, violation)
		}
	}
	allViolations = append(allViolations, analyzeFiles(contexts, fileRules, cfg, overrides)...)
	return allViolations, nil
}

func outputResults(format string, violations core.ViolationList, stats output.Stats) error {
	switch format {
	case "json":
		out := output.NewJSONOutput().WithWriter(os.Stdout)
		return out.Write(violations, stats)
	case "summary":
		out := output.NewSummaryOutput().WithWriter(os.Stdout)
		return out.Write(violations, stats)
	default:
		out := output.NewConsoleOutput().
			WithWriter(os.Stdout).
			WithNoColor(flagNoColor)
		return out.Write(violations, stats)
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
	for name, cat := range cfg.Categories {
		status := "enabled"
		if !cat.Enabled {
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

	_, err = core.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
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

	// Collect findings through the same pipeline as `check`, so that project
	// rules run, and configuration exceptions and inline suppression comments
	// are honored.
	contexts, _, project, err := prepareAnalysis(projectRoot, cfg, fixableRules)
	if err != nil {
		return err
	}

	// Build context map for fixers (by both absolute and relative paths)
	contextMap := make(map[string]*core.FileContext)
	for _, ctx := range contexts {
		contextMap[ctx.Path] = ctx
		contextMap[ctx.RelPath] = ctx
	}

	rules.ResetState(fixableRules)
	violations, err := analyzeProject(contexts, fixableRules, cfg, project)
	if err != nil {
		return err
	}

	if len(violations) == 0 {
		fmt.Println("No issues found that can be fixed.")
		return nil
	}

	// Generate fixes
	fixes := engine.GenerateFixes(violations, contextMap)

	if len(fixes) == 0 {
		fmt.Println("No automatic fixes available for the found issues.")
		return nil
	}

	// Show preview
	fmt.Print(engine.Preview(fixes))

	if dryRun {
		return nil
	}

	// Apply fixes
	results := engine.ApplyFixes(fixes)

	// Report results
	totalFixed := 0
	for _, result := range results {
		if result.Error != nil {
			fmt.Fprintf(os.Stderr, "Error fixing %s: %v\n", result.File, result.Error)
		} else {
			totalFixed += result.FixesApplied
			if flagVerbose {
				fmt.Printf("Fixed %d issues in %s\n", result.FixesApplied, result.File)
			}
		}
	}

	fmt.Printf("\nApplied %d fixes in %d files.\n", totalFixed, len(results))
	return nil
}
