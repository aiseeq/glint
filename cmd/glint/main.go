package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/fix"
	"github.com/aiseeq/glint/pkg/output"
	"github.com/aiseeq/glint/pkg/rules"

	// Rule packages - imported for init() registration
	_ "github.com/aiseeq/glint/pkg/rules/architecture"
	_ "github.com/aiseeq/glint/pkg/rules/duplication"
	_ "github.com/aiseeq/glint/pkg/rules/patterns"
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
	// Fix command flags
	flagDryRun    bool
	flagForce     bool
	flagFixRule   string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "glint",
	Short: "Glint - Unified Code Analyzer",
	Long: `Glint is a fast, configurable static analyzer for Go and TypeScript projects.
Originally built to help AI agents understand codebases.`,
	Version: version,
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
Use --no-dry-run to actually apply fixes.

Available fixers:
  - interface-any: Replace interface{} with any (Go 1.18+)
  - deprecated-ioutil: Replace io/ioutil with io/os
  - bool-compare: Simplify boolean comparisons (x == true -> x)`,
	RunE: runFix,
}

func init() {
	// Check command flags
	checkCmd.Flags().StringVarP(&flagCategory, "category", "c", "", "Run only specified category")
	checkCmd.Flags().StringVarP(&flagRule, "rule", "r", "", "Run only specified rule")
	checkCmd.Flags().StringVarP(&flagMinSeverity, "min-severity", "s", "", "Minimum severity (low, medium, high, critical)")
	checkCmd.Flags().StringVarP(&flagOutput, "output", "o", "console", "Output format (console, json, summary)")
	checkCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show analyzed files")
	checkCmd.Flags().BoolVar(&flagDebug, "debug", false, "Enable debug output")
	checkCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Disable colored output")

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

func runCheck(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	projectRoot, err := getProjectRoot(args)
	if err != nil {
		return err
	}

	cfg, enabledRules, err := loadConfig(projectRoot)
	if err != nil {
		return err
	}

	if len(enabledRules) == 0 {
		fmt.Println("No rules enabled. Check your configuration.")
		return nil
	}

	contexts, walker := walkFiles(projectRoot, cfg)

	allViolations := analyzeFiles(contexts, enabledRules)
	allViolations = allViolations.BySeverity(cfg.GetMinSeverity())

	stats := output.Stats{
		FilesAnalyzed: len(contexts),
		FilesSkipped:  walker.Stats().SkippedFiles,
		RulesRun:      len(enabledRules),
		Duration:      time.Since(startTime).Seconds(),
	}

	if err := outputResults(cfg.Settings.Output, allViolations, stats); err != nil {
		return fmt.Errorf("output error: %w", err)
	}

	if allViolations.HasCritical() {
		os.Exit(1)
	}

	return nil
}

func getProjectRoot(args []string) (string, error) {
	paths := args
	if len(paths) == 0 {
		paths = []string{"."}
	}

	projectRoot := paths[0]
	if projectRoot == "." {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get working directory: %w", err)
		}
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

	enabledRules := getEnabledRules(cfg)
	return cfg, enabledRules, nil
}

func getEnabledRules(cfg *core.Config) []rules.Rule {
	enabledRules := rules.GetEnabled(cfg)
	if flagCategory != "" {
		enabledRules = rules.GetByCategory(flagCategory)
	}
	if flagRule != "" {
		if r, ok := rules.Get(flagRule); ok {
			enabledRules = []rules.Rule{r}
		}
	}

	if flagVerbose {
		fmt.Printf("Running %d rules...\n", len(enabledRules))
	}

	return enabledRules
}

func walkFiles(projectRoot string, cfg *core.Config) ([]*core.FileContext, *core.Walker) {
	walker := core.NewWalker(projectRoot, cfg)
	contexts, errors := walker.WalkSync()

	if flagVerbose {
		stats := walker.Stats()
		fmt.Printf("Found %d files to analyze\n", stats.TotalFiles)
	}

	for _, err := range errors {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}

	return contexts, walker
}

func analyzeFiles(contexts []*core.FileContext, enabledRules []rules.Rule) core.ViolationList {
	var allViolations core.ViolationList
	for _, ctx := range contexts {
		for _, rule := range enabledRules {
			violations := rule.AnalyzeFile(ctx)
			allViolations = append(allViolations, violations...)
		}
	}
	return allViolations
}

func outputResults(format string, violations core.ViolationList, stats output.Stats) error {
	switch format {
	case "json":
		fmt.Println("JSON output not yet implemented")
		return nil
	case "summary":
		out := output.NewSummaryOutput().WithWriter(os.Stdout)
		return out.Write(violations, stats)
	default:
		out := output.NewConsoleOutput().
			WithWriter(os.Stdout).
			WithVerbose(flagVerbose).
			WithNoColor(flagNoColor)
		return out.Write(violations, stats)
	}
}

func runRules(cmd *cobra.Command, args []string) error {
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
		if info.HasAutoFix {
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

func runExplain(cmd *cobra.Command, args []string) error {
	ruleName := args[0]

	rule, ok := rules.Get(ruleName)
	if !ok {
		return fmt.Errorf("unknown rule: %s", ruleName)
	}

	info := rules.GetRuleInfo(rule)

	fmt.Printf("RULE: %s\n", info.Name)
	fmt.Printf("CATEGORY: %s\n", info.Category)
	fmt.Printf("SEVERITY: %s\n", info.Severity.Label())
	if info.HasAutoFix {
		fmt.Println("AUTO-FIX: Available")
	}
	fmt.Println()
	fmt.Println("DESCRIPTION:")
	fmt.Printf("  %s\n", info.Description)

	return nil
}

func runInit(cmd *cobra.Command, args []string) error {
	configContent := `# Glint configuration
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
  architecture:
    enabled: true
  patterns:
    enabled: true
  typesafety:
    enabled: true
  duplication:
    enabled: true
  deadcode:
    enabled: true
  config:
    enabled: true
  naming:
    enabled: true
`

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

func runConfigShow(cmd *cobra.Command, args []string) error {
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

func runConfigValidate(cmd *cobra.Command, args []string) error {
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

func runFix(cmd *cobra.Command, args []string) error {
	projectRoot, err := getProjectRoot(args)
	if err != nil {
		return err
	}

	// Check for uncommitted changes
	engine := fix.NewEngine(fix.DefaultRegistry, flagDryRun, flagVerbose)
	hasChanges, err := engine.CheckGitStatus(projectRoot)
	if err != nil && flagVerbose {
		fmt.Fprintf(os.Stderr, "Warning: could not check git status: %v\n", err)
	}

	if hasChanges && !flagForce && !flagDryRun {
		fmt.Println("WARNING: You have uncommitted changes.")
		fmt.Println("Use --force to apply fixes anyway, or commit your changes first.")
		fmt.Println("Running in dry-run mode instead.")
		flagDryRun = true
	}

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

	// Walk files and analyze
	contexts, _ := walkFiles(projectRoot, cfg)

	// Build context map for fixers (by both absolute and relative paths)
	contextMap := make(map[string]*core.FileContext)
	for _, ctx := range contexts {
		contextMap[ctx.Path] = ctx
		contextMap[ctx.RelPath] = ctx
	}

	// Collect violations from fixable rules
	var violations []*core.Violation
	for _, ctx := range contexts {
		for _, rule := range fixableRules {
			vs := rule.AnalyzeFile(ctx)
			violations = append(violations, vs...)
		}
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

	if flagDryRun {
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
