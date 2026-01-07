package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/output"
	"github.com/aiseeq/glint/pkg/rules"
)

var version = "dev"

// CLI flags
var (
	flagCategory    string
	flagRule        string
	flagMinSeverity string
	flagOutput      string
	flagVerbose     bool
	flagDebug       bool
	flagNoColor     bool
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

	// Root commands
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(explainCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(configCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	// Determine paths to analyze
	paths := args
	if len(paths) == 0 {
		paths = []string{"."}
	}

	// Get project root
	projectRoot := paths[0]
	if projectRoot == "." {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
	}

	// Load configuration
	cfg, err := core.LoadConfigWithDefaults(projectRoot)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Apply CLI overrides
	if flagMinSeverity != "" {
		cfg.Settings.MinSeverity = flagMinSeverity
	}
	if flagOutput != "" {
		cfg.Settings.Output = flagOutput
	}

	// Configure rules
	if err := rules.ConfigureAll(cfg); err != nil {
		return fmt.Errorf("failed to configure rules: %w", err)
	}

	// Get enabled rules
	enabledRules := rules.GetEnabled(cfg)
	if flagCategory != "" {
		enabledRules = rules.GetByCategory(flagCategory)
	}
	if flagRule != "" {
		if r, ok := rules.Get(flagRule); ok {
			enabledRules = []rules.Rule{r}
		} else {
			return fmt.Errorf("unknown rule: %s", flagRule)
		}
	}

	if len(enabledRules) == 0 {
		fmt.Println("No rules enabled. Check your configuration.")
		return nil
	}

	if flagVerbose {
		fmt.Printf("Running %d rules...\n", len(enabledRules))
	}

	// Walk files
	walker := core.NewWalker(projectRoot, cfg)
	contexts, errors := walker.WalkSync()

	if flagVerbose {
		stats := walker.Stats()
		fmt.Printf("Found %d files to analyze\n", stats.TotalFiles)
	}

	// Report walk errors
	for _, err := range errors {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}

	// Run analysis
	var allViolations core.ViolationList
	for _, ctx := range contexts {
		for _, rule := range enabledRules {
			violations := rule.AnalyzeFile(ctx)
			allViolations = append(allViolations, violations...)
		}
	}

	// Filter by severity
	minSev := cfg.GetMinSeverity()
	allViolations = allViolations.BySeverity(minSev)

	// Output results
	stats := output.Stats{
		FilesAnalyzed: len(contexts),
		FilesSkipped:  walker.Stats().SkippedFiles,
		RulesRun:      len(enabledRules),
		Duration:      time.Since(startTime).Seconds(),
	}

	switch cfg.Settings.Output {
	case "json":
		// TODO: Implement JSON output
		fmt.Println("JSON output not yet implemented")
	case "summary":
		out := output.NewSummaryOutput().WithWriter(os.Stdout)
		out.Write(allViolations, stats)
	default:
		out := output.NewConsoleOutput().
			WithWriter(os.Stdout).
			WithVerbose(flagVerbose).
			WithNoColor(flagNoColor)
		out.Write(allViolations, stats)
	}

	// Exit with error code if critical issues found
	if allViolations.HasCritical() {
		os.Exit(1)
	}

	return nil
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

	if err := os.WriteFile(filename, []byte(configContent), 0644); err != nil {
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
