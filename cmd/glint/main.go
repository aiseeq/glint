package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("glint version %s\n", version)
		return
	}

	fmt.Println("glint - Unified Code Analyzer")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  glint check [paths...]     Analyze code")
	fmt.Println("  glint rules                List available rules")
	fmt.Println("  glint explain <rule>       Explain a rule")
	fmt.Println("  glint init                 Initialize .glint.yaml")
	fmt.Println("  glint config show          Show effective config")
	fmt.Println("  glint config validate      Validate config")
	fmt.Println("  glint fix [--dry-run]      Auto-fix issues (v1.1+)")
	fmt.Println("  glint version              Show version")
	fmt.Println("")
	fmt.Println("Flags:")
	fmt.Println("  --category=NAME    Run only specified category")
	fmt.Println("  --rule=NAME        Run only specified rule")
	fmt.Println("  --min-severity=LVL Minimum severity (low, medium, high, critical)")
	fmt.Println("  --output=FORMAT    Output format (console, json, summary)")
	fmt.Println("  --verbose          Show analyzed files")
	fmt.Println("  --debug            Full debug output")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  glint check")
	fmt.Println("  glint check ./backend --category=architecture")
	fmt.Println("  glint check --output=summary")
	fmt.Println("")
	fmt.Println("Documentation: https://github.com/aiseeq/glint")
}
