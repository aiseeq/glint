package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/output"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/spf13/cobra"
)

func TestGuideSections(t *testing.T) {
	sections := []string{"Finding", "False positive", "Exceptions", "Missing rule", "Config", "Marks", "Running"}
	for _, section := range sections {
		t.Run(section, func(t *testing.T) {
			var out bytes.Buffer
			guideCmd.SetOut(&out)
			found, args, err := rootCmd.Find([]string{"guide", strings.ToLower(section)})
			if err != nil || found != guideCmd || len(args) != 1 {
				t.Fatalf("guide section is not reachable through CLI: command=%v args=%v err=%v", found, args, err)
			}
			if err := found.RunE(found, args); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(out.String(), "## "+section+"\n") {
				t.Fatalf("section output: %q", out.String())
			}
		})
	}
	var out bytes.Buffer
	guideCmd.SetOut(&out)
	if err := runGuide(guideCmd, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "This guide describes the glint version that printed it.\n\n# Working with glint\n") {
		t.Fatalf("unexpected guide introduction: %q", out.String())
	}
	if err := runGuide(guideCmd, []string{"unknown"}); err == nil || !strings.Contains(err.Error(), strings.Join(sections, ", ")) {
		t.Fatalf("unknown section should list all sections, got %v", err)
	}
}

func TestGuideReferencesCLIAndRegisteredRules(t *testing.T) {
	commands := map[string]*cobra.Command{}
	var addCommands func(*cobra.Command, string)
	addCommands = func(cmd *cobra.Command, prefix string) {
		path := strings.TrimSpace(prefix + " " + cmd.Name())
		commands[path] = cmd
		for _, child := range cmd.Commands() {
			addCommands(child, path)
		}
	}
	addCommands(rootCmd, "")

	inline := regexp.MustCompile("`([^`]+)`")
	flags := regexp.MustCompile(`(?:^|\s)(--?[a-z][a-z0-9-]*)`)
	ruleRef := regexp.MustCompile("Rule: `([a-z][a-z0-9-]+)`")
	inlineMatches := inline.FindAllStringSubmatch(agentGuide, -1)
	if len(inlineMatches) == 0 {
		t.Fatal("guide has no inline code references")
	}
	flagCount := 0
	for _, match := range inlineMatches {
		code := match[1]
		fields := strings.Fields(code)
		if len(fields) > 0 && fields[0] == "glint" {
			path := []string{"glint"}
			for _, field := range fields[1:] {
				if strings.HasPrefix(field, "-") || strings.HasPrefix(field, "<") || strings.ContainsAny(field, "[]/") {
					break
				}
				path = append(path, field)
			}
			if _, ok := commands[strings.Join(path, " ")]; !ok {
				t.Errorf("guide command %q does not exist in CLI", strings.Join(path, " "))
			}
		}
		flagMatches := flags.FindAllStringSubmatch(code, -1)
		if len(flagMatches) == 0 {
			continue
		}
		flagCount += len(flagMatches)
		for _, flag := range flagMatches {
			name := strings.TrimLeft(flag[1], "-")
			found := name == "version" && rootCmd.Version != "" || rootCmd.PersistentFlags().Lookup(name) != nil || rootCmd.Flags().Lookup(name) != nil
			if len(name) == 1 {
				found = found || rootCmd.PersistentFlags().ShorthandLookup(name) != nil || rootCmd.Flags().ShorthandLookup(name) != nil
			}
			for _, cmd := range commands {
				found = found || cmd.Flags().Lookup(name) != nil || cmd.PersistentFlags().Lookup(name) != nil
				if len(name) == 1 {
					found = found || cmd.Flags().ShorthandLookup(name) != nil || cmd.PersistentFlags().ShorthandLookup(name) != nil
				}
			}
			if !found {
				t.Errorf("guide flag %q does not exist in CLI", flag[1])
			}
		}
	}
	if flagCount == 0 {
		t.Fatal("guide has no CLI flag references")
	}
	ruleMatches := ruleRef.FindAllStringSubmatch(agentGuide, -1)
	if len(ruleMatches) == 0 {
		t.Fatal("guide has no explicitly marked rule references")
	}
	for _, match := range ruleMatches {
		if _, ok := rules.Get(match[1]); !ok {
			t.Errorf("guide rule %q is absent from the registry", match[1])
		}
	}
}

// Every command the next steps after a report with findings name runs: a
// guide section named with hyphens is found, and the level advice says what
// the Finding section of the guide says.
func TestFindingNextStepsCommandsRun(t *testing.T) {
	command := regexp.MustCompile(`glint ([a-z]+)(?: ([a-z-]+))?`)
	var guides int
	for _, line := range output.FindingNextSteps {
		match := command.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		found, args, err := rootCmd.Find(strings.Fields(strings.TrimPrefix(match[0], "glint ")))
		if err != nil || found.Name() != match[1] {
			t.Fatalf("%q: command not found: %v %v", line, found, err)
		}
		if found != guideCmd {
			continue
		}
		guides++
		var out bytes.Buffer
		guideCmd.SetOut(&out)
		if err := runGuide(guideCmd, args); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if !strings.HasPrefix(out.String(), "## ") {
			t.Fatalf("%q printed no section: %q", line, out.String())
		}
	}
	if guides != 2 {
		t.Fatalf("next steps name %d guide sections, want 2", guides)
	}
	var finding bytes.Buffer
	guideCmd.SetOut(&finding)
	if err := runGuide(guideCmd, []string{"finding"}); err != nil {
		t.Fatal(err)
	}
	for _, advice := range []string{"Handle high and critical findings in your task", "resolve lower findings, including Low, before the ticket is done", "record the remaining work on an open ticket"} {
		if !strings.Contains(finding.String(), advice) {
			t.Fatalf("the Finding section no longer says %q: update output.FindingNextSteps with it", advice)
		}
	}
}
