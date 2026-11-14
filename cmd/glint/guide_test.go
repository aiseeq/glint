package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

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
	if !strings.HasPrefix(out.String(), "# Working with glint\n\nThis guide describes the glint version that printed it.") {
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
	for _, match := range inline.FindAllStringSubmatch(agentGuide, -1) {
		code := match[1]
		for _, flag := range flags.FindAllStringSubmatch(code, -1) {
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
		if !strings.HasPrefix(code, "glint") {
			continue
		}
		fields := strings.Fields(code)
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
	for _, match := range ruleRef.FindAllStringSubmatch(agentGuide, -1) {
		if _, ok := rules.Get(match[1]); !ok {
			t.Errorf("guide rule %q is absent from the registry", match[1])
		}
	}
	if len(ruleRef.FindAllStringSubmatch(agentGuide, -1)) == 0 {
		t.Fatal("guide has no explicitly marked rule references")
	}
}
