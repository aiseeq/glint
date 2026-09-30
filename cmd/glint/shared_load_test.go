package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// Roots of one module share a single typed load, and rules keep their
// module-wide indexes in it. Whichever root builds an index first, every root
// must get exactly the findings a separate load of it gives.
func TestSharedLoaderMatchesSeparateLoadsPerRoot(t *testing.T) {
	module := t.TempDir()
	writeModuleFile(t, module, "go.mod", "module example.com/shared\n\ngo 1.22\n")
	writeModuleFile(t, module, "svc/svc.go", `package svc

// Mailer delivers a message.
type Mailer interface{ Send(msg string) error }

// Service notifies users.
type Service struct{ mailer Mailer }

// NewService builds a Service without a mailer.
func NewService() *Service { return &Service{} }

// SetMailer injects the mailer.
func (s *Service) SetMailer(m Mailer) { s.mailer = m }

// Notify sends the message when a mailer is set.
func (s *Service) Notify(msg string) error {
	if s.mailer == nil {
		return nil
	}
	return s.mailer.Send(msg)
}
`)
	writeModuleFile(t, module, "app/app.go", `package app

import "example.com/shared/svc"

// First is the only construction site that sets the mailer.
func First(m svc.Mailer) *svc.Service {
	s := svc.NewService()
	s.SetMailer(m)
	return s
}

// Second forgets the mailer.
func Second() *svc.Service { return svc.NewService() }

// Third forgets the mailer too.
func Third() *svc.Service { return svc.NewService() }
`)
	roots := []string{filepath.Join(module, "app"), filepath.Join(module, "svc")}

	shared := core.NewGoProjectLoader()
	var total int
	for _, root := range roots {
		got := analyzeRoot(t, shared, root)
		want := analyzeRoot(t, core.NewGoProjectLoader(), root)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("root %s: shared load found\n%v\nseparate load found\n%v", root, got, want)
		}
		total += len(got)
	}
	if total == 0 {
		t.Fatal("the fixture produced no findings, the comparison proves nothing")
	}
	if !containsRule(analyzeRoot(t, shared, roots[1]), "silently-optional-dependency") {
		t.Fatal("svc root lost the finding that needs construction sites from app")
	}
}

func analyzeRoot(t *testing.T, loader *core.GoProjectLoader, root string) []string {
	t.Helper()
	cfg, enabledRules, err := loadConfig(root)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	contexts, _, project, err := prepareAnalysis(loader, root, cfg, enabledRules)
	if err != nil {
		t.Fatalf("prepare %s: %v", root, err)
	}
	rules.ResetState(enabledRules)
	violations, err := analyzeProject(contexts, enabledRules, cfg, project)
	if err != nil {
		t.Fatalf("analyze %s: %v", root, err)
	}
	found := make([]string, 0, len(violations))
	for _, v := range violations {
		found = append(found, fmt.Sprintf("%s %s:%d %s", v.Rule, v.File, v.Line, v.Message))
	}
	sort.Strings(found)
	return found
}

func containsRule(findings []string, rule string) bool {
	for _, finding := range findings {
		if len(finding) > len(rule) && finding[:len(rule)+1] == rule+" " {
			return true
		}
	}
	return false
}

func writeModuleFile(t *testing.T, module, rel, content string) {
	t.Helper()
	path := filepath.Join(module, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
