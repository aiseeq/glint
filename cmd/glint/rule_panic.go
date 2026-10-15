package main

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// rulePanic is a rule that panicked - a bug in that rule. glint check goes on
// with the other rules, prints their findings, names the panic and exits
// non-zero; the strict analysis of glint fix fails on it.
type rulePanic struct {
	rule  string
	file  string // the file the rule choked on, "(go project)" for a project rule
	value any
	stack []byte
}

func (p *rulePanic) Error() string {
	return fmt.Sprintf("rule %q panicked on %s: %v", p.rule, p.file, p.value)
}

// rulePanics are the panics of one run.
type rulePanics []*rulePanic

func (ps rulePanics) Error() string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.Error()
	}
	return fmt.Sprintf("%d rule panic(s), the findings of these rules are missing: %s", len(ps), strings.Join(parts, "; "))
}

// rules returns the names of the rules that panicked, sorted and once each.
func (ps rulePanics) rules() []string {
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		names = append(names, p.rule)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// writeStacks writes every panic with its stack for the bug report.
func (ps rulePanics) writeStacks(w io.Writer) error {
	for _, p := range ps {
		if _, err := fmt.Fprintf(w, "Error: %s\n%s\n", p.Error(), p.stack); err != nil {
			return fmt.Errorf("write panic of rule %q: %w", p.rule, err)
		}
	}
	return nil
}

// splitRulePanic separates a rule panic from any other failure of a rule.
func splitRulePanic(err error) (*rulePanic, error) {
	var p *rulePanic
	if errors.As(err, &p) {
		return p, nil
	}
	return nil, err
}
