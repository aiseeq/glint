package doccheck

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestMdFrontmatterRule(t *testing.T) {
	rule := NewMdFrontmatterRule()

	tests := []struct {
		name             string
		path             string
		content          string
		expectViolations int
		expectMessages   []string
	}{
		{
			name: "valid frontmatter",
			path: "/test/doc.md",
			content: `---
title: Test Document
description: A test document for validation
date: 2026-01-23
version: 3.3.51
---

# Test Document

Some content here.`,
			expectViolations: 0,
		},
		{
			name: "valid frontmatter with optional fields",
			path: "/test/doc.md",
			content: `---
title: API Documentation
description: Complete API reference
date: 2026-01-23
version: 3.3.51
author: Team
audience: developers
tags: [api, reference]
---

# API Documentation

Content.`,
			expectViolations: 0,
		},
		{
			name: "missing frontmatter",
			path: "/test/doc.md",
			content: `# Test Document

Some content here.`,
			expectViolations: 1,
			expectMessages:   []string{"Missing YAML frontmatter"},
		},
		{
			name: "missing required field - title",
			path: "/test/doc.md",
			content: `---
description: A test document
date: 2026-01-23
version: 3.3.51
---

# Test Document`,
			expectViolations: 1,
			expectMessages:   []string{"Missing required frontmatter field: title"},
		},
		{
			name: "missing multiple required fields",
			path: "/test/doc.md",
			content: `---
title: Test
---

# Test`,
			expectViolations: 3,
			expectMessages:   []string{"description", "date", "version"},
		},
		{
			name: "invalid date format",
			path: "/test/doc.md",
			content: `---
title: Test Document
description: A test
date: January 2026
version: 3.3.51
---

# Test`,
			expectViolations: 1,
			expectMessages:   []string{"Invalid date format"},
		},
		{
			name: "invalid version format",
			path: "/test/doc.md",
			content: `---
title: Test Document
description: A test
date: 2026-01-23
version: v3.3
---

# Test`,
			expectViolations: 1,
			expectMessages:   []string{"Invalid version format"},
		},
		{
			name: "old-style metadata after title",
			path: "/test/doc.md",
			content: `---
title: Test Document
description: A test
date: 2026-01-23
version: 3.3.51
---

# Test Document

**Version:** 3.3.51
**Date:** 2026-01-23

Some content.`,
			expectViolations: 2,
			expectMessages:   []string{"Old-style metadata found"},
		},
		{
			name: "skip README.md",
			path: "/test/README.md",
			content: `# Project

No frontmatter required for README.`,
			expectViolations: 0,
		},
		{
			name: "skip templates directory",
			path: "/test/templates/template.md",
			content: `# Template

No frontmatter required.`,
			expectViolations: 0,
		},
		{
			name:             "skip non-markdown files",
			path:             "/test/doc.txt",
			content:          `Some text content without frontmatter.`,
			expectViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.path, "/test", []byte(tt.content), nil)
			violations := rule.AnalyzeFile(ctx)

			if len(violations) != tt.expectViolations {
				t.Errorf("expected %d violations, got %d", tt.expectViolations, len(violations))
				for _, v := range violations {
					t.Logf("  violation at line %d: %s", v.Line, v.Message)
				}
				return
			}

			// Check expected messages if specified
			for _, expectedMsg := range tt.expectMessages {
				found := false
				for _, v := range violations {
					if contains(v.Message, expectedMsg) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected violation containing %q not found", expectedMsg)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestParseFrontmatter(t *testing.T) {
	rule := NewMdFrontmatterRule()

	tests := []struct {
		name       string
		lines      []string
		expectHas  bool
		expectEnd  int
		expectKeys []string
	}{
		{
			name: "valid frontmatter",
			lines: []string{
				"---",
				"title: Test",
				"description: A test",
				"date: 2026-01-23",
				"version: 1.0.0",
				"---",
				"# Content",
			},
			expectHas:  true,
			expectEnd:  5,
			expectKeys: []string{"title", "description", "date", "version"},
		},
		{
			name: "no frontmatter",
			lines: []string{
				"# Title",
				"Content",
			},
			expectHas: false,
			expectEnd: 0,
		},
		{
			name: "unclosed frontmatter",
			lines: []string{
				"---",
				"title: Test",
				"# Content",
			},
			expectHas: false,
			expectEnd: 0,
		},
		{
			name: "frontmatter with quotes",
			lines: []string{
				"---",
				`title: "Quoted Title"`,
				"description: 'Single quotes'",
				"date: 2026-01-23",
				"version: 1.0.0",
				"---",
			},
			expectHas:  true,
			expectEnd:  5,
			expectKeys: []string{"title", "description"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			has, end, fields := rule.parseFrontmatter(tt.lines)

			if has != tt.expectHas {
				t.Errorf("expected has=%v, got %v", tt.expectHas, has)
			}
			if end != tt.expectEnd {
				t.Errorf("expected end=%d, got %d", tt.expectEnd, end)
			}
			for _, key := range tt.expectKeys {
				if _, ok := fields[key]; !ok {
					t.Errorf("expected field %q not found", key)
				}
			}
		})
	}
}
