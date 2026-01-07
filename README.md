# Glint

Fast, configurable static analyzer for Go and TypeScript projects.

Originally built to help AI agents understand codebases, but useful for any project.

## Features

- **28 rules in 8 categories** — architecture, patterns, typesafety, duplication, deadcode, config, naming, documentation
- **Single-pass analysis** — files are read and parsed once, AST is cached
- **Parallel execution** — utilizes all CPU cores
- **YAML configuration** — with inheritance and per-rule exceptions
- **Multiple output formats** — console, JSON, summary (optimized for AI agents)
- **Auto-fix support** (v1.1+) — safe automatic fixes with dry-run preview

## Installation

```bash
go install github.com/aiseeq/glint/cmd/glint@latest
```

Or build from source:

```bash
git clone https://github.com/aiseeq/glint.git
cd glint
make build
```

## Quick Start

```bash
# Analyze current directory
glint check

# Analyze specific paths
glint check ./backend ./frontend/shared

# Show only high+ severity issues
glint check --min-severity=high

# Run specific category
glint check --category=architecture

# Run specific rule
glint check --rule=fallback

# Get summary for AI agents
glint check --output=summary
```

## Configuration

Create `.glint.yaml` in your project root:

```yaml
version: 1

settings:
  exclude:
    - vendor/**
    - node_modules/**
    - "**/*_test.go"
  min_severity: medium

categories:
  architecture:
    enabled: true
  patterns:
    enabled: true
    rules:
      fallback:
        exceptions:
          - files: "**/config/**"
            reason: "Config defaults are acceptable"
  naming:
    enabled: false
```

See [docs/configuration.md](docs/configuration.md) for full reference.

## Rules

### Categories

| Category | Rules | Description |
|----------|-------|-------------|
| architecture | 5 | Layer violations, call graph, SOLID |
| patterns | 7 | Fallback masking, error handling, tech debt |
| typesafety | 4 | interface{}/any, API compatibility |
| duplication | 4 | Code clones, semantic duplicates |
| deadcode | 3 | Unused symbols, endpoint coverage |
| config | 3 | Hardcoded values, config usage |
| naming | 2 | Go conventions, JSON/DB tags |
| documentation | 3 | Doc completeness, broken links |

### Rule Details

```bash
# List all rules
glint rules

# Explain specific rule
glint explain fallback
```

## Output Formats

### Console (default)

Human-readable output with colors and context.

### JSON

```bash
glint check --output=json > report.json
```

Machine-readable format for CI/CD integration.

### Summary

```bash
glint check --output=summary
```

Compact output optimized for AI agents:

```
GLINT ANALYSIS SUMMARY
======================
Critical: 3 | High: 12 | Medium: 28 | Low: 5

TOP ISSUES:
1. [CRITICAL] fallback: 3 violations in backend/shared/services/
2. [HIGH] layer_violation: 5 violations in backend/handlers/

Full report: /tmp/glint-report-20250107-120000.json
```

## Auto-fix (v1.1+)

```bash
# Preview changes
glint fix --dry-run

# Apply fixes
glint fix

# Fix specific rule only
glint fix --rule=interface_any
```

Supported auto-fixes:
- `interface_any`: `interface{}` → `any` (Go 1.18+)
- `json_db_tags`: Format JSON tags to camelCase
- `go_naming`: Fix exported symbol casing

## Verbose/Debug

```bash
# Show which files are being analyzed
glint check --verbose

# Full debug output (timing, cache hits)
glint check --debug
```

## Project Structure

```
glint/
├── cmd/glint/          # CLI entry point
├── pkg/
│   ├── core/           # Walker, parser, config, cache
│   ├── rules/          # Rule implementations by category
│   └── output/         # Output formatters
├── configs/            # Built-in presets
└── testdata/           # Test fixtures and golden files
```

## License

MIT License. See [LICENSE](LICENSE) for details.
