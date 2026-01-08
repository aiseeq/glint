# Glint

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Fast, configurable static analyzer for Go projects.

Originally built to help AI agents understand codebases, but useful for any project.

## Features

- **40 rules in 8 categories** — architecture, duplication, patterns, typesafety, security, deadcode, naming, documentation
- **Auto-fix support** — automatic fixes for common issues (v1.1+)
- **Single-pass analysis** — files are read and parsed once, AST is cached
- **Parallel execution** — utilizes all CPU cores
- **YAML configuration** — with inheritance and per-rule exceptions
- **Multiple output formats** — console, JSON, summary (optimized for AI agents)
- **Go and TypeScript support** — regex and AST-based analysis

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
glint check --rule=error-masking

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
      error-masking:
        exceptions:
          - files: "**/config/**"
            reason: "Config defaults are acceptable"
  typesafety:
    enabled: true
```

See [docs/configuration.md](docs/configuration.md) for full reference.

## Rules

### Current Categories

| Category | Rules | Description |
|----------|-------|-------------|
| architecture | 5 | layer-violation, import-direction, long-function, deep-nesting, cyclomatic-complexity |
| deadcode | 2 | unused-param, unused-symbol |
| documentation | 2 | doc-missing, doc-links |
| duplication | 2 | duplicate-block, cross-file-duplicate |
| naming | 1 | naming-convention |
| patterns | 24 | error-masking, ignored-error, deprecated-ioutil, todo-comment, empty-block, error-string, error-string-compare, error-wrap, go-modern, magic-number, context-background, tech-debt, defer-in-loop, return-nil-error, shadow-variable, append-assign, range-val-pointer, mutex-lock, http-body-close, sql-rows-close, string-concat, bool-compare, nil-slice, time-equal |
| security | 2 | hardcoded-secret, sql-injection |
| typesafety | 2 | interface-any, type-assertion |

### Key Rules

- **layer-violation** (CRITICAL) — Detects violations of Handler→Service→Repository architecture
- **import-direction** (HIGH) — Detects imports that violate layered architecture direction
- **hardcoded-secret** (CRITICAL) — Detects passwords, API keys, tokens in code
- **sql-injection** (CRITICAL) — Detects SQL injection via string concatenation
- **error-masking** (CRITICAL) — Detects patterns that mask errors instead of handling them properly
- **cyclomatic-complexity** — Functions with too many decision paths (default: >10)
- **cross-file-duplicate** — Detects duplicate code blocks across different files
- **unused-param** — Function parameters that are never used
- **naming-convention** — Detects stuttering, ALL_CAPS, underscores in exported names
- **doc-missing** — Detects exported types/functions without documentation
- **error-string-compare** — Detects error comparisons via strings instead of errors.Is/errors.As
- **error-wrap** — Detects errors returned without context (should use %w)
- **go-modern** — Suggests modern Go 1.21+ alternatives (slices.Sort, built-in min/max)
- **unused-symbol** — Detects unused private functions, types, constants
- **doc-links** — Detects broken/placeholder URLs in documentation

### Known Limitations

- **unused-symbol**: Analyzes single files only, not entire packages. May report false positives for symbols used in other files of the same package. Best for main packages or single-file packages.
- **go-modern**: May suggest iterator patterns for external library methods (e.g., `router.Walk`) that cannot be changed.
- **doc-links**: May flag `localhost` or `example.com` in code comments used as format examples.

### Rule Details

```bash
# List all rules
glint rules

# Explain specific rule
glint explain error-masking
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
Critical: 37 | High: 176 | Medium: 1324 | Low: 1141

TOP ISSUES:
1. [HIGH] error-masking: 62 violations
2. [MEDIUM] ignored-error: 791 violations
3. [MEDIUM] long-function: 587 violations

Files analyzed: 666 | Duration: 1.26s
```

## Auto-Fix (v1.1+)

Glint can automatically fix certain issues:

```bash
# Preview fixes (dry-run by default)
glint fix

# Fix specific rule
glint fix --rule=interface-any

# Actually apply fixes
glint fix --dry-run=false

# Apply fixes even with uncommitted changes
glint fix --dry-run=false --force
```

### Available Fixers

| Rule | Fix | Description |
|------|-----|-------------|
| interface-any | `interface{}` → `any` | Go 1.18+ type alias |
| deprecated-ioutil | `ioutil.*` → `io/os.*` | Go 1.16+ deprecation |
| bool-compare | `x == true` → `x` | Simplify boolean comparisons |

### Safety

- **Dry-run by default** — always preview changes first
- **Git warning** — warns if you have uncommitted changes
- **Atomic** — all fixes in a file are applied together

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
│   ├── fix/            # Auto-fix implementations
│   ├── rules/          # Rule implementations by category
│   └── output/         # Output formatters
├── configs/            # Built-in presets
└── testdata/           # Test fixtures and golden files
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-rule`)
3. Add tests for your changes
4. Run tests (`go test ./...`)
5. Commit your changes (`git commit -m 'Add amazing-rule'`)
6. Push to the branch (`git push origin feature/amazing-rule`)
7. Open a Pull Request

## License

MIT License. See [LICENSE](LICENSE) for details.
