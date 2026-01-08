# Glint

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Fast, configurable static analyzer for Go projects.

Originally built to help AI agents understand codebases, but useful for any project.

## Features

- **28 rules in 4 categories** — architecture, duplication, patterns, typesafety
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
| architecture | 4 | layer-violation, import-direction, long-function, deep-nesting |
| duplication | 1 | duplicate-block |
| patterns | 21 | error-masking, ignored-error, deprecated-ioutil, todo-comment, empty-block, error-string, magic-number, context-background, tech-debt, defer-in-loop, return-nil-error, shadow-variable, append-assign, range-val-pointer, mutex-lock, http-body-close, sql-rows-close, string-concat, bool-compare, nil-slice, time-equal |
| typesafety | 2 | interface-any, type-assertion |

### Key Rules

- **layer-violation** (CRITICAL) — Detects violations of Handler→Service→Repository architecture
- **import-direction** (HIGH) — Detects imports that violate layered architecture direction
- **duplicate-block** (MEDIUM) — Detects copy-pasted code blocks (8+ lines)
- **error-masking** (CRITICAL) — Detects patterns that mask errors instead of handling them properly
- **long-function** — Functions exceeding 50 lines
- **ignored-error** — Error values ignored with blank identifier
- **interface-any** — interface{} that should be replaced with 'any'

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
