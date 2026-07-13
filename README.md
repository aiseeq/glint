# Glint

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Fast, configurable static analyzer for Go projects.

Originally built to help AI agents understand codebases, but useful for any project.

## Features

- **80 rules in 8 categories** — architecture, duplication, patterns, typesafety, security, deadcode, naming, documentation (`glint rules` is always the authoritative list)
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
| architecture | 7 | cyclomatic-complexity, deep-nesting, import-direction, layer-violation, long-function, solid-isp, solid-srp |
| deadcode | 5 | deprecated-comment, nil-return-stub, stub-method, unused-param, unused-symbol |
| documentation | 5 | doc-links, doc-missing, md-frontmatter, md-line-break, md-list-after-label |
| duplication | 2 | cross-file-duplicate, duplicate-block |
| naming | 1 | naming-convention |
| patterns | 54 | anon-interface-degradation, append-assign, bool-compare, constructor-nil-return, constructor-swallows-nil-dep, context-background, context-first, defer-in-loop, deprecated-ioutil, deterministic-uuid, empty-block, empty-struct-return, error-length-check, error-masked-as-false-bool, error-masking, error-string, error-string-compare, error-wrap, fallback-return, financial-constants, financial-fp-rounding, financial-rounded-delta, frontend-env-fallback, frontend-money-arithmetic, frontend-silent-catch, go-modern, http-body-close, ignored-error, legacy-comment-marker, legacy-identifier, log-and-return-zero, magic-number, masked-error-in-or-condition, migration-duplicate-version, mutex-lock, nil-di, nil-slice, non-canonical-logger, nullable-object-call, orphaned-interface, query-in-loop, range-val-pointer, redundant-compatibility, return-nil-error, scattered-construction, shadow-variable, silent-config-error, silent-error-handling, sql-rows-close, string-concat, tech-debt, time-equal, todo-comment, tombstone-comment |
| security | 3 | hardcoded-secret, sensitive-query-param, sql-injection |
| typesafety | 3 | any-in-public-contract, interface-any, type-assertion |

### Key Rules

- **masked-error-in-or-condition** (HIGH) — `if err != nil || x == nil { return zero, nil }` masks a real failure as a valid zero value
- **constructor-nil-return** (HIGH) — New* constructor without an error result that can return nil
- **constructor-swallows-nil-dep** (HIGH) — constructor logs a nil dependency and builds the object anyway
- **log-and-return-zero** (MEDIUM) — Error/Warn log followed by a zero-value return in a function without an error result
- **frontend-money-arithmetic** (HIGH) — client-side arithmetic over money values (parseFloat sums, reduce aggregation)
- **any-in-public-contract** (MEDIUM) — bare any/interface{} in exported results and map[string]any fields
- **tombstone-comment** (LOW) — comments describing deleted code ("removed", "УДАЛЕНО") — git history already remembers
- **migration-duplicate-version** (CRITICAL) — two different migrations sharing one version number; also missing up/down pairs
- **layer-violation** (CRITICAL) — Detects violations of Handler→Service→Repository architecture
- **import-direction** (HIGH) — Detects imports that violate layered architecture direction
- **hardcoded-secret** (CRITICAL) — Detects passwords, API keys, tokens in code
- **sensitive-query-param** (HIGH) — Detects credentials and action tokens exposed in URLs (CWE-598)
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

### Suppressing a finding

Two equivalent inline forms, placed on the violation line or the line directly above; markers work only inside comments and match the rule name exactly. Comma-separated `nolint` lists are supported:

```go
db := NewRepo(nil) //nolint:nil-di
db := NewRepo(nil) //nolint:gosec,nil-di
// nil-di: safe — repo is wired later by the DI container
db := NewRepo(nil)
```

Always add the reason after the marker. Policy rules may opt out of suppression entirely (implement `rules.SuppressionExempt`; `silent-config-error` does).

### Known Limitations

- **unused-symbol**: Analyzes single files only, not entire packages. May report false positives for symbols used in other files of the same package. Best for main packages or single-file packages.
- **go-modern**: May suggest iterator patterns for external library methods (e.g., `router.Walk`) that cannot be changed.
- **doc-links**: May flag `localhost` or `example.com` in code comments used as format examples.

### Rule Details

```bash
# List all rules
glint rules

# Exit status is non-zero when HIGH or CRITICAL findings are present.

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
