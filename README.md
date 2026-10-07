# Glint

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Fast, configurable static analyzer for Go projects.

Originally built to help AI agents understand codebases, but useful for any project.

## Features

- **Rules in 8 categories** — architecture, duplication, patterns, typesafety, security, deadcode, naming, documentation (`glint rules` prints the authoritative list)
- **Auto-fix support** — automatic fixes for common issues (v1.1+)
- **Single-pass analysis** — files are read and parsed once, AST is cached
- **Parallel execution** — reading, parsing and rule evaluation use all CPU cores; findings stay byte-for-byte reproducible
- **YAML configuration** — with `extends` inheritance, severity overrides and per-rule exceptions
- **Multiple output formats** — console, JSON, summary (optimized for AI agents)
- **Go and TypeScript support** — regex and AST-based analysis

## Installation

```bash
go install github.com/aiseeq/glint/cmd/glint@latest
```

This build needs no C compiler: the SQL rules parse with libpg_query compiled
to WebAssembly, which adds about a second and a few hundred MB to a run that
parses SQL. Where a C compiler (gcc or clang) is installed and cgo is on,
build the native parser instead:

```bash
go install -tags pgquery_cgo github.com/aiseeq/glint/cmd/glint@latest
```

Without cgo that build stops with `undefined: pganalyze.FingerprintToHexStr`:
drop the tag, or install a C compiler.

Or build from source (graft builds the native parser, so it needs a C compiler). Development commands run through
[graft](https://github.com/aiseeq/graft) (tasks in `.graft.yaml`):

```bash
go install github.com/aiseeq/graft@v0.5.0
git clone https://github.com/aiseeq/glint.git
cd glint
graft init      # git hooks
graft build     # bin/glint
graft install   # ~/bin/glint
graft help      # every task
```

## Quick Start

```bash
# Analyze current directory
glint check

# Analyze specific paths: paths under one .glint.yaml are one project, files
# are named from its directory and cross-file rules see every path
glint check ./backend ./frontend/shared

# Show only high+ severity issues
glint check --min-severity=high

# Run specific category
glint check --category=architecture

# Run specific rule
glint check --rule=error-masking

# Get summary for AI agents
glint check --output=summary

# Analyze a tree that does not compile as a whole (historical commits,
# git-ignored or generated sources, work in progress): packages that fail to
# type-check are reported and their files are analyzed without type information
glint check --tolerate-broken-packages
```

## Measuring your history

`tools/history/measure.py` builds a quality curve over a repository's git
history: a slice every two weeks, each analyzed by today's full rule set
(project `.glint.yaml` exclusions are ignored, so the instrument stays the
same across all slices). Output is JSONL with per-slice aggregates:
findings per 1000 non-test Go lines, split by severity and category.

```bash
python3 tools/history/measure.py /path/to/repo curve.jsonl
python3 tools/history/plot.py curve.jsonl -o curve.png  # needs matplotlib
```

`plot.py` draws the heavy-findings curve (critical+high per 1000 lines) by
default; `--metric per_kloc_total` plots all findings, and passing several
JSONL files draws one line per project.

`tools/history/mine/` finds rule candidates in a repository's fix commits:
agents triage the fixes in batches, the records are grouped into bug classes,
and today's glint is replayed on the tree before every fix to show which
classes it misses. The steps are in its README.

## Configuration

Create `.glint.yaml` in your project root:

```yaml
version: 1

# Optional: start from another config file, resolved relative to this one.
extends: ../shared/glint-base.yaml

settings:
  exclude:
    - vendor/**
    - node_modules/**
    - "**/*_test.go"
  min_severity: medium
  output: console

categories:
  architecture:
    enabled: true
  patterns:
    severity_override: high      # severity for every rule in this category
    rules:
      error-masking:
        severity: critical       # wins over the category override
        exceptions:
          - files: "**/config/**"
            reason: "Config defaults are acceptable"
      todo-comment:
        enabled: false
  typesafety:
    enabled: true
```

Reference:

| Key | Meaning |
|-----|---------|
| `extends` | Path to a base config merged under this one (relative to this file). |
| `settings.exclude` | Glob patterns; `*` stays inside one path segment, `**` spans segments. A pattern without a separator also matches the base name. |
| `settings.skip_dirs` | Directory names never descended into. Defaults to `.git .svn .hg .idea .vscode node_modules vendor .next out dist build bin` — set it if one of those is a real package of yours. |
| `settings.respect_gitignore` | Honour `.gitignore` files (default `true`): whatever the project excludes from git — generated bundles, test-runner reports, local scratch files — is not analyzed. Patterns are applied with git semantics from the repository root down, so running glint on a subdirectory still sees the root `.gitignore`. Set to `false` to analyze everything. |
| `settings.min_severity` | `low` / `medium` / `high` / `critical`. |
| `settings.output` | `console` / `json` / `summary`. |
| `categories.<name>.enabled` | Defaults to `true` — naming a category to configure its rules does not switch it off. |
| `categories.<name>.severity_override` | Reported severity for every rule of the category. |
| `categories.<name>.rules.<rule>.severity` | Reported severity for one rule; wins over the category override. |
| `categories.<name>.rules.<rule>.exceptions` | `file` / `files` / `line` / `pattern` / `function` + `reason`. |

Paths in `exclude` and `exceptions` are relative to the directory of the
configuration file, whichever directory a run checks: with the configuration at
the repository root, `glint check ./backend` still matches `backend/services/**`,
not `services/**`. An exception whose `file` or `files` matches no file under
that directory suppresses nothing, and the `dead-config-exception` rule reports
it on its line of `.glint.yaml`.

Individual findings can also be silenced at the source with `//nolint:<rule>` or
`// <rule>: safe — reason`, on the offending line or the line above it.

## Rules

### Current Categories

Rules are organized into 8 categories: architecture, deadcode, documentation,
duplication, naming, patterns, security, typesafety. The authoritative,
always-current list — names, severities and auto-fix availability — comes from
the tool itself:

```bash
glint rules
```

### Key Rules

- **masked-error-in-or-condition** (HIGH) — `if err != nil || x == nil { return zero, nil }` masks a real failure as a valid zero value
- **constructor-nil-return** (HIGH) — New* constructor without an error result that can return nil
- **constructor-swallows-nil-dep** (HIGH) — constructor logs a nil dependency and builds the object anyway
- **log-and-return-zero** (MEDIUM) — Error/Warn log followed by a zero-value return in a function without an error result
- **frontend-money-arithmetic** (HIGH) — client-side arithmetic over money values (parseFloat sums, reduce aggregation)
- **any-in-public-contract** (MEDIUM) — bare any/interface{} in exported results and map[string]any fields
- **tombstone-comment** (LOW) — comments describing deleted code ("removed", "УДАЛЕНО") — git history already remembers
- **migration-duplicate-version** (CRITICAL) — two different migrations sharing one version number; also missing up/down pairs
- **test-external-service** (HIGH) — a test builds a live vendor client, or gates itself with "skip unless the API key is set" — a gate that is open in exactly the environment the test runs in, since the key comes from `.env`. Declare the real opt-in helper in `guard_functions` to allow deliberate live runs
- **layer-violation** (CRITICAL) — Detects violations of Handler→Service→Repository architecture
- **import-direction** (HIGH) — Detects imports that violate layered architecture direction
- **hardcoded-secret** (CRITICAL) — Detects passwords, API keys, tokens in code
- **sensitive-query-param** (HIGH) — Detects credentials and action tokens exposed in URLs (CWE-598)
- **sql-injection** (CRITICAL) — Detects SQL text built from a string parameter (concatenation or fmt.Sprintf, through local variables) without a whitelist check and passed to a database call
- **error-masking** (CRITICAL) — Detects patterns that mask errors instead of handling them properly
- **cyclomatic-complexity** — Functions with too many decision paths (default: >20, setting `max_complexity`)
- **cross-file-duplicate** — Detects duplicate code blocks across different files
- **unused-param** — Function parameters that are never used
- **naming-convention** — Detects stuttering, ALL_CAPS, underscores in exported names
- **doc-missing** — Detects exported types/functions without documentation
- **error-string-compare** — Detects error comparisons via strings instead of errors.Is/errors.As
- **error-wrap** — Detects errors from the standard library or other modules returned without context (should use fmt.Errorf with %w)
- **error-cause-dropped** — Detects error branches that replace the real cause with a fixed message (Go `if err != nil`, TS `catch`) — the caller learns that it failed, never why
- **go-modern** — Detects deprecated reflect.SliceHeader/StringHeader (use unsafe.Slice/SliceData/String/StringData)
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

Shell scripts, make files, Dockerfiles, YAML and env templates comment with `#`, and the same markers work there; a `#` inside quotes or within a word (`${#var}`) is no comment:

```bash
printf 'TOKEN=%s\n' "$TOKEN" # secret-exposure: safe — captured by the caller, never printed
```

Always add the reason after the marker. Policy rules may opt out of suppression entirely (implement `rules.SuppressionExempt`; `silent-config-error` does).

A marker or a finding exception that silenced nothing in the run is reported by `stale-suppression`: it would hide the next real finding on that spot unseen. The rule judges only rules the run executed; a bare `//nolint` and a name that is no glint rule are reported unless the project configures golangci-lint (`.golangci.yml` in the root or above), whose linters such names may mean. Markers are read from the comments of Go, TypeScript and JavaScript, and from the `#` comments of shell scripts, make files, Dockerfiles, YAML and env templates. `//nolint:glint` names the tool, not a rule, and is reported always: glint honors only `nolint:<rule>`, and golangci-lint takes it for an unknown linter. Exceptions are judged when the run covers the configuration's whole directory. A file-only exception (`file`/`files` and nothing else) is judged by running the rule on the files it names and keeping the findings out of the report; rules whose analysis of one file feeds their findings on others (cross-file duplication, for instance) are not run there, so their file exceptions are not judged. An exception whose files do not exist is `dead-config-exception`'s.

### Known Limitations

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

Rules with an auto-fix are marked `(auto-fix)` in `glint rules` output.

### Safety

- **Dry-run by default** — always preview changes first
- **Git warning** — warns if you have uncommitted changes
- **Atomic** — all fixes in a file are applied together

## Verbose/Debug

```bash
# Show which files are being analyzed
glint check --verbose

# Debug output for rule selection
glint check --debug
```

## Timing

`--timing` reports per-phase and per-rule durations to stderr — total and the
slowest single file per rule:

```bash
glint check --timing
```

If glint hangs on your project, run it with `--timing` and press Ctrl+C: the
report names the rule and file it is stuck on (or the loading phase, if
type-checking is the problem). Please attach that output when filing an issue.

## Result Cache

Findings of rules that look at one file only are kept per project root in the
user cache directory (`~/.cache/glint/results` on Linux). A file whose content
is unchanged gets them back instead of being analyzed again. Another glint
build, another configuration or another loading mode discards the cache; rules
that read other files or the disk always run.

The directory stays bounded. A cache file is named after its root and the
glint build that wrote it; once per run glint removes the caches of other
builds (and of older layouts) and leftover temporary files, any cache not read
or written for 7 days, and then the least recently used caches of its own
build until they fit 1 GB. Files touched in the last 10 minutes are kept by
all but the age rule, so a run in another session never loses the cache it is
writing. A save replaces the file by rename and a removed file reads as an
empty cache, so concurrent runs only ever lose time, never findings.

The findings of the rules that see the whole module are kept too, for the
inputs of the typed load: the Go and cgo sources and module files of the
modules the root belongs to (and of their workspace), the analyzed Go files,
the Go version and build environment. While none of them changes — a commit
that touches only the frontend, say — the packages are not loaded at all. A
module with a `replace` to a local directory is always loaded.

```bash
glint check --no-cache    # analyze every file
```

A rule whose findings depend on more than its file must implement
`rules.ReadsOtherFiles`; a test walks the call graph of every other file rule
and fails when it reaches the disk, the environment or the clock.

## Project Structure

```
glint/
├── cmd/glint/          # CLI entry point
├── pkg/
│   ├── core/           # Walker, parser, config, cache
│   ├── fix/            # Auto-fix implementations
│   ├── rules/          # Rule implementations by category
│   └── output/         # Output formatters
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-rule`)
3. Add tests for your changes
4. Run the checks (`graft all`) and glint on itself (`graft self-check`)
5. Commit your changes (`graft commit -m 'feat: add amazing-rule'`)
6. Push to the branch (`git push origin feature/amazing-rule`)
7. Open a Pull Request

## License

MIT License. See [LICENSE](LICENSE) for details.
