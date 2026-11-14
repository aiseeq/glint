This guide describes the glint version that printed it.

# Working with glint

## Finding

Fix findings in code instead of hiding them. Handle high and critical findings in your task; resolve lower findings, including Low, before the ticket is done. If unfinished, record the remaining work on an open ticket. Use `glint explain <rule>` for details.

## False positive

A false finding is a glint defect. File a glint ticket with the rule name, a minimal example using synthetic names, and `glint --version`. While the ticket is open, suppress only the affected line or function, with a reason linking to `glint#<slug>`. Remove the exception when the ticket closes: a fixed rule makes it stale; a rejected ticket means the finding is valid and the code must be fixed. Rule: `exception-ticket-closed` reports a `glint#<slug>` exception whose ticket is done or rejected, when `tickets_dir` is set in the user config.

## Exceptions

Use exceptions only for deliberate design, scoped to a line, function, or file and backed by a verifiable reason. Disable a whole rule only when it does not fit the project. Never exclude your code by directory, rule category, or all tests.

In `.glint.yaml`, use `exceptions` with `file`, `files`, `line`, `pattern`, or `function`, and always give `reason`. In code, use `//nolint:<rule>` or `// <rule>: safe — <reason>`; in shell, Makefile, Dockerfile, and YAML, prefix the same markers with `#`. `//nolint:glint` is always reported. Bare `//nolint` and unknown rule names are reported when the project has no `.golangci.yml`.

Rule: `stale-suppression` reports obsolete code suppressions. Rule: `dead-config-exception` reports obsolete config exceptions.

## Missing rule

If glint missed a defect it could detect, file a ticket with the defect class in one sentence and a minimal example using synthetic names.

## Config

Run `glint init` to create `.glint.yaml`; inspect it with `glint config show` and check it with `glint config validate`. Only the human owner may change the shared gate threshold; an agent must not change it.

## Marks

Add `//glint:hot` above a function to enable these hot-path rules:

- Rule: `allocation-in-hot-function`
- Rule: `hot-function-without-alloc-guard`
- Rule: `reflect-in-hot-function`
- Rule: `small-constant-map-in-hot-function`
- Rule: `sqrt-compared-to-threshold`
- Rule: `nil-dst-in-loop`

## Running

Run `glint check [paths...]` to analyze paths. Add `-r <rule>` to run one rule. Use `--timing --no-cache` to measure rule time without cached results. In a project with graft, run checks through the project's task.
