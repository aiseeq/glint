# Triage of a project's fixes: which bugs could glint catch

You triage a batch of fix commits of one project. The goal: find bug classes
that a static analyzer (glint) could have caught BEFORE the fix, in the code
before the commit. You do not fix anything and do not write rules: you read
and record.

## Inputs (given in the task)
- REPO: path to the project's git repository.
- BATCH: TSV file, one line = `hash<TAB>date<TAB>changed_files<TAB>subject`.
- RULES: file with the glint rule list and descriptions (what is already caught).
  To decide whether a rule would catch this exact code, read the rule sources
  and tests under GLINT_SRC/pkg/rules (read only).
- OUT: JSONL file to write the result to (only this file).

## Restrictions
- Read the repository only: `git -C REPO show/log/diff/blame`, reading files.
  No checkout, switch, stash, restore, reset, clean, commit, add, worktree;
  do not create or change files in REPO. Do not run tests, builds, deploys or
  project make targets. Write only to OUT.
- Do not spend time on cosmetics: a commit that is clearly about UI layout,
  texts, constant values or business formulas is NOT_RULEABLE, stop reading.

## How to read a commit
1. `git -C REPO show --stat --format='%H%n%B' HASH` — message and files.
   Messages often explain the ROOT CAUSE — use it.
2. If the message and file list suggest a bug class — `git -C REPO show HASH -- <file>`
   for the key files (at most ~200 diff lines per commit; for huge diffs read
   only code files, not tests or generated code). If no class shows from the
   message and --stat, stop reading.
3. To conclude "a rule would catch it" you need the code BEFORE the fix: the
   minus lines of the diff or `git -C REPO show HASH^:<path>`.
4. Fixes come in series on one topic (fix, revert, fix again). If a commit
   continues the topic of its neighbours, look at the series (`git -C REPO log
   --oneline -S<string>` or by file) and record the defect once, where it shows.
5. A cherry-pick or a repeat of an already triaged fix is a duplicate: do not
   record it, count it as duplicate in the summary. A later commit fixing the
   same class in places the first fix missed is not a duplicate: those places
   held the defect too, so record it - every instance is a case a rule must
   catch.
6. Parts of a `fix:` commit that only restructure code without changing
   behaviour are not fixes: skip them.

## What counts as a candidate
A candidate is a fix where the code before it held a defect RECOGNIZABLE FROM
THE CODE, and that defect is an instance of a class that occurs beyond this
project:
- misuse of stdlib or a popular library (context, time, sql, http, decimal,
  json, sync, errors, React hooks, fetch, Promise...);
- a lost or masked error, a fallback to a default, a zero value instead of an error;
- non-atomicity, races, a missing transaction, check-then-act;
- resource leaks, unclosed bodies, missing timeouts or limits;
- money arithmetic in floats, rounding;
- configuration: read and unused, a default that masks absence;
- tests that do not test (skips, mocks, timer-based waits);
- contract drift (backend sends one thing, client reads another) — if
  recognizable from the code.
Project specifics (particular tables, endpoints, business rules) — record too,
with universal=low: that is a candidate for the project's own linter.

NOT_RULEABLE: business logic, values, layout, texts, infrastructure settings
without a common pattern, fixes where the defect is not visible in the code
(an external service changed behaviour, data in the database), tuning to an
external API's limits or filters (rate limits, page sizes, event filters).

COVERED: if the class is already in RULES — check against the rule whether it
would catch this exact code. If the rule exists but misses this variant, that
is valuable: record a candidate with covered_by=<rule> and explain in
covered_note what the rule lacked. If it would catch it — just COVERED (not in
the JSONL, only in the counter). A commit whose only finding is an antipattern
the fix introduced and an existing rule catches is COVERED too.

## OUT format (JSONL, one line per record)
A record has one of two kinds (field kind):
- "defect" — a defect in the code BEFORE the fix that the fix removed;
- "introduced" — the fix itself added an antipattern (turned an error into a
  zero, a fallback to a default, context.Background, error classification by
  text...). That code stayed in the project; it is material for a rule too.

{"kind":"defect|introduced","commit":"<short hash>","date":"YYYY-MM-DD",
 "class":"<kebab-case name of the bug class, general, no project names>",
 "lang":"go|ts|sql|yaml|shell|docker|other",
 "before":"<1-3 lines: what the defective code looked like, abridged>",
 "after":"<1-2 lines: what the fix did>",
 "why_bug":"<one sentence: what broke>",
 "detect":"syntactic|typed|flow|cross-file|cross-lang",
 "detector":"<one or two sentences: by which sign a rule would find the code BEFORE the fix>",
 "universal":"high|medium|low",
 "covered_by":"<glint rule or none>",
 "covered_note":"<if covered_by is not none: what the rule lacked>"}

universal: high - any project of the language; medium - a library or a
domain beyond this project (payments, blockchain integrations); low - this
project only. detect cross-lang: the defect is a mismatch between code in two
languages (a Go response field against a TS type).

For "introduced", before/after describe the code the fix added (before —
what was there, after — what came, the antipattern is in after).

The last line of OUT is the summary:
{"summary":true,"total":N,"candidate_commits":N,"records":N,"covered":N,"not_ruleable":N,"duplicate":N,
 "notes":"<2-4 sentences: recurring themes of the batch, what deserves a deeper look>"}
total = candidate_commits + covered + not_ruleable + duplicate (by commits);
records — the number of defect|introduced records.

Append candidates to OUT as you go, so the work is not lost. Choose class
names descriptive and general (`sql-rows-err-not-checked`,
`react-effect-missing-cleanup`), so that the same bugs from different batches
merge into one class.
