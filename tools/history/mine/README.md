# Mining fix history for rule candidates

Finds bug classes a project fixed by hand that glint could catch: the fix
commits of a repository are triaged by agents in batches, their records are
grouped into classes, and a replay of today's glint on the tree before every
fix shows whether it stays silent there. Every step only reads the
repository: commits come from `git log`/`git show`, trees from `git archive`.

## Steps

1. **List the fixes.** `prepare.sh REPO OUT [BATCH_SIZE]` keeps the
   Conventional Commits `fix`/`security`/`perf` subjects, drops analyzer,
   formatting and documentation work and commits that touch only documents,
   orders them oldest first and splits them into `batch-NN.tsv` (180 by
   default). It saves `glint rules` next to them as the list of what is
   already caught.

2. **Pilot.** Triage about 30 commits of one batch by `triage.md` and read the
   records before starting the rest: the instructions are what makes records
   of different batches comparable, and a pilot is where they get corrected.

3. **Triage.** One agent per batch, all following `triage.md`, with REPO,
   BATCH, RULES (the saved rule list), GLINT_SRC (a glint checkout) and OUT
   (`out-NN.jsonl`, a file of its own). Agents that run in parallel must be
   told not to touch the repository's working tree. A batch of 180 commits
   costs an agent about 200–450 thousand tokens.

4. **Merge.** `merge.sh OUT` prints the batch summaries and the classes with
   their counts, languages, universality, the glint rules that missed them and
   the commits, and writes `all-candidates.jsonl`. Agents name one class in
   different words: group the names into families by hand before ranking.

5. **Replay.** `verify.py REPO OUT/all-candidates.jsonl WORK OUT/verify.jsonl`
   extracts, for each record, the tree the record is about (the parent for a
   defect, the commit itself for an antipattern the fix introduced), runs
   today's glint with every rule and no project configuration on the Go module
   or directory of each changed file, and lists the rules firing on the lines
   the commit removed or added. Commits are replayed oldest first into the
   same directories, so the result cache serves the files that did not change;
   the run can be stopped and resumed. `packages_skipped` counts the packages
   of the tree that did not type-check: typed rules are silent in them.

   The same script accepts new rules: given a manifest (`.tsv`, one
   `commit kind rule[,rule...]` per line — the commits a rule must catch), it
   runs only those rules, checks every line afresh and prints the lines where
   none of its rules fired; the exit status is 1 while there is one.

6. **Rank.** Per family: how many commits, how universal, how hard to detect
   (syntactic, typed, flow, cross-file), which existing rule missed it and
   why. A gap of an existing rule is usually cheaper than a new rule; a class
   another linter the project already runs covers is not glint's. Estimate
   the noise of a draft detector on the current code before proposing a rule.

## Outputs

- `batch-NN.tsv` — `hash date changed_files subject`, oldest first.
- `out-NN.jsonl` — records in the format `triage.md` describes, then a summary line.
- `all-candidates.jsonl` — every record of every batch.
- `verify.jsonl` — per commit and kind: changed files, the rules that fired on
  the changed lines, the findings in the analyzed roots, skipped packages.
