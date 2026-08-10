#!/usr/bin/env python3
"""Build a quality curve over a repository's git history using glint.

Method (one instrument for the whole history):
- take a slice every N days (default 14) from the first commit to HEAD,
  following first-parent;
- for each slice: check out a detached worktree, remove the project
  .glint.yaml (full default rule set, no project exclusions), run
  `glint check --tolerate-broken-packages -o json`;
- count only findings in non-test .go files; normalize per 1000
  non-test Go lines (vendor/ and node_modules/ excluded).

If a rule hard-crashes on a historical slice (old trees can break
type-dependent rules), it is disabled for that slice only and recorded
in the output as `disabled_rules`.

Output: JSONL, one record per slice with aggregate numbers only.

Usage: measure.py REPO OUT.jsonl [--interval 14] [--glint PATH]
Plot per_kloc_crit_high over date to get the heavy-findings curve.
"""

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SEVERITIES = ["critical", "high", "medium", "low"]
RULE_FAIL_RE = re.compile(r'rule "([a-z0-9-]+)"')


def run(cmd, cwd=None, check=True):
    return subprocess.run(cmd, cwd=cwd, check=check,
                          capture_output=True, text=True)


def git(repo, *args, check=True):
    return run(["git", "-C", repo, *args], check=check).stdout


def slice_commits(repo, interval_days):
    """Last first-parent commit before each slice date."""
    log = git(repo, "log", "--first-parent", "--format=%H %cI",
              "--reverse").strip().splitlines()
    commits = []
    for line in log:
        h, iso = line.split(" ", 1)
        commits.append((h, dt.datetime.fromisoformat(iso)))
    start, end = commits[0][1], commits[-1][1]
    slices = []
    cur = start + dt.timedelta(days=interval_days)
    while cur <= end + dt.timedelta(days=interval_days):
        best = None
        for h, d in commits:
            if d <= cur:
                best = (h, d)
            else:
                break
        if best and (not slices or slices[-1][0] != best[0]):
            slices.append(best)
        cur += dt.timedelta(days=interval_days)
    if slices and slices[-1][0] != commits[-1][0]:
        slices.append(commits[-1])
    return slices


def go_sloc(root):
    total = files = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in ("vendor", "node_modules", ".git")]
        for f in filenames:
            if f.endswith(".go") and not f.endswith("_test.go"):
                files += 1
                try:
                    with open(os.path.join(dirpath, f), "rb") as fh:
                        total += sum(1 for _ in fh)
                except OSError:
                    pass
    return total, files


def rule_categories(glint_bin):
    out = run([glint_bin, "rules"], check=False).stdout
    cat, mapping = None, {}
    for line in out.splitlines():
        m = re.match(r"^\[(\w+)\]", line.strip())
        if m:
            cat = m.group(1)
            continue
        m = re.match(r"^\s{2}([a-z0-9-]+)\s", line)
        if m and cat:
            mapping[m.group(1)] = cat
    return mapping


def write_disable_config(wt, disabled, rule_cats):
    by_cat = {}
    for r in disabled:
        by_cat.setdefault(rule_cats.get(r, "patterns"), []).append(r)
    lines = ["version: 1", "categories:"]
    for cat, rules in by_cat.items():
        lines += [f"  {cat}:", "    rules:"]
        for r in rules:
            lines += [f"      {r}:", "        enabled: false"]
    with open(os.path.join(wt, ".glint.yaml"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


def analyze_slice(repo, commit, glint_bin):
    tmp = tempfile.mkdtemp(prefix="glint-slice-")
    wt = os.path.join(tmp, "wt")
    try:
        run(["git", "-C", repo, "worktree", "add", "--detach", wt, commit])
        for cfg in (".glint.yaml", ".glint.yml"):
            p = os.path.join(wt, cfg)
            if os.path.exists(p):
                os.remove(p)
        sloc, nfiles = go_sloc(wt)
        rec = {"commit": commit, "sloc": sloc, "go_files": nfiles}
        disabled, rule_cats, data = [], None, None
        for _ in range(6):
            proc = run([glint_bin, "check", "--tolerate-broken-packages",
                        "-o", "json", "."], cwd=wt, check=False)
            rec["glint_exit"] = proc.returncode
            try:
                data = json.loads(proc.stdout)
                break
            except json.JSONDecodeError:
                m = RULE_FAIL_RE.search(proc.stdout + proc.stderr)
                if not m or m.group(1) in disabled:
                    break
                if rule_cats is None:
                    rule_cats = rule_categories(glint_bin)
                disabled.append(m.group(1))
                write_disable_config(wt, disabled, rule_cats)
        if disabled:
            rec["disabled_rules"] = disabled
        if data is None:
            rec["error"] = "json_parse_failed"
            rec["stderr_tail"] = (proc.stdout + proc.stderr)[-500:]
            return rec
        issues = [i for i in data.get("issues") or []
                  if i.get("file", "").endswith(".go")
                  and not i.get("file", "").endswith("_test.go")]
        by_sev = {s: 0 for s in SEVERITIES}
        by_cat, by_rule = {}, {}
        for i in issues:
            sev = i.get("severity", "low")
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_cat[i.get("category", "?")] = by_cat.get(
                i.get("category", "?"), 0) + 1
            by_rule[i.get("rule", "?")] = by_rule.get(i.get("rule", "?"), 0) + 1
        rec.update({
            "total_go": len(issues),
            "by_severity": by_sev,
            "by_category": by_cat,
            "top_rules": dict(sorted(by_rule.items(),
                                     key=lambda kv: -kv[1])[:15]),
            "packages_skipped": (data.get("stats") or {}).get(
                "packagesSkipped", 0),
            "rules_run": (data.get("stats") or {}).get("rulesRun"),
        })
        if sloc:
            k = sloc / 1000.0
            rec["per_kloc_total"] = round(len(issues) / k, 2)
            rec["per_kloc_crit_high"] = round(
                (by_sev["critical"] + by_sev["high"]) / k, 2)
        return rec
    finally:
        run(["git", "-C", repo, "worktree", "remove", "--force", wt],
            check=False)
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("out")
    ap.add_argument("--interval", type=int, default=14)
    ap.add_argument("--glint", default="glint")
    args = ap.parse_args()

    slices = slice_commits(args.repo, args.interval)
    print(f"{len(slices)} slices", flush=True)
    with open(args.out, "w") as out:
        for n, (commit, date) in enumerate(slices, 1):
            rec = analyze_slice(args.repo, commit, args.glint)
            rec["date"] = date.date().isoformat()
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out.flush()
            print(f"[{n}/{len(slices)}] {date.date()} "
                  f"sloc={rec.get('sloc')} total={rec.get('total_go')} "
                  f"c+h/kloc={rec.get('per_kloc_crit_high')}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
