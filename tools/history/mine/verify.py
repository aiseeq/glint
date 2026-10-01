#!/usr/bin/env python3
"""usage: verify.py <repo> <candidates.jsonl | manifest.tsv> <workdir> <out.jsonl>

For every candidate commit, runs the current glint (all rules, no project
config) on the directories of the files the commit changed, on the tree the
record is about: the parent for kind=defect (the code before the fix), the
commit itself for kind=introduced (the code the fix left). Reports the rules
that fire on the lines the commit removed (defect) or added (introduced), +-1.
Only reads the repository: trees come from git archive.

A manifest (.tsv, `commit kind rule[,rule...] [@path:line] [whole-tree]` per line) is the
acceptance of new rules: only the listed rules run, every line is checked
afresh, and the lines where none of its rules fired are printed as misses;
the exit status is 1 when there is one. A rule that reports the defect on a
line the commit did not change (a setter, a line the fix kept) is anchored
with @path:line in the analyzed tree. A rule that compares files across the
repository (a TS set against a Go type) is run with whole-tree: glint checks
the whole tree from its top instead of each changed file's module.
"""
import json, os, re, shutil, subprocess, sys
from collections import defaultdict

repo, cand_path, work, out_path = sys.argv[1:5]
CODE = re.compile(r'\.(go|ts|tsx|js|jsx|mjs|sh|mk)$|(^|/)(GNUmakefile|[Mm]akefile)$')


def git(*args):
    return subprocess.run(['git', '-C', repo, *args], capture_output=True, text=True, check=True).stdout


def changed_lines(commit, side):
    """side 'old': removed lines in parent numbering; 'new': added lines."""
    diff = git('show', '--format=', '-U0', '--no-renames', commit)
    lines = defaultdict(set)
    path = None
    for line in diff.splitlines():
        if line.startswith('--- '):
            old = line[4:]
            old_path = None if old == '/dev/null' else old[2:]
        elif line.startswith('+++ '):
            new = line[4:]
            new_path = None if new == '/dev/null' else new[2:]
            path = old_path if side == 'old' else new_path
        elif line.startswith('@@') and path and CODE.search(path):
            m = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
            start, count = (m.group(1), m.group(2)) if side == 'old' else (m.group(3), m.group(4))
            start, count = int(start), int(count if count is not None else 1)
            for n in range(start, start + count):
                lines[path].add(n)
    return {p: s for p, s in lines.items() if s}


def module_root(path, tree_files):
    """Top directory to extract for a file: its Go module or its own directory."""
    parts = path.split('/')
    for i in range(len(parts) - 1, 0, -1):
        if '/'.join(parts[:i]) + '/go.mod' in tree_files:
            return '/'.join(parts[:i])
    return os.path.dirname(path) or '.'


def run(commit, tree, side, rules, anchor=None, whole=False):
    lines = changed_lines(commit, side)
    if anchor:
        path, line = anchor.rsplit(':', 1)
        lines.setdefault(path, set()).add(int(line))
    if not lines:
        return {'status': 'no-code-lines'}
    tree_files = set(git('ls-tree', '-r', '--name-only', tree).split())
    by_root = defaultdict(list)
    for path in lines:
        by_root['.' if whole else module_root(path, tree_files)].append(path)
    fired = defaultdict(set)
    errors = []
    total = 0
    skipped = 0
    for root in sorted(by_root):
        # One directory per root, so that the result cache of the previous
        # commit's tree serves the files that did not change.
        dest = os.path.join(work, 'top' if root == '.' else root.replace('/', '__'))
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest)
        # Files at the top of the repository come alone, not with the whole tree.
        paths = [] if whole else by_root[root] if root == '.' else [root]
        archive = subprocess.run(['git', '-C', repo, 'archive', tree, *paths], capture_output=True, check=True).stdout
        # Historical trees may hold entries tar refuses (a symlink with a file
        # body): skip them, the Go and TS sources extract.
        subprocess.run(['tar', '-x', '-C', dest], input=archive, stderr=subprocess.DEVNULL)
        target = os.path.join(dest, root)
        issues = []
        for rule in rules or [None]:
            args = ['glint', 'check', '--tolerate-broken-packages', '--output=json', '--min-severity=low']
            if rule:
                args.append('--rule=' + rule)
            proc = subprocess.run([*args, '.'], cwd=target, capture_output=True, text=True)
            try:
                report = json.loads(proc.stdout)
            except json.JSONDecodeError:
                errors.append(f'{root}: exit {proc.returncode}: {proc.stderr.strip()[:300]}')
                continue
            issues += report.get('issues') or []
            skipped = max(skipped, report.get('stats', {}).get('packagesSkipped', 0))
        total += len(issues)
        for issue in issues:
            rel = os.path.normpath(os.path.join(root, issue['file']))
            want = lines.get(rel)
            if want and any(n in want for n in (issue['line'] - 1, issue['line'], issue['line'] + 1)):
                fired[rel].add(issue['rule'])
    return {'status': 'ok' if not errors else 'partial', 'errors': errors, 'files': sorted(lines),
            'issues_in_roots': total, 'packages_skipped': skipped, 'fired': {p: sorted(r) for p, r in fired.items()}}


manifest = cand_path.endswith('.tsv')
expected = defaultdict(set)
if manifest:
    anchors = {}
    whole = set()
    for line in open(cand_path):
        if line.strip() and not line.startswith('#'):
            commit, kind, rules, *rest = line.split()
            expected[(commit, kind)].update(rules.split(','))
            for token in rest:
                if token == 'whole-tree':
                    whole.add((commit, kind))
                else:
                    anchors[(commit, kind)] = token.lstrip('@')
    dates = {c: git('log', '-1', '--format=%ad', '--date=short', c).strip() for c, _ in expected}
    jobs = sorted((dates[c], c, k) for c, k in expected)
else:
    records = [json.loads(l) for l in open(cand_path) if l.strip()]
    jobs = sorted({(r['date'], r['commit'], r.get('kind') or 'defect') for r in records})
# Oldest first: neighbouring trees share most files, and the result cache
# serves them. A candidate run resumes where it stopped; a manifest is
# checked afresh.
done = set()
if not manifest and os.path.exists(out_path):
    for l in open(out_path):
        d = json.loads(l)
        done.add((d['commit'], d['kind']))
misses = []
with open(out_path, 'a' if not manifest else 'w') as out:
    for i, (_, commit, kind) in enumerate(jobs):
        if (commit, kind) in done:
            continue
        side = 'old' if kind == 'defect' else 'new'
        tree = commit + '^' if kind == 'defect' else commit
        rules = sorted(expected[(commit, kind)]) if manifest else None
        try:
            res = run(commit, tree, side, rules, anchors.get((commit, kind)) if manifest else None,
                      manifest and (commit, kind) in whole)
        except subprocess.CalledProcessError as e:
            res = {'status': 'error', 'errors': [str(e)[:300]]}
        res.update(commit=commit, kind=kind)
        if manifest:
            fired = {r for rs in res.get('fired', {}).values() for r in rs}
            res.update(expected=rules, hit=bool(fired & set(rules)))
            if not res['hit']:
                misses.append(f'{commit} {kind} {",".join(rules)} {res["status"]}')
        out.write(json.dumps(res, ensure_ascii=False) + '\n')
        out.flush()
        print(f'{i + 1}/{len(jobs)} {commit} {kind} {res["status"]}' + (f' hit={res["hit"]}' if manifest else ''), flush=True)
if manifest:
    print(f'misses: {len(misses)} of {len(jobs)}')
    for miss in misses:
        print('  ' + miss)
    sys.exit(1 if misses else 0)
