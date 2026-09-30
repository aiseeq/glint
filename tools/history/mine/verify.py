#!/usr/bin/env python3
"""usage: verify.py <repo> <candidates.jsonl> <workdir> <out.jsonl>

For every candidate commit, runs the current glint (all rules, no project
config) on the directories of the files the commit changed, on the tree the
record is about: the parent for kind=defect (the code before the fix), the
commit itself for kind=introduced (the code the fix left). Reports the rules
that fire on the lines the commit removed (defect) or added (introduced), +-1.
Only reads the repository: trees come from git archive.
"""
import json, os, re, shutil, subprocess, sys
from collections import defaultdict

repo, cand_path, work, out_path = sys.argv[1:5]
CODE = re.compile(r'\.(go|ts|tsx|js|jsx|mjs)$')


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


def run(commit, tree, side):
    lines = changed_lines(commit, side)
    if not lines:
        return {'status': 'no-code-lines'}
    tree_files = set(git('ls-tree', '-r', '--name-only', tree).split())
    by_root = defaultdict(list)
    for path in lines:
        by_root[module_root(path, tree_files)].append(path)
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
        paths = by_root[root] if root == '.' else [root]
        archive = subprocess.run(['git', '-C', repo, 'archive', tree, *paths], capture_output=True, check=True).stdout
        # Historical trees may hold entries tar refuses (a symlink with a file
        # body): skip them, the Go and TS sources extract.
        subprocess.run(['tar', '-x', '-C', dest], input=archive, stderr=subprocess.DEVNULL)
        target = os.path.join(dest, root)
        proc = subprocess.run(['glint', 'check', '--tolerate-broken-packages', '--output=json', '--min-severity=low', '.'],
                              cwd=target, capture_output=True, text=True)
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            errors.append(f'{root}: exit {proc.returncode}: {proc.stderr.strip()[:300]}')
            continue
        total += len(report.get('issues') or [])
        skipped += report.get('stats', {}).get('packagesSkipped', 0)
        for issue in report.get('issues') or []:
            rel = os.path.normpath(os.path.join(root, issue['file']))
            want = lines.get(rel)
            if want and any(n in want for n in (issue['line'] - 1, issue['line'], issue['line'] + 1)):
                fired[rel].add(issue['rule'])
    return {'status': 'ok' if not errors else 'partial', 'errors': errors, 'files': sorted(lines),
            'issues_in_roots': total, 'packages_skipped': skipped, 'fired': {p: sorted(r) for p, r in fired.items()}}


records = [json.loads(l) for l in open(cand_path) if l.strip()]
# Oldest first: neighbouring trees share most files, and the result cache
# serves them.
jobs = sorted({(r['date'], r['commit'], r.get('kind') or 'defect') for r in records})
done = set()
if os.path.exists(out_path):
    for l in open(out_path):
        d = json.loads(l)
        done.add((d['commit'], d['kind']))
with open(out_path, 'a') as out:
    for i, (_, commit, kind) in enumerate(jobs):
        if (commit, kind) in done:
            continue
        side = 'old' if kind == 'defect' else 'new'
        tree = commit + '^' if kind == 'defect' else commit
        try:
            res = run(commit, tree, side)
        except subprocess.CalledProcessError as e:
            res = {'status': 'error', 'errors': [str(e)[:300]]}
        res.update(commit=commit, kind=kind)
        out.write(json.dumps(res, ensure_ascii=False) + '\n')
        out.flush()
        print(f'{i + 1}/{len(jobs)} {commit} {kind} {res["status"]}', flush=True)
