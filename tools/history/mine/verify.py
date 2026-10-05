#!/usr/bin/env python3
"""usage: verify.py <repo> <candidates.jsonl | manifest.tsv> <workdir> <out.jsonl> [--sibling NAME=REPO ...]

For every candidate commit, runs the current glint (all rules, no project
config) on the directories of the files the commit changed, on the tree the
record is about: the parent for kind=defect (the code before the fix), the
commit itself for kind=introduced (the code the fix left). Reports the rules
that fire on the lines the commit removed (defect) or added (introduced), +-1.
Only reads the repository: trees come from git archive.

A module that reaches a sibling repository through a local replace in go.mod
(replace example.com/lib => ../../lib/backend) does not type-check alone:
--sibling lib=/path/to/lib extracts that repository, as it was at the date of
the analyzed tree, to where the replace points. When packages still fail to
type-check on the tree before a fix, the sibling as of the fix's date is tried
too: that tree was often built against sibling changes committed later.

A manifest (.tsv, `commit kind rule[,rule...] [@path:line] [whole-tree]` per line) is the
acceptance of new rules: only the listed rules run, every line is checked
afresh and on its own - lines of one commit and kind share a glint run, not a
verdict - and the lines where none of its rules fired are printed as misses;
the exit status is 1 when there is one. A rule that reports the defect on a
line the commit did not change (a setter, a line the fix kept) is anchored
with @path:line in the analyzed tree. A rule that compares files across the
repository (a TS set against a Go type) is run with whole-tree: glint checks
the whole tree from its top instead of each changed file's module.
"""
import json, os, re, shutil, subprocess, sys
from collections import defaultdict

repo, cand_path, work, out_path = sys.argv[1:5]
siblings = {}
rest = sys.argv[5:]
while rest:
    flag, value, *rest = rest
    name, _, path = value.partition('=')
    if flag != '--sibling' or not name or not path:
        sys.exit(f'unknown argument {flag} {value}: expected --sibling NAME=REPO')
    siblings[name] = os.path.expanduser(path)
LOCAL_REPLACE = re.compile(r'=>\s*(\.\.?/\S+)')
CODE = re.compile(r'\.(go|ts|tsx|js|jsx|mjs|sh|mk|dockerfile)$|(^|/)(GNUmakefile|[Mm]akefile|Dockerfile(\.[\w-]+)?|Containerfile|(docker-)?compose[\w.-]*\.ya?ml)$')


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
    # A module at the top of the repository is the whole tree: its packages
    # import each other and type-check only together.
    if 'go.mod' in tree_files:
        return '.'
    return os.path.dirname(path) or '.'


def provide_siblings(target, at):
    """Extracts the sibling repositories a local replace of target's go.mod
    points to, as they were at the date of commit at; a path already holding
    that revision is kept. Returns whether target has such a replace."""
    gomod = os.path.join(target, 'go.mod')
    if not siblings or not os.path.exists(gomod):
        return False
    date = git('log', '-1', '--format=%cI', at).strip()
    provided = False
    for rel in LOCAL_REPLACE.findall(open(gomod).read()):
        parts = [p for p in rel.split('/') if p not in ('.', '..')]
        if not parts or parts[0] not in siblings:
            continue
        provided = True
        sibling, sub = siblings[parts[0]], '/'.join(parts[1:])
        dest = os.path.normpath(os.path.join(target, rel))
        rev = subprocess.run(['git', '-C', sibling, 'rev-list', '-1', '--before=' + date, 'HEAD'],
                             capture_output=True, text=True, check=True).stdout.strip()
        marker = dest + '.rev'
        if os.path.exists(marker) and open(marker).read() == rev:
            continue
        shutil.rmtree(dest, ignore_errors=True)
        top = dest[:len(dest) - len(sub)].rstrip('/') if sub else dest
        os.makedirs(top, exist_ok=True)
        archive = subprocess.run(['git', '-C', sibling, 'archive', rev, *([sub] if sub else [])],
                                 capture_output=True, check=True).stdout
        subprocess.run(['tar', '-x', '-C', top], input=archive, stderr=subprocess.DEVNULL)
        with open(marker, 'w') as f:
            f.write(rev)
    return provided


def run(commit, tree, side, rules, anchors=(), whole=False):
    lines = changed_lines(commit, side)
    changed = {p: set(s) for p, s in lines.items()}
    for anchor in anchors:
        path, line = anchor.rsplit(':', 1)
        lines.setdefault(path, set()).add(int(line))
    if not lines:
        return {'status': 'no-code-lines'}
    tree_files = set(git('ls-tree', '-r', '--name-only', tree).split())
    by_root = defaultdict(list)
    for path in lines:
        by_root['.' if whole else module_root(path, tree_files)].append(path)
    fired = defaultdict(set)
    # hits keep where each rule fired: on a changed line, or on which anchor.
    hits = set()
    errors = []
    total = 0
    skipped = 0
    for root in sorted(by_root):
        # One directory per root, so that the result cache of the previous
        # commit's tree serves the files that did not change.
        dest = os.path.join(work, 'top' if root == '.' else root.replace('/', '__'))
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest)
        # Files at the top of the repository come alone, not with the whole
        # tree - unless the top is a Go module, which is the whole tree.
        top_module = root == '.' and 'go.mod' in tree_files
        paths = [] if whole or top_module else by_root[root] if root == '.' else [root]
        archive = subprocess.run(['git', '-C', repo, 'archive', tree, *paths], capture_output=True, check=True).stdout
        # Historical trees may hold entries tar refuses (a symlink with a file
        # body): skip them, the Go and TS sources extract.
        subprocess.run(['tar', '-x', '-C', dest], input=archive, stderr=subprocess.DEVNULL)
        target = os.path.join(dest, root)
        # Today's rules run without the project's configuration: its
        # exceptions would hide the very findings the replay looks for.
        for config in {os.path.join(dest, '.glint.yaml'), os.path.join(target, '.glint.yaml')}:
            if os.path.exists(config):
                os.remove(config)
        args = ['glint', 'check', '--tolerate-broken-packages', '--output=json', '--min-severity=low']
        if rules:
            args.append('--rule=' + ','.join(rules))
        report, failure = None, None
        # The tree before a fix was often built against sibling changes
        # committed later, up to the fix itself: when packages do not
        # type-check with the sibling of the tree's date, the sibling of the
        # fix's date is tried, and the run with fewer of them kept.
        for at in ([tree, commit] if tree != commit else [tree]):
            if not provide_siblings(target, at) and at != tree:
                break
            proc = subprocess.run([*args, '.'], cwd=target, capture_output=True, text=True)
            try:
                attempt = json.loads(proc.stdout)
            except json.JSONDecodeError:
                failure = f'{root}: exit {proc.returncode}: {proc.stderr.strip()[:300]}'
                continue
            if report is None or attempt.get('stats', {}).get('packagesSkipped', 0) < report.get('stats', {}).get('packagesSkipped', 0):
                report = attempt
            if not report.get('stats', {}).get('packagesSkipped', 0):
                break
        if report is None:
            errors.append(failure)
            continue
        issues = report.get('issues') or []
        skipped = max(skipped, report.get('stats', {}).get('packagesSkipped', 0))
        total += len(issues)
        for issue in issues:
            rel = os.path.normpath(os.path.join(root, issue['file']))
            want = lines.get(rel)
            near = (issue['line'] - 1, issue['line'], issue['line'] + 1)
            if want and any(n in want for n in near):
                fired[rel].add(issue['rule'])
                if any(n in changed.get(rel, ()) for n in near):
                    hits.add((issue['rule'], 'changed'))
                for anchor in anchors:
                    path, line = anchor.rsplit(':', 1)
                    if path == rel and int(line) in near:
                        hits.add((issue['rule'], anchor))
    return {'status': 'ok' if not errors else 'partial', 'errors': errors, 'files': sorted(lines),
            'issues_in_roots': total, 'packages_skipped': skipped, 'fired': {p: sorted(r) for p, r in fired.items()},
            'hits': sorted(hits)}


manifest = cand_path.endswith('.tsv')
expected = defaultdict(set)
# checks are the manifest lines of each commit and kind: (rules, anchor or None).
checks = defaultdict(list)
if manifest:
    whole = set()
    for line in open(cand_path):
        if line.strip() and not line.startswith('#'):
            commit, kind, rules, *rest = line.split()
            expected[(commit, kind)].update(rules.split(','))
            anchor = None
            for token in rest:
                if token == 'whole-tree':
                    whole.add((commit, kind))
                else:
                    anchor = token.lstrip('@')
            checks[(commit, kind)].append((rules.split(','), anchor))
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
            res = run(commit, tree, side, rules,
                      [a for _, a in checks[(commit, kind)] if a] if manifest else (),
                      manifest and (commit, kind) in whole)
        except subprocess.CalledProcessError as e:
            res = {'status': 'error', 'errors': [str(e)[:300]]}
        res.update(commit=commit, kind=kind)
        if manifest:
            # A line is hit by one of its own rules, on a changed line or on
            # its own anchor; another line's rule or anchor does not count.
            hits = {tuple(h) for h in res.get('hits', [])}
            verdicts = []
            for line_rules, anchor in checks[(commit, kind)]:
                hit = any((r, 'changed') in hits or (anchor and (r, anchor) in hits) for r in line_rules)
                verdicts.append(hit)
                if not hit:
                    misses.append(f'{commit} {kind} {",".join(line_rules)}' + (f' @{anchor}' if anchor else '') + f' {res["status"]}')
            res.update(expected=rules, hit=all(verdicts))
        out.write(json.dumps(res, ensure_ascii=False) + '\n')
        out.flush()
        print(f'{i + 1}/{len(jobs)} {commit} {kind} {res["status"]}' + (f' hit={res["hit"]}' if manifest else ''), flush=True)
if manifest:
    print(f'misses: {len(misses)} of {sum(len(c) for c in checks.values())}')
    for miss in misses:
        print('  ' + miss)
    sys.exit(1 if misses else 0)
