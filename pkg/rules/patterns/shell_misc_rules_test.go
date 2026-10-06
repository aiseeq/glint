package patterns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// writeFiles writes files under a root.
func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, source := range files {
		full := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(source), 0o644))
	}
}

// shellFindingsIn runs a registered rule over files already written under a
// root, the root being the project.
func shellFindingsIn(t *testing.T, name, root string, paths ...string) []string {
	t.Helper()
	rule, ok := rules.Get(name)
	require.True(t, ok, name)
	var found []*core.Violation
	for _, p := range paths {
		full := filepath.Join(root, p)
		data, err := os.ReadFile(full)
		require.NoError(t, err)
		ctx, err := core.NewFileContextChecked(full, root, data, core.DefaultConfig())
		require.NoError(t, err)
		found = append(found, rule.AnalyzeFile(ctx)...)
	}
	return foundLines(found)
}

// Repro from a real project: a captured id-to-name function answered an
// unknown id with a made-up name from its *) arm, and a typo ran another agent.
func TestShellCaseDefaultInventsValue(t *testing.T) {
	shellWanted(t, "shell-case-default-invents-value", "lib.sh", `#!/bin/bash
agent_name() { case "$1" in p[0-9]*) echo "Slow${1^^}";; c[0-9]*) echo "Fast${1^^}";; *) echo "Agent${1^^}";; esac; } # want
agent_kind() {
  case "$1" in
    ar*|mr*) echo Red ;;
    ag*|mg*) echo Green ;;
    *) echo Blue ;; # want
  esac
}
name_of() { case "$1" in v[0-9]*) agent_name "$1";; *) echo "$1";; esac; }
kind_of() { case "$1" in v*) echo v;; *) echo "unknown id $1" >&2; return 1;; esac; }
# One special name and a rule for the rest is a naming scheme, not a table.
full_name() { case "$1" in ar) echo Agent;; *) echo "Agent${1^^}";; esac; }
n=$(agent_name "$v"); r=$(agent_kind "$v"); m=$(name_of "$v"); k=$(kind_of "$v"); f=$(full_name "$v")
`)
}

// Repro from a real project: grep -c "WINNER: $name" counted the wins of
// p1 for p11 too - the name was a prefix of another.
func TestShellGrepLabelPrefix(t *testing.T) {
	shellWanted(t, "shell-grep-label-prefix-match", "score.sh", `#!/bin/bash
w=$(echo "$out" | grep -c "WINNER: ${name:-none}") || w=0 # want
echo "$out" | grep -q "status: $state" && ok=1 # want
x=$(echo "$out" | grep -cx "WINNER: $name") || x=0
y=$(echo "$out" | grep -cw "WINNER: $name") || y=0
z=$(echo "$out" | grep -c "WINNER: $name\$") || z=0
grep -q "$pattern" "$f"
grep -q "proxy_pass http://127.0.0.1:$port" "$conf"
`)
}

// Repro from a real project: ssh host "open \"$rep\"" with a file name from
// the argument - the remote shell expanded $ and backquotes in the name.
func TestShellSSHQuotedArgument(t *testing.T) {
	shellWanted(t, "shell-ssh-double-quoted-argument", "watch.sh", `#!/bin/bash
arg=$1
rep="\$HOME/files/$(basename "$arg")"
ssh "$PC" "~/tools/viewer.sh open \"$rep\"" # want
ssh "$PC" "~/tools/viewer.sh open $(printf '%q' "$rep")"
ssh "$PC" "systemctl restart \"$service\""
`)
}

// Repro from a real project: rm -rf "$repo/dist/$name" with the name from
// the second argument - an argument with .. or / removed something else.
func TestShellRmRfArgument(t *testing.T) {
	shellWanted(t, "shell-rm-rf-unvalidated-argument", "pack.sh", `#!/bin/bash
v=$1
name=${2:-$(agent_name "$v")}
out=$repo/dist/$name
rm -rf "$out" # want
rm -rf "$repo/build/$1" # want
`)
	shellWanted(t, "shell-rm-rf-unvalidated-argument", "checked.sh", `#!/bin/bash
name=$1
case "$name" in */*|*..*|"") echo "bad name" >&2; exit 2;; esac
rm -rf "$repo/dist/$name"
tmp=$(mktemp -d)
rm -rf "$tmp"
work=$(mktemp -d "/tmp/$1-XXXXXX")
rm -rf "$work"
host_dir() { local h="$hosts/$1"; rm -rf "$h"; }
`)
}

// Repro from a real project: a release script ran go build in a module a
// go.work with a local sibling included - the binary was built against the
// sibling's working tree instead of the released version.
func TestShellGoBuildWithoutGoworkOff(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.work":           "go 1.24\n\nuse (\n\t./app\n\t../kit\n)\n",
		"app/go.mod":        "module example.com/app\n\ngo 1.24\n",
		"app/tools/pack.sh": "#!/bin/bash\n(cd \"$repo\" && CGO_ENABLED=0 GOOS=linux go build -trimpath -o \"$out/app\" ./cmd/app)\nGOWORK=off GOOS=linux go build -trimpath -o \"$out/tool\" ./cmd/tool\n",
		"app/tools/dev.sh":  "#!/bin/bash\ngo build -o bin/app ./cmd/app\n",
	})
	assert.Equal(t, []string{"app/tools/pack.sh:2"}, shellFindingsIn(t, "shell-go-build-without-gowork-off", root, "app/tools/pack.sh", "app/tools/dev.sh"))
}

// Repro from a real project: two scripts classified agent ids with case
// statements that had drifted apart - one knew a family the other sent to
// the wrong arm.
func TestShellCaseDrift(t *testing.T) {
	assert.Equal(t, []string{"batch.sh:2"}, shellFindings(t, "shell-case-patterns-drift", map[string]string{
		"batch.sh": `#!/bin/bash
name_of() { case "$1" in a[0-9]*|b[0-9]*|k[xyz]*|solo|base) agent_name "$1";; *) echo "$1";; esac; }
`,
		"match.sh": `#!/bin/bash
resolve() { case "$1" in a[0-9]*|ab[0-9]*|b[0-9]*|k[xyz]*|q[xyz][0-9]*|solo|base) install_version "$1";; *) fetch "$1";; esac; }
`,
		"other.sh": `#!/bin/bash
mode() { case "$1" in start|stop) run "$1";; *) usage;; esac; }
`,
	}))
}

// Repro from a real project: an export after a ; in a trailing comment - the
// author thought it ran, and the command never did.
func TestShellCommandInComment(t *testing.T) {
	shellWanted(t, "shell-command-in-comment", "env.sh", `#!/bin/bash
P=$(pgrep -f '[d]aemon\.sh' | head -1)   # [s] keeps pgrep off itself; export $(tr '\0' '\n' < /proc/$P/environ | grep -E '^DISPLAY') # want
x=1   # one; two words, nothing to run
y=2   # see $(git log) for why
`)
}

// Repro from a real project: git rev-parse --git-path printed a path relative
// to the repository, and after cd into the worktree the script stat-ed
// another file.
func TestShellGitPathRelative(t *testing.T) {
	shellWanted(t, "shell-git-path-relative", "merge.sh", `#!/bin/bash
lock=$(git -C "$repo" rev-parse --git-path index.lock) # want
abs=$(git -C "$repo" rev-parse --path-format=absolute --git-path index.lock)
dir=$(git -C "$repo" rev-parse --absolute-git-dir)
cd "$wt"
m=$(stat -c %Y "$lock" 2>/dev/null) || return 0
`)
	shellWanted(t, "shell-git-path-relative", "stay.sh", `#!/bin/bash
lock=$(git rev-parse --git-path index.lock)
[ -e "$lock" ] && exit 1
cp "$(git rev-parse --git-path index)" "$idx"
`)
	shellWanted(t, "shell-git-path-relative", "move.sh", `#!/bin/bash
taken=$(git rev-parse --git-path taken) # want
cd "$wt"
cat "$taken"
`)
	shellWanted(t, "shell-git-path-relative", "sub.sh", `#!/bin/bash
cd "$wt"
taken=$(git rev-parse --git-path taken)
(cd "$repo" && git status)
cat "$taken"
`)
}

// Repro from a real project: PEER_KEY=${strat:+mode-$strat} ./match.sh - with
// no strategy argument the prefix set PEER_KEY to empty and wiped the value
// the caller exported.
func TestShellPrefixClearsEnvironment(t *testing.T) {
	shellWanted(t, "shell-prefix-assignment-clears-env", "series.sh", `#!/bin/bash
strat=${3:-}
RUN_HOST=${RUN_HOST:-pc} PEER_KEY=${strat:+mode-$strat} ./match.sh "$1" # want
MODE=${mode:+fast} ./run.sh
MODE=slow
`)
}

// Repro from a real project: a script and the sibling it called found the
// same directory through different variables - an override of one moved
// only half of the work.
func TestShellSiblingPathVariable(t *testing.T) {
	assert.Equal(t, []string{"get.sh:3"}, shellFindings(t, "shell-sibling-path-variable-differs", map[string]string{
		"get.sh": `#!/bin/bash
agents=${APP_AGENTS:-$HOME/farm/agents}
"$(dirname "$0")/fix.sh" "$name"
FARM_AGENTS="$agents" "$(dirname "$0")/fix.sh" "$name"
`,
		"fix.sh": `#!/bin/bash
dir=${FARM_AGENTS:-$HOME/farm/agents}/$1
`,
	}))
}

// Repro from a real project: go test ./... with no -p in three entry points -
// two of them at once loaded the machine past what it could serve.
func TestShellGoTestWithoutParallelLimit(t *testing.T) {
	shellWanted(t, "go-test-without-parallel-limit", "Makefile", `test:
  @go test -timeout 30m ./... # want
fast:
  go test -p 4 ./...
one:
  go test ./internal/x/
`)
	shellWanted(t, "go-test-without-parallel-limit", "smoke.sh", `#!/bin/bash
go test -timeout 30m ./... # want
go test -p=2 ./...
`)
}

// Repro from a real project: the hand-written list of scripts copied to the
// stage left out a library one of them sourced.
func TestShellCopyListMissesSourced(t *testing.T) {
	assert.Equal(t, []string{"tools/stage.sh:2"}, shellFindings(t, "shell-copy-list-misses-sourced", map[string]string{
		"tools/stage.sh": `#!/bin/bash
(cd "$tools" && cp match.sh lib.sh bootstrap.sh "$stage/run/tools/")
(cd "$tools" && cp match.sh lib.sh bootstrap.sh limits.sh "$stage/run/tools/")
`,
		"tools/bootstrap.sh": `#!/bin/bash
. "$(dirname "$0")/limits.sh"
`,
		"tools/match.sh":  "#!/bin/bash\n. \"$(dirname \"$0\")/lib.sh\"\n",
		"tools/lib.sh":    "#!/bin/bash\n",
		"tools/limits.sh": "#!/bin/bash\n",
	}))
}

// Repro from a real project: a script pointed at a docker volume by its
// generated id - the volume was recreated and the path led nowhere.
func TestShellDockerVolumeIDPath(t *testing.T) {
	shellWanted(t, "shell-docker-volume-id-path", "data.sh", `#!/bin/bash
VOL=/var/lib/docker/volumes/4f2a9e0b7c13d58e6a0f42b91c7d3e58a6b0c4d29e7f13a85b6c0d4e2f9a71c3/_data # want
VOL2=$(docker volume inspect -f '{{.Mountpoint}}' app_data)
VOL3=/var/lib/docker/volumes/app_data/_data
`)
}

// Repro from a real project: docker logs --since 6s on every poll read the
// whole window of a chatty container each second.
func TestShellDockerLogsSinceWithoutTail(t *testing.T) {
	shellWanted(t, "shell-docker-logs-since-without-tail", "watch.sh", `#!/bin/bash
for i in $(seq 1 60); do
  sudo -n docker logs --since 6s "$w" 2>&1 | grep -qE 'ready' && break # want
  docker logs --since 6s --tail 200 "$w" 2>&1 | grep -q x && break
  sleep 1
done
docker logs --since 10m "$w" > "$log" 2>&1
`)
}
