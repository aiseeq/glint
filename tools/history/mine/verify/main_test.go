package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseDiffTakesTheLinesOfCodeFiles(t *testing.T) {
	diff := `diff --git a/db/q.go b/db/q.go
index 1..2 100644
--- a/db/q.go
+++ b/db/q.go
@@ -3,2 +3 @@ func q() {
--- removed sql comment
-x := 1
+y := 2
@@ -10 +9,0 @@
-gone
diff --git a/docs/notes.md b/docs/notes.md
--- a/docs/notes.md
+++ b/docs/notes.md
@@ -1 +1 @@
-a
+b
diff --git "a/tools/\321\217.sh" "b/tools/\321\217.sh"
new file mode 100755
--- /dev/null
+++ "b/tools/\321\217.sh"
@@ -0,0 +1,2 @@
+++ a line that looks like a header
+echo hi
`
	old, err := parseDiff(diff, "old")
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]map[int]bool{"db/q.go": {3: true, 4: true, 10: true}}; !reflect.DeepEqual(old, want) {
		t.Errorf("old = %v, want %v", old, want)
	}
	added, err := parseDiff(diff, "new")
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]map[int]bool{"db/q.go": {3: true}, "tools/я.sh": {1: true, 2: true}}; !reflect.DeepEqual(added, want) {
		t.Errorf("new = %v, want %v", added, want)
	}
}

func TestModuleRootIsTheNearestModule(t *testing.T) {
	tree := map[string]bool{"go.mod": true, "svc/go.mod": true, "svc/api/h.go": true}
	for file, want := range map[string]string{"svc/api/h.go": "svc", "cmd/x/main.go": ".", "svc/go.sum": "svc"} {
		if got := moduleRoot(file, tree); got != want {
			t.Errorf("moduleRoot(%s) = %s, want %s", file, got, want)
		}
	}
	if got := moduleRoot("tools/x.sh", map[string]bool{}); got != "tools" {
		t.Errorf("a file outside modules: %s", got)
	}
}

func TestLocalSiblingPathsReadsReplacesAndUses(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":  "module x\n\nreplace example.com/lib => ../../lib/backend\nreplace example.com/v => example.com/v2 v2.0.0\n",
		"go.work": "go 1.22\n\nuse (\n\t.\n\t../kit\n)\nuse ../other\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := localSiblingPaths(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"../../lib/backend", "../kit", "../other"}; !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}
}

func TestReadManifestRejectsAmbiguousLines(t *testing.T) {
	for _, line := range []string{
		"abc defect",
		"abc defect rule tools/x.sh:3",
		"abc defect rule @tools/x.sh",
		"abc defect rule @a.sh:1 @b.sh:2",
	} {
		path := filepath.Join(t.TempDir(), "m.tsv")
		if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readManifest(path); err == nil {
			t.Errorf("%q: no error", line)
		}
	}
}

// fixture is a repository whose second commit fixes line 4 of svc/a.go,
// in a module of its own, and rewrites tools/run.sh, and a glint that
// reports a.go:4 with "r1", a.go:1 with "r9" and run.sh:2 with "r2".
func fixture(t *testing.T) (repo, fix, glint string) {
	t.Helper()
	repo = t.TempDir()
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
			"GIT_AUTHOR_DATE=2026-01-01T10:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T10:00:00Z")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(name, content string) {
		path := filepath.Join(repo, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q")
	write("svc/go.mod", "module x\n")
	write("svc/.glint.yaml", "settings: {}\n")
	write("svc/a.go", "package x\n\nfunc f() {\n\tbad()\n}\n")
	write("tools/run.sh", "#!/bin/sh\nsleep 5\n")
	git("add", "-A")
	git("commit", "-qm", "init")
	write("svc/a.go", "package x\n\nfunc f() {\n\tgood()\n}\n")
	write("tools/run.sh", "#!/bin/sh\nwait_ready\n")
	git("add", "-A")
	git("commit", "-qm", "fix")
	fix = git("rev-parse", "--short", "HEAD")

	glint = filepath.Join(t.TempDir(), "glint")
	// The project configuration must be gone before glint runs.
	script := `#!/bin/sh
[ -e .glint.yaml ] && { echo 'project config left in place' >&2; exit 2; }
if [ -e a.go ]; then
  echo '{"stats":{},"issues":[{"rule":"r1","file":"a.go","line":4},{"rule":"r9","file":"a.go","line":1}]}'
else
  echo '{"stats":{"packagesSkipped":0},"issues":[{"rule":"r2","file":"run.sh","line":2}]}'
fi
`
	if err := os.WriteFile(glint, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return repo, fix, glint
}

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
	}
	return recs
}

func TestVerifyManifestReportsEachLineOnItsOwn(t *testing.T) {
	repo, fix, glint := fixture(t)
	dir := t.TempDir()
	manifest := filepath.Join(dir, "m.tsv")
	lines := "# acceptance\n" +
		fix + " defect r1\n" +
		fix + " defect r2\n" +
		fix + " defect r9 @svc/a.go:2\n" +
		fix + " defect r7\n"
	if err := os.WriteFile(manifest, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.jsonl")
	var progress strings.Builder
	r := &replay{repo: repo, work: filepath.Join(dir, "work"), glint: glint}
	misses, err := r.verify(manifest, out, &progress)
	if err != nil {
		t.Fatal(err)
	}
	if misses != 1 || !strings.Contains(progress.String(), "misses: 1 of 4\n  "+fix+" defect r7 ok\n") {
		t.Errorf("misses = %d, progress:\n%s", misses, progress.String())
	}
	recs := readLines(t, out)
	if len(recs) != 1 {
		t.Fatalf("records = %v", recs)
	}
	rec := recs[0]
	wantHits := []any{[]any{"r1", "changed"}, []any{"r2", "changed"}, []any{"r9", "svc/a.go:2"}}
	if rec["status"] != "ok" || rec["hit"] != false || !reflect.DeepEqual(rec["hits"], wantHits) {
		t.Errorf("record = %v", rec)
	}
	if want := []any{"svc/a.go", "tools/run.sh"}; !reflect.DeepEqual(rec["files"], want) {
		t.Errorf("files = %v", rec["files"])
	}
}

func TestVerifyCandidatesResume(t *testing.T) {
	repo, fix, glint := fixture(t)
	dir := t.TempDir()
	candidates := filepath.Join(dir, "c.jsonl")
	recs := `{"commit":"` + fix + `","date":"2026-01-01"}
{"commit":"` + fix + `","date":"2026-01-01","kind":"introduced"}
{"commit":"0000000","date":"2026-01-02","kind":"defect"}
`
	if err := os.WriteFile(candidates, []byte(recs), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.jsonl")
	r := &replay{repo: repo, work: filepath.Join(dir, "work"), glint: glint}
	if _, err := r.verify(candidates, out, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	var progress strings.Builder
	if _, err := r.verify(candidates, out, &progress); err != nil {
		t.Fatal(err)
	}
	if progress.Len() != 0 {
		t.Errorf("a finished run replayed again:\n%s", progress.String())
	}
	got := readLines(t, out)
	var statuses []string
	for _, rec := range got {
		statuses = append(statuses, rec["kind"].(string)+" "+rec["status"].(string))
	}
	if want := []string{"defect ok", "introduced ok", "defect error"}; !reflect.DeepEqual(statuses, want) {
		t.Errorf("statuses = %v", statuses)
	}
	// The tree a fix left is checked on the lines it added: r1 on a.go:4
	// fires there, r9 on a line the fix kept does not.
	if fired := got[1]["fired"].(map[string]any); !reflect.DeepEqual(fired["svc/a.go"], []any{"r1"}) {
		t.Errorf("fired = %v", fired)
	}
}
