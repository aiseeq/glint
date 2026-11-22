package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"golang.org/x/mod/modfile"
	"gopkg.in/yaml.v3"
)

// maxHostPaths is the most entries worker pc takes from WORKER_PC_TREES.
const maxHostPaths = 64

// hostPaths lists what a comparison on remote_heavy's host reads outside the
// glint tree root: the git toplevel of every target (the directory itself when
// it is in no repository) and of every go.work use they name, the targets of
// the links in those trees that lead out of them, the glint user config
// directory, the consumers config, the tickets_dir of the user config and the
// old and new binaries. An entry inside the root goes with the root; an entry
// inside another is folded into it, as worker pc refuses nested entries; the
// result is sorted.
func hostPaths(targets []string, cfgPath, oldAbs, newAbs, root string) ([]string, error) {
	var trees []string
	for _, target := range targets {
		top := gitToplevel(target)
		trees = append(trees, top)
		uses, err := goWorkUses(target, top)
		if err != nil {
			return nil, err
		}
		for _, use := range uses {
			trees = append(trees, gitToplevel(use))
		}
	}
	trees = foldNestedPaths(trees)
	paths := slices.Clone(trees)
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("find home directory: %w", err)
	}
	for _, tree := range trees {
		links, err := outwardLinks(tree, home)
		if err != nil {
			return nil, err
		}
		paths = append(paths, links...)
	}
	glintConfig := hostGlintConfigDir(home)
	if exists(glintConfig) {
		paths = append(paths, glintConfig)
	}
	cfgAbs, err := filepath.Abs(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("resolve consumers config %s: %w", cfgPath, err)
	}
	paths = append(paths, cfgAbs)
	tickets, err := userTicketsDir(filepath.Join(glintConfig, "config.yaml"))
	if err != nil {
		return nil, err
	}
	if tickets != "" && exists(tickets) {
		paths = append(paths, tickets)
	}
	for _, bin := range []struct{ name, path string }{{"old", oldAbs}, {"new", newAbs}} {
		if _, err := os.Stat(bin.path); err != nil {
			return nil, fmt.Errorf("%s binary %s: %w", bin.name, bin.path, err)
		}
		paths = append(paths, bin.path)
	}
	paths = slices.DeleteFunc(paths, func(path string) bool { return path != root && core.WithinPath(path, root) })
	folded := foldNestedPaths(paths)
	if len(folded) > maxHostPaths {
		return nil, fmt.Errorf("%d host paths, worker pc takes at most %d", len(folded), maxHostPaths)
	}
	return folded, nil
}

// hostGlintConfigDir is where glint on the host finds its user config: worker
// pc clears the environment and keeps HOME, so XDG_CONFIG_HOME is unset there.
func hostGlintConfigDir(home string) string {
	return filepath.Join(home, ".config", "glint")
}

// warnConfigDir says when glint here reads its user config from elsewhere
// than glint on the host will.
func warnConfigDir(home string, stderr io.Writer) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: cannot tell where glint here reads its user config (%v); glint on the host reads %s\n", err, hostGlintConfigDir(home))
		return
	}
	if filepath.Join(configDir, "glint") != hostGlintConfigDir(home) {
		_, _ = fmt.Fprintf(stderr, "consumers: XDG_CONFIG_HOME=%s: glint here reads %s, glint on the host %s; their findings may differ\n",
			os.Getenv("XDG_CONFIG_HOME"), filepath.Join(configDir, "glint"), hostGlintConfigDir(home))
	}
}

// outwardLinks are the targets of the symbolic links below tree (its .git
// left out) that lead out of it to an existing path under home: on the host
// such a link names a path that is not there unless it is sent too, and a
// rule that follows it (md-broken-link stats the target of a markdown link)
// would report otherwise. A target outside home is the host's own system's.
func outwardLinks(tree, home string) ([]string, error) {
	var targets []string
	err := filepath.WalkDir(tree, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory has no links glint could follow either.
			return skipDirOnError(d)
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		target, err := filepath.EvalSymlinks(path)
		if err != nil { //nolint:silent-error-handling // A dangling link here is dangling on the host too.
			return nil
		}
		// A link up to a directory holding the tree names a path the host
		// has as the parent of the tree's mount; sending it would send the tree's
		// neighbours too.
		if !core.WithinPath(target, tree) && !core.WithinPath(tree, target) && core.WithinPath(target, home) && !slices.Contains(targets, target) {
			targets = append(targets, target)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("find the links out of %s: %w", tree, err)
	}
	return targets, nil
}

func skipDirOnError(d fs.DirEntry) error {
	if d != nil && d.IsDir() {
		return filepath.SkipDir
	}
	return nil
}

// gitToplevel is the root of the repository dir is in, dir itself when it is
// in none.
func gitToplevel(dir string) string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = dir
	out, err := cmd.Output()
	if top := strings.TrimSpace(string(out)); err == nil && top != "" {
		return filepath.Clean(top)
	}
	return filepath.Clean(dir)
}

// goWorkUses are the directories the go.work nearest to target, up to top,
// uses: glint loads them with the target's packages.
func goWorkUses(target, top string) ([]string, error) {
	for dir := filepath.Clean(target); ; dir = filepath.Dir(dir) {
		work := filepath.Join(dir, "go.work")
		data, err := os.ReadFile(work)
		if err == nil {
			parsed, err := modfile.ParseWork(work, data, nil)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", work, err)
			}
			var uses []string
			for _, use := range parsed.Use {
				path := use.Path
				if !filepath.IsAbs(path) {
					path = filepath.Join(dir, path)
				}
				if exists(path) {
					uses = append(uses, filepath.Clean(path))
				}
			}
			return uses, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("read %s: %w", work, err)
		}
		if dir == top || dir == filepath.Dir(dir) || !core.WithinPath(dir, top) {
			return nil, nil
		}
	}
}

// userTicketsDir is tickets_dir of glint's user config, "" when the config or
// the key is missing. glint reads it as it is, so a relative one cannot be
// named for the host.
func userTicketsDir(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read glint user config %s: %w", path, err)
	}
	var cfg struct {
		TicketsDir string `yaml:"tickets_dir"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("parse glint user config %s: %w", path, err)
	}
	if cfg.TicketsDir != "" && !filepath.IsAbs(cfg.TicketsDir) {
		return "", fmt.Errorf("%s: tickets_dir %q is not an absolute path", path, cfg.TicketsDir)
	}
	if cfg.TicketsDir == "" {
		return "", nil
	}
	return filepath.Clean(cfg.TicketsDir), nil
}

// foldNestedPaths drops duplicates and every path inside another one.
func foldNestedPaths(paths []string) []string {
	var kept []string
	for _, path := range paths {
		if !slices.ContainsFunc(paths, func(other string) bool { return other != path && core.WithinPath(path, other) }) && !slices.Contains(kept, path) {
			kept = append(kept, path)
		}
	}
	slices.Sort(kept)
	return kept
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writeHostPaths writes the list for WORKER_PC_TREES: a comment line saying
// whose paths they are, then one absolute path a line; the file is replaced
// whole.
func writeHostPaths(file, whose string, paths []string) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return fmt.Errorf("create directory of %s: %w", file, err)
	}
	var b strings.Builder
	b.WriteString("# paths " + whose + " reads outside the glint tree, for worker pc (WORKER_PC_TREES); written by tools/consumers\n")
	for _, path := range paths {
		b.WriteString(path + "\n")
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), filepath.Base(file)+".*")
	if err != nil {
		return fmt.Errorf("write %s: %w", file, err)
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write %s: %w", file, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write %s: %w", file, err)
	}
	if err := os.Rename(tmp.Name(), file); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write %s: %w", file, err)
	}
	return nil
}

// selfHostPaths lists what glint on the tree in dir reads outside it: the
// tree's root, which worker pc then sends with its .git (glint reads HEAD and
// the index), the glint user config directory and its tickets_dir. The
// approved models list worker pc sends with every job.
func selfHostPaths(dir string) ([]string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("find the root of %s: %w", dir, err)
	}
	paths := []string{filepath.Clean(strings.TrimSpace(string(out)))}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("find home directory: %w", err)
	}
	glintConfig := hostGlintConfigDir(home)
	if exists(glintConfig) {
		paths = append(paths, glintConfig)
	}
	tickets, err := userTicketsDir(filepath.Join(glintConfig, "config.yaml"))
	if err != nil {
		return nil, err
	}
	if tickets != "" && exists(tickets) {
		paths = append(paths, tickets)
	}
	return foldNestedPaths(paths), nil
}

func writeSelfPaths(file string, stderr io.Writer) int {
	dir, err := os.Getwd()
	if err == nil {
		var paths []string
		if paths, err = selfHostPaths(dir); err == nil {
			err = writeHostPaths(file, "glint on this tree", paths)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "consumers:", err)
		return 2
	}
	return 0
}
