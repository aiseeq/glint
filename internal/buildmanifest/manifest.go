package buildmanifest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

type Manifest struct {
	Core     string            `json:"core"`
	Packages map[string]string `json:"packages"`
}

type Snapshot struct {
	Packages map[string]Package
	Manifest Manifest
}

type Package struct {
	ImportPath string
	Dir        string
	BuildID    string
	Imports    []string
	Sources    []string
}

type listedPackage struct {
	ImportPath   string
	Dir          string
	BuildID      string
	Imports      []string
	GoFiles      []string
	CgoFiles     []string
	CFiles       []string
	CXXFiles     []string
	MFiles       []string
	HFiles       []string
	SFiles       []string
	SwigFiles    []string
	SwigCXXFiles []string
	EmbedFiles   []string
}

func Capture(ctx context.Context, root string) (Snapshot, error) {
	listed, err := commandOutput(ctx, root, "go", "list", "-export", "-deps", "-json", "./...")
	if err != nil {
		return Snapshot{}, fmt.Errorf("go list -export: %w", err)
	}
	module, err := commandOutput(ctx, root, "go", "list", "-m")
	if err != nil {
		return Snapshot{}, fmt.Errorf("go list -m: %w", err)
	}
	modulePath := strings.TrimSpace(string(module))
	if modulePath == "" || strings.Contains(modulePath, "\n") {
		return Snapshot{}, fmt.Errorf("go list -m reported %q, want one main module", modulePath)
	}
	packages := make(map[string]Package)
	decoder := json.NewDecoder(bytes.NewReader(listed))
	for {
		var listed listedPackage
		err := decoder.Decode(&listed)
		if err == io.EOF {
			break
		}
		if err != nil {
			return Snapshot{}, fmt.Errorf("decode go list output: %w", err)
		}
		if listed.ImportPath == "" {
			return Snapshot{}, fmt.Errorf("go list omitted import path")
		}
		if listed.BuildID == "" {
			continue
		}
		pkg := Package{
			ImportPath: listed.ImportPath,
			Dir:        listed.Dir,
			BuildID:    listed.BuildID,
			Imports:    listed.Imports,
			Sources: slices.Concat(listed.GoFiles, listed.CgoFiles, listed.CFiles, listed.CXXFiles, listed.MFiles,
				listed.HFiles, listed.SFiles, listed.SwigFiles, listed.SwigCXXFiles, listed.EmbedFiles),
		}

		packages[pkg.ImportPath] = pkg
	}

	goEnv, err := commandOutput(ctx, root, "go", "env", "-json", "GOFLAGS", "GOOS", "GOARCH", "CGO_ENABLED", "GOEXPERIMENT")
	if err != nil {
		return Snapshot{}, fmt.Errorf("read build environment: %w", err)
	}
	var environment map[string]string
	if err := json.Unmarshal(goEnv, &environment); err != nil {
		return Snapshot{}, fmt.Errorf("decode build environment: %w", err)
	}
	manifest, err := BuildManifest(modulePath, packages, environment)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Packages: packages, Manifest: manifest}, nil
}

func BuildManifest(modulePath string, packages map[string]Package, environment map[string]string) (Manifest, error) {
	ids := make(map[string]string, len(packages))
	for path, pkg := range packages {
		ids[path] = pkg.BuildID
	}
	manifest := Manifest{Packages: make(map[string]string)}
	commandPath := modulePath + "/cmd/glint"
	linked := linkedInto(commandPath, packages)
	coreParts := make([]string, 0, len(packages)+8)
	for path, pkg := range packages {
		if !withinModule(path, modulePath) {
			continue
		}
		if isRulePackage(path, modulePath) {
			manifest.Packages[path] = pkg.BuildID
			continue
		}
		// Module packages the binary does not link (build tools, test
		// helpers) cannot change what it reports.
		if path != commandPath && linked[path] {
			coreParts = append(coreParts, path+" "+pkg.BuildID)
		}
	}
	command, ok := packages[commandPath]
	if !ok {
		return Manifest{}, fmt.Errorf("go list did not include %s", commandPath)
	}
	sources := append([]string(nil), command.Sources...)
	sort.Strings(sources)
	hash := sha256.New()
	for _, name := range sources {
		data, err := readFile(filepath.Join(command.Dir, name))
		if err != nil {
			return Manifest{}, fmt.Errorf("read %s source %s: %w", commandPath, name, err)
		}
		_, _ = fmt.Fprintf(hash, "%s\x00", name)
		_, _ = hash.Write(data)
		_, _ = hash.Write([]byte{0})
	}
	coreParts = append(coreParts, "cmd/glint sources "+hex.EncodeToString(hash.Sum(nil)))
	for _, imported := range command.Imports {
		if isRulePackage(imported, modulePath) || isCommand(imported, modulePath) {
			continue
		}
		if id := ids[imported]; id != "" {
			coreParts = append(coreParts, "cmd/glint dependency "+imported+" "+id)
		}
	}
	environmentJSON, err := json.Marshal(environment)
	if err != nil {
		return Manifest{}, fmt.Errorf("encode build environment: %w", err)
	}
	coreParts = append(coreParts, "build environment "+string(environmentJSON))
	sort.Strings(coreParts)
	coreHash := sha256.Sum256([]byte(strings.Join(coreParts, "\n")))
	manifest.Core = hex.EncodeToString(coreHash[:])[:16]
	return manifest, nil
}

func VerifyStable(before, after Snapshot) error {
	changed := make([]string, 0)
	for path, previous := range before.Packages {
		current, ok := after.Packages[path]
		if !ok || previous.BuildID != current.BuildID {
			changed = append(changed, path)
		}
	}
	for path := range after.Packages {
		if _, ok := before.Packages[path]; !ok {
			changed = append(changed, path)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	sort.Strings(changed)
	return fmt.Errorf("package BuildIDs changed during the graft build: %s", strings.Join(changed, ", "))
}

// linkedInto returns the packages root imports, directly or transitively.
func linkedInto(root string, packages map[string]Package) map[string]bool {
	linked := make(map[string]bool)
	pending := []string{root}
	for len(pending) > 0 {
		path := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for _, imported := range packages[path].Imports {
			if !linked[imported] {
				linked[imported] = true
				pending = append(pending, imported)
			}
		}
	}
	return linked
}

func withinModule(importPath, modulePath string) bool {
	return importPath == modulePath || strings.HasPrefix(importPath, modulePath+"/")
}

func isRulePackage(importPath, modulePath string) bool {
	if !withinModule(importPath, modulePath) {
		return false
	}
	relative := strings.TrimPrefix(strings.TrimPrefix(importPath, modulePath), "/")
	return strings.HasPrefix(relative, "pkg/rules/") &&
		!strings.HasPrefix(relative, "pkg/rules/patterns/internal/") &&
		!strings.HasPrefix(relative, "pkg/rules/helpers")
}

func isCommand(importPath, modulePath string) bool {
	return importPath == modulePath+"/cmd/glint"
}

var readFile = os.ReadFile

func commandOutput(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Stderr = dir, os.Stderr
	return cmd.Output()
}
