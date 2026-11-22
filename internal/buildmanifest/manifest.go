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
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aiseeq/akit/proc"
)

// Snapshot is the state of the build's packages at one moment.
type Snapshot struct {
	Packages map[string]Package
	// Module is the main module's path.
	Module string
	// External hashes what the module's own source does not decide: the
	// packages outside the module (their versions, local replacements, the
	// toolchain) and the build environment.
	External string
}

// Package is one package of the build as go list -export reports it.
type Package struct {
	ImportPath string
	BuildID    string
	Imports    []string
}

type listedPackage struct {
	ImportPath string
	BuildID    string
	Imports    []string
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
		pkg := Package(listed)

		packages[pkg.ImportPath] = pkg
	}

	goEnv, err := commandOutput(ctx, root, "go", "env", "-json", "GOFLAGS", "GOOS", "GOARCH", "CGO_ENABLED", "GOEXPERIMENT", "GOVERSION")
	if err != nil {
		return Snapshot{}, fmt.Errorf("read build environment: %w", err)
	}
	var environment map[string]string
	if err := json.Unmarshal(goEnv, &environment); err != nil {
		return Snapshot{}, fmt.Errorf("decode build environment: %w", err)
	}
	external, err := ExternalKey(modulePath, packages, environment)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Packages: packages, Module: modulePath, External: external}, nil
}

// ExternalKey hashes the BuildIDs of the packages outside the module that
// the binary links, and the build environment. A BuildID covers a package's
// source, its dependencies' and the compiler, so a new version, an edited
// local replacement or another toolchain changes it.
func ExternalKey(modulePath string, packages map[string]Package, environment map[string]string) (string, error) {
	commandPath := modulePath + "/cmd/glint"
	if _, ok := packages[commandPath]; !ok {
		return "", fmt.Errorf("go list did not include %s", commandPath)
	}
	linked := linkedInto(commandPath, packages)
	parts := make([]string, 0, len(linked)+1)
	for path := range linked {
		if pkg, ok := packages[path]; ok && !withinModule(path, modulePath) {
			parts = append(parts, path+" "+pkg.BuildID)
		}
	}
	environmentJSON, err := json.Marshal(environment)
	if err != nil {
		return "", fmt.Errorf("encode build environment: %w", err)
	}
	parts = append(parts, "build environment "+string(environmentJSON))
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:]), nil
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

func commandOutput(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Stderr = dir, os.Stderr
	if err := proc.CancelByStop(cmd, time.Second, syscall.SIGTERM); err != nil {
		return nil, fmt.Errorf("configure command cancellation: %w", err)
	}
	return cmd.Output()
}
