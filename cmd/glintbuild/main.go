package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aiseeq/akit/proc"
	"github.com/aiseeq/glint/internal/buildmanifest"
	"github.com/aiseeq/glint/internal/cachekey"
	"github.com/aiseeq/glint/internal/depgraph"
)

func main() {
	deps := flag.Bool("deps", false, "print the result cache key the build would record, as JSON, and build nothing")
	flag.Parse()
	if *deps {
		if err := printDeps(context.Background()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/glintbuild <version> | -deps")
		os.Exit(2)
	}
	if err := build(context.Background(), flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// glintDeps names what the dependency analysis treats specially in glint:
// the check command, how rules register, and the methods the run calls on
// every registered rule (rules.Register, rules.ConfigureAll,
// rules.ValidateConfig, rules.GetEnabled, the state reset of a run), and
// those it asks every enabled rule before analysis, whose answers decide what
// all rules see: the walk (RequiresFile, RequiresAdditionalFile), the typed
// load (TypedGoProjectImports, NeedsTypedGoProject) and SSA (RequiresSSA).
func glintDeps(root, module string) depgraph.Config {
	return depgraph.Config{
		Dir:      root,
		Command:  module + "/cmd/glint",
		Entry:    "runCheck",
		Register: module + "/pkg/rules.Register",
		Rule:     module + "/pkg/rules.Rule",
		RegistryMethods: []string{"Name", "Category", "Description", "DefaultSeverity", "Configure",
			"SettingSpecs", "useRunConfig", "ResetState", "ReadsExcludedInstructions",
			"RequiresFile", "RequiresAdditionalFile", "TypedGoProjectImports", "NeedsTypedGoProject", "RequiresSSA"},
	}
}

// cacheKey analyzes the module and combines its scopes with what its source
// does not decide (packages outside the module, the build environment).
func cacheKey(ctx context.Context, root string, snapshot buildmanifest.Snapshot) (*cachekey.Manifest, error) {
	result, err := depgraph.Analyze(ctx, glintDeps(root, snapshot.Module))
	if err != nil {
		return nil, fmt.Errorf("analyze rule dependencies: %w", err)
	}
	mix := func(hash string) string {
		sum := sha256.Sum256([]byte(hash + "\x00" + snapshot.External))
		return hex.EncodeToString(sum[:])[:16]
	}
	var index cachekey.Index
	indexes := func(keys []string) []int {
		out := make([]int, 0, len(keys))
		for _, key := range keys {
			out = append(out, index.Add(key))
		}
		return out
	}
	manifest := &cachekey.Manifest{Driver: mix(result.Driver), All: mix(result.All), DriverFuncs: indexes(result.DriverFuncs)}
	for _, s := range result.Sites {
		sum := sha256.Sum256([]byte(s.Hash))
		manifest.Sites = append(manifest.Sites, cachekey.Site{File: s.File, From: s.From, To: s.To,
			Hash: hex.EncodeToString(sum[:])[:16], Funcs: indexes(s.Funcs)})
	}
	manifest.Funcs = index.Keys()
	return manifest, nil
}

func printDeps(ctx context.Context) error {
	root, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("working directory: %w", err)
	}
	snapshot, err := buildmanifest.Capture(ctx, root)
	if err != nil {
		return fmt.Errorf("capture Go package fingerprints: %w", err)
	}
	result, err := depgraph.Analyze(ctx, glintDeps(root, snapshot.Module))
	if err != nil {
		return fmt.Errorf("analyze rule dependencies: %w", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", " ")
	return encoder.Encode(result)
}

func build(ctx context.Context, version string) error {
	root, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("working directory: %w", err)
	}
	before, err := buildmanifest.Capture(ctx, root)
	if err != nil {
		return fmt.Errorf("capture Go package fingerprints: %w", err)
	}
	manifest, err := cacheKey(ctx, root, before)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		return fmt.Errorf("create bin: %w", err)
	}
	ldflags := fmt.Sprintf("-X main.version=%s", version)
	link := func(out string) error {
		cmd := exec.CommandContext(ctx, "go", "build", "-ldflags", ldflags, "-o", out, "./cmd/glint")
		cmd.Dir, cmd.Stdout, cmd.Stderr = root, os.Stdout, os.Stderr
		if err := proc.CancelByStop(cmd, time.Second, syscall.SIGTERM); err != nil {
			return fmt.Errorf("configure build cancellation: %w", err)
		}
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("build bin/glint: %w", err)
		}
		return cachekey.Append(out, manifest)
	}
	verify := func() error {
		after, err := buildmanifest.Capture(ctx, root)
		if err != nil {
			return fmt.Errorf("verify Go package fingerprints: %w", err)
		}
		return buildmanifest.VerifyStable(before, after)
	}
	return publishVerified(filepath.Join(root, "bin", "glint"), link, verify)
}

// publishVerified links the binary next to out and moves it there only after
// verify accepts it: a binary whose code changed after its manifest was
// captured would trust stale cached findings.
func publishVerified(out string, link func(string) error, verify func() error) error {
	unverified := out + ".unverified"
	err := link(unverified)
	if err == nil {
		err = verify()
	}
	if err == nil {
		return os.Rename(unverified, out)
	}
	if removeErr := os.Remove(unverified); removeErr != nil && !os.IsNotExist(removeErr) {
		return errors.Join(err, fmt.Errorf("remove unverified binary: %w", removeErr))
	}
	return err
}
