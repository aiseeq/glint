package main

import (
	"context"
	"encoding/base64"
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
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/glintbuild <version>")
		os.Exit(2)
	}
	if err := build(context.Background(), flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
	data, err := json.Marshal(before.Manifest)
	if err != nil {
		return fmt.Errorf("encode build manifest: %w", err)
	}
	manifest := base64.StdEncoding.EncodeToString(data)
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		return fmt.Errorf("create bin: %w", err)
	}
	ldflags := fmt.Sprintf("-X main.version=%s -X main.cacheBuildManifest=%s", version, manifest)
	link := func(out string) error {
		cmd := exec.CommandContext(ctx, "go", "build", "-ldflags", ldflags, "-o", out, "./cmd/glint")
		cmd.Dir, cmd.Stdout, cmd.Stderr = root, os.Stdout, os.Stderr
		if err := proc.CancelByStop(cmd, time.Second, syscall.SIGTERM); err != nil {
			return fmt.Errorf("configure build cancellation: %w", err)
		}
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("build bin/glint: %w", err)
		}
		return nil
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
