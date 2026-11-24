package frontendrules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain puts first on PATH a global tsc 7 laid out as npm installs it
// (<prefix>/bin/tsc -> ../lib/node_modules/typescript/bin/tsc, @types beside
// typescript) whose bin/tsc starts the compiler's native executable itself.
// npm's bin/tsc is a node script that only starts that executable: node takes
// about 0.3-0.5 s a launch, and the tests here launch tsc hundreds of times.
// The compiler, its version, its libraries and the @types are the installed
// ones; without an npm-installed tsc 7 with its native executable the tests
// run the tsc on PATH, as before.
func TestMain(m *testing.M) {
	dir, err := directGlobalTsc()
	if err != nil {
		fmt.Fprintln(os.Stderr, "frontendrules tests: the tsc on PATH stays:", err)
	}
	code := m.Run()
	if dir != "" {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	os.Exit(code)
}

// directGlobalTsc builds the global tsc of TestMain and prepends its bin to
// PATH; it returns the directory to remove, "" when PATH stays.
func directGlobalTsc() (string, error) {
	path, err := exec.LookPath("tsc")
	if err != nil {
		return "", nil // the tsc tests skip
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	// <prefix>/lib/node_modules/typescript/bin/tsc
	pkg := filepath.Dir(filepath.Dir(real))
	modules := filepath.Dir(pkg)
	if filepath.Base(modules) != "node_modules" {
		return "", fmt.Errorf("%s is not in a node_modules directory", real)
	}
	native, err := nativeTsc(pkg, modules)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(native, "'\n") {
		return "", fmt.Errorf("the path %q does not fit a shell script", native)
	}
	npmVersion, err := exec.Command(path, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("%s --version: %w", path, err)
	}
	nativeVersion, err := exec.Command(native, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("%s --version: %w", native, err)
	}
	if string(npmVersion) != string(nativeVersion) {
		return "", fmt.Errorf("%s prints %q, %s prints %q", path, npmVersion, native, nativeVersion)
	}
	dir, err := os.MkdirTemp("", "glint-global-tsc")
	if err != nil {
		return "", fmt.Errorf("create the directory of the global tsc: %w", err)
	}
	if err := layOutGlobalTsc(dir, native, filepath.Join(modules, "@types")); err != nil {
		return dir, err
	}
	return dir, os.Setenv("PATH", filepath.Join(dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// nativeTsc finds the executable of the platform package npm installs with
// typescript 7, nested in typescript or hoisted beside it.
func nativeTsc(pkg, modules string) (string, error) {
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" || runtime.GOOS == "windows" {
		return "", fmt.Errorf("no native tsc package for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	platform := filepath.Join("@typescript", "typescript-"+runtime.GOOS+"-"+arch, "lib", "tsc")
	for _, candidate := range []string{filepath.Join(pkg, "node_modules", platform), filepath.Join(modules, platform)} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no %s under %s", platform, pkg)
}

// layOutGlobalTsc writes the npm layout under dir. Its files are dated back:
// the rule keeps no answer while an input of tsc, the global tsc among them,
// is newer than a second before the run.
func layOutGlobalTsc(dir, native, types string) error {
	modules := filepath.Join(dir, "lib", "node_modules")
	script := filepath.Join(modules, "typescript", "bin", "tsc")
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{filepath.Dir(script), bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec '"+native+"' \"$@\"\n"), 0o755); err != nil {
		return fmt.Errorf("write %s: %w", script, err)
	}
	if _, err := os.Stat(types); err == nil {
		if err := os.Symlink(types, filepath.Join(modules, "@types")); err != nil {
			return fmt.Errorf("link the @types of the global tsc: %w", err)
		}
	}
	if err := os.Symlink(filepath.Join("..", "lib", "node_modules", "typescript", "bin", "tsc"), filepath.Join(bin, "tsc")); err != nil {
		return fmt.Errorf("link bin/tsc of the global tsc: %w", err)
	}
	old := time.Now().Add(-time.Hour)
	for _, p := range []string{script, filepath.Dir(script), filepath.Join(modules, "typescript"), modules, filepath.Join(dir, "lib"), bin, dir} {
		if err := os.Chtimes(p, old, old); err != nil {
			return fmt.Errorf("date back %s: %w", p, err)
		}
	}
	return nil
}
