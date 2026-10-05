package patterns

import (
	"fmt"
	"go/version"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewCIToolchainImageOlderThanGoModRule())
}

// CIToolchainImageOlderThanGoModRule reports a golang image in a CI pipeline
// or a Dockerfile older than the go line of the module it builds. The
// official image sets GOTOOLCHAIN=local, so the go command does not fetch the
// newer toolchain go.mod asks for and refuses to build.
type CIToolchainImageOlderThanGoModRule struct {
	*rules.BaseRule
}

// NewCIToolchainImageOlderThanGoModRule creates ci-toolchain-image-older-than-go-mod.
func NewCIToolchainImageOlderThanGoModRule() *CIToolchainImageOlderThanGoModRule {
	return &CIToolchainImageOlderThanGoModRule{BaseRule: rules.NewBaseRule(
		"ci-toolchain-image-older-than-go-mod",
		"patterns",
		"Detects a golang image in a CI pipeline or a Dockerfile older than the go line of go.mod — the image sets GOTOOLCHAIN=local and refuses to build the module",
		core.SeverityHigh,
	)}
}

// ReadsOtherFiles reports that the findings depend on go.mod.
func (r *CIToolchainImageOlderThanGoModRule) ReadsOtherFiles() bool { return true }

var (
	golangImage   = regexp.MustCompile(`(?:^|[\s"'=])(?:[\w.-]+(?::\d+)?/)*golang:(\d+\.\d+(?:\.\d+)?)\b`)
	dockerFrom    = regexp.MustCompile(`(?i)^\s*FROM\s`)
	goDirective   = regexp.MustCompile(`(?m)^go\s+(\d+\.\d+(?:\.\d+)?)\s*$`)
	yamlCommented = regexp.MustCompile(`^\s*#`)
)

// AnalyzeFile checks the golang images of a CI config or a Dockerfile.
func (r *CIToolchainImageOlderThanGoModRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsCIConfig() && !ctx.IsDockerfile() {
		return nil
	}
	goMod, err := nearestGoMod(ctx)
	if err == nil && goMod == "" {
		return nil
	}
	module := ""
	if err == nil {
		module, err = readGoDirective(goMod)
	}
	if err != nil {
		return []*core.Violation{r.CreateViolation(ctx.RelPath, 1, "The go.mod this file builds cannot be read, and the image versions are not checked: "+err.Error())}
	}
	if module == "" {
		return nil // no go line: any toolchain builds the module
	}
	var out []*core.Violation
	for i, line := range ctx.Lines {
		if yamlCommented.MatchString(line) || ctx.IsDockerfile() && !dockerFrom.MatchString(line) {
			continue
		}
		m := golangImage.FindStringSubmatch(line)
		if m == nil || !olderToolchain(m[1], module) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1,
			"The image golang:"+m[1]+" is older than go "+module+" in go.mod — the image sets GOTOOLCHAIN=local, and the go command refuses to build the module")
		v.WithCode(strings.TrimSpace(line))
		v.WithSuggestion("Use golang:" + version.Lang("go" + module)[2:] + " or newer, and raise the image together with the go line")
		out = append(out, v)
	}
	return out
}

// olderToolchain reports an image version below the module's go line; an
// image tag without a patch version is the newest patch of its release.
func olderToolchain(image, module string) bool {
	if strings.Count(image, ".") == 1 {
		return version.Compare("go"+image, version.Lang("go"+module)) < 0
	}
	return version.Compare("go"+image, "go"+module) < 0
}

// nearestGoMod returns the go.mod nearest to the file, looking up to the
// project root; for a CI config without one above it, the go.mod of the
// single module one level below the root. "" when there is none.
func nearestGoMod(ctx *core.FileContext) (string, error) {
	root := filepath.Clean(ctx.ProjectRoot)
	for dir := filepath.Dir(ctx.Path); strings.HasPrefix(dir, root); dir = filepath.Dir(dir) {
		if candidate := filepath.Join(dir, "go.mod"); fileExists(candidate) {
			return candidate, nil
		}
		if dir == root || filepath.Dir(dir) == dir {
			break
		}
	}
	if !ctx.IsCIConfig() {
		return "", nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("list %s: %w", root, err)
	}
	var nested []string
	for _, entry := range entries {
		if candidate := filepath.Join(root, entry.Name(), "go.mod"); entry.IsDir() && fileExists(candidate) {
			nested = append(nested, candidate)
		}
	}
	if len(nested) != 1 {
		return "", nil // no module, or several: which one the pipeline builds is unknown
	}
	return nested[0], nil
}

// fileExists reports a regular file at the path.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// readGoDirective returns the version of the go line of a go.mod file, ""
// when it has none.
func readGoDirective(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if m := goDirective.FindSubmatch(content); m != nil {
		return string(m[1]), nil
	}
	return "", nil
}
