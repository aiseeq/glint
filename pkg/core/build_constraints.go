package core

import (
	"errors"
	"fmt"
	"go/build"
	"path/filepath"
)

// errExcludedByBuild marks a Go file that does not parse but that the go
// command never compiles on this platform: a //go:build ignore generator or
// template, a file for another GOOS. The toolchain never parses such a file,
// so its syntax is not an error of the project.
var errExcludedByBuild = errors.New("excluded by build constraints")

// classifyParseError returns errExcludedByBuild wrapped around parseErr when
// the build excludes the file, and parseErr itself otherwise.
func classifyParseError(path string, parseErr error) error {
	match, err := build.Default.MatchFile(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return errors.Join(parseErr, fmt.Errorf("evaluate build constraints of %q: %w", path, err))
	}
	if match {
		return parseErr
	}
	return fmt.Errorf("%w: %w", errExcludedByBuild, parseErr)
}
