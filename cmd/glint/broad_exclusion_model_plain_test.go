//go:build !race

// This test parses static YAML fixtures and compares decoded configuration
// models; it never runs project analysis or starts glint workers.

package main

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// broad-exclusion judges a configuration by the YAML nodes, the load by
// what yaml.v3 decodes of them. Where the two part, a switch or an exception
// is in effect that broad-exclusion does not see: a !!binary category or
// rule key switched a watch off without a finding, a !!binary exclude, skip
// directory or exception glob took sources out unjudged. On every
// configuration the load accepts, broad-exclusion now reads the same lists,
// switches and exceptions as the load.
func TestBroadExclusionReadsTheConfigurationAsTheLoad(t *testing.T) {
	var paths []string
	require.NoError(t, filepath.WalkDir(broadModelConfigs, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && entry.Name() == "glint.yaml" {
			paths = append(paths, path)
		}
		return err
	}))
	compared := 0
	var refused []string
	for _, path := range paths {
		abs, err := filepath.Abs(path)
		require.NoError(t, err)
		loaded, err := core.LoadConfig(abs)
		if err != nil {
			// A configuration the load refuses stops the run before any rule.
			refused = append(refused, filepath.Dir(path))
			continue
		}
		compared++
		t.Run(path, func(t *testing.T) {
			chain, err := readBroadChain(abs, filepath.Dir(abs))
			require.NoError(t, err)
			assert.Equal(t, loadedModel(loaded), broadModel(t, chain))
		})
	}
	t.Logf("%d configurations compared; refused by the load: %v", compared, refused)
	assert.GreaterOrEqual(t, compared, 81)
}
