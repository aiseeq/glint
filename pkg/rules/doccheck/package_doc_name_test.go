package doccheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A package was renamed, its doc comment kept the old name: a reader who
// searches for the package by the name in its doc finds nothing.
func TestPackageDocNameReportsOldName(t *testing.T) {
	file := rulestest.GoFile(t, "catalog/catalog.go", `// Package registry keeps the list of entries.
package catalog
`)
	violations := NewPackageDocNameRule().AnalyzeFile(file)

	require.Len(t, violations, 1)
	assert.Equal(t, 1, violations[0].Line)
	assert.Contains(t, violations[0].Message, "registry")
	assert.Contains(t, violations[0].Message, "catalog")
}

func TestPackageDocNameAcceptsOwnName(t *testing.T) {
	file := rulestest.GoFile(t, "catalog/catalog.go", `// Package catalog keeps the list of entries.
package catalog
`)
	assert.Empty(t, NewPackageDocNameRule().AnalyzeFile(file))
}

// A doc that does not open with "Package" names nothing to compare: a
// command's doc, prose, a license header.
func TestPackageDocNameIgnoresOtherOpenings(t *testing.T) {
	for _, src := range []string{
		"// Command catalog prints the list of entries.\npackage main\n",
		"// Packages of this module share one config.\npackage catalog\n",
		"// Copyright the authors.\n\npackage catalog\n",
		"package catalog\n",
	} {
		file := rulestest.GoFile(t, "catalog/catalog.go", src)
		assert.Empty(t, NewPackageDocNameRule().AnalyzeFile(file), src)
	}
}

// An external test package documents itself under its own name.
func TestPackageDocNameAcceptsExternalTestPackage(t *testing.T) {
	file := rulestest.GoFile(t, "catalog/catalog_test.go", `// Package catalog_test checks the list from outside.
package catalog_test
`)
	assert.Empty(t, NewPackageDocNameRule().AnalyzeFile(file))
}
