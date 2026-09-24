package duplication

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestCrossFileDuplicateRule(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	rule.minBlockSize = 8 // Match the test data

	// Substantial duplicate block (10 meaningful lines)
	duplicateBlock := []string{
		"func processData(input []byte, config *Config) (*Result, error) {",
		"    if input == nil || len(input) == 0 {",
		"        return nil, errors.New(\"input cannot be empty\")",
		"    }",
		"    result := &Result{Data: make([]byte, len(input))}",
		"    for i, b := range input {",
		"        result.Data[i] = b ^ config.XORMask",
		"    }",
		"    result.Checksum = calculateChecksum(result.Data)",
		"    return result, nil",
	}

	// File 1 (note: avoid /test/ in path as it triggers IsTestFile)
	ctx1 := &core.FileContext{
		Path:    "/project/pkg/processor/data.go",
		RelPath: "pkg/processor/data.go",
		Lines:   append([]string{"package processor", ""}, duplicateBlock...),
	}

	// File 2 - contains same duplicate
	ctx2 := &core.FileContext{
		Path:    "/project/pkg/transformer/data.go",
		RelPath: "pkg/transformer/data.go",
		Lines:   append([]string{"package transformer", ""}, duplicateBlock...),
	}

	// Reset rule state
	rule.ResetState()

	// Process file 1 - should find no violations yet
	violations1 := rule.AnalyzeFile(ctx1)
	if len(violations1) != 0 {
		t.Errorf("Expected 0 violations for first file, got %d", len(violations1))
	}

	// Process file 2 - should detect duplicate from file 1
	violations2 := rule.AnalyzeFile(ctx2)
	if len(violations2) == 0 {
		t.Error("Expected to find cross-file duplicate")
	}

	// Verify violation details
	if len(violations2) > 0 {
		v := violations2[0]
		if v.Rule != "cross-file-duplicate" {
			t.Errorf("Expected rule 'cross-file-duplicate', got '%s'", v.Rule)
		}
		if v.Context["original_file"] != "pkg/processor/data.go" {
			t.Errorf("Expected original_file 'pkg/processor/data.go', got '%s'", v.Context["original_file"])
		}
	}
}

func TestCrossFileDuplicateRule_NoDuplicate(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	rule.minBlockSize = 5

	ctx1 := &core.FileContext{
		Path:    "/project/pkg/a/file1.go",
		RelPath: "pkg/a/file1.go",
		Lines: []string{
			"package main",
			"func foo() {",
			"    a := 1",
			"    b := 2",
			"    c := 3",
			"    fmt.Println(a + b + c)",
			"}",
		},
	}

	ctx2 := &core.FileContext{
		Path:    "/project/pkg/b/file2.go",
		RelPath: "pkg/b/file2.go",
		Lines: []string{
			"package main",
			"func bar() {",
			"    x := 10",
			"    y := 20",
			"    z := 30",
			"    fmt.Println(x * y * z)",
			"}",
		},
	}

	rule.ResetState()

	violations1 := rule.AnalyzeFile(ctx1)
	violations2 := rule.AnalyzeFile(ctx2)

	if len(violations1) != 0 || len(violations2) != 0 {
		t.Error("Expected no violations for different code")
	}
}

// Test files carry the same copy-paste debt as production code: a fixture block
// copied into five test files is fixed five times when the setup changes.
func TestCrossFileDuplicateComparesTestFiles(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	body := `func TestSplit(t *testing.T) {
	store := newStore(t, "orders", withRetention(30*time.Day))
	order := store.Create(Order{Customer: "acme", Amount: 1500})
	parts := splitter.Split(order, SplitPolicy{MaxPart: 500})
	require.Len(t, parts, 3)
	assert.Equal(t, order.ID, parts[0].ParentID)
	assert.Equal(t, int64(500), parts[0].Amount)
	assert.Equal(t, int64(500), parts[1].Amount)
	assert.Equal(t, int64(500), parts[2].Amount)
	assert.NoError(t, store.Verify(order.ID))
}
`
	first := createTestContext(t, "billing/split_test.go", "package billing\n"+body)
	second := createTestContext(t, "invoices/split_test.go", "package invoices\n"+body)

	assert.Empty(t, rule.AnalyzeFile(first))
	violations := rule.AnalyzeFile(second)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "billing/split_test.go")
}

// Repro: two wrapper scripts each carried the same container launch block, and
// the copies drifted apart (one lost its "|| true" under pipefail). Shell is
// code with the same duplication problem.
func TestCrossFileDuplicateComparesShell(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	body := `MAPS=${MAPS:-$HOME/games/maps}
IMAGE=${IMAGE:-registry.local/engine:latest}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/tool-XXXXXX")
trap 'rm -rf "$WORK"' EXIT
(cd "$(dirname "$0")/.." && CGO_ENABLED=0 go build -o "$WORK/tool" ./cmd/tool)
$ENGINE run --rm -e TZ=Europe/Belgrade -v "$WORK:/work:z" \\
    -v "$MAPS:/root/maps:ro,z" --entrypoint /work/tool "$IMAGE" "$@" \\
    | grep -v 'INFO engine started' || true
echo "tool finished with status $? in $WORK"
rm -rf "$WORK/cache" "$WORK/replays" "$WORK/logs"
`
	first := createTestContext(t, "tools/scan.sh", "#!/usr/bin/env bash\nset -euo pipefail\n"+body)
	second := createTestContext(t, "tools/story.sh", "#!/usr/bin/env bash\nset -eu\n"+body)

	assert.Empty(t, rule.AnalyzeFile(first))
	violations := rule.AnalyzeFile(second)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "tools/scan.sh")
}

// Repro from projectA: 611 TypeScript files were never compared, because the rule
// only looked at Go. A type declared twice is the same duplication problem.
func TestCrossFileDuplicateComparesTypeScript(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	body := `interface PlatformProfit {
  periodStart: string
  periodEnd: string
  strategy: string
  vaultValueStart: string
  vaultValueEnd: string
  netDeposits: string
  systemProfit: string
  platformProfit: string
  userProfit: string
  effectiveAPY: string
}
`
	first := createTestContext(t, "frontend/card.tsx", "export const Card = () => null\n"+body)
	second := createTestContext(t, "frontend/page.tsx", "export const Page = () => null\n"+body)

	assert.Empty(t, rule.AnalyzeFile(first))
	violations := rule.AnalyzeFile(second)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "card.tsx")
}

// A copied region matches at every window offset inside it; the reader needs the
// region once, not one finding per line.
func TestCrossFileDuplicateReportsRegionOnce(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	var block strings.Builder
	for i := range 30 {
		fmt.Fprintf(&block, "  const value%d = computeSomething(input, %d, options)\n", i, i)
	}

	first := createTestContext(t, "frontend/a.ts", "export function a() {\n"+block.String()+"}\n")
	second := createTestContext(t, "frontend/b.ts", "export function b() {\n"+block.String()+"}\n")

	assert.Empty(t, rule.AnalyzeFile(first))
	violations := rule.AnalyzeFile(second)
	assert.Len(t, violations, 1, "one finding for the whole copied region")
}

// Content inside raw-string literals is data, not code: duplicate-block blanks
// those lines before hashing, and the cross-file rule must judge the same
// content the same way.
func TestCrossFileDuplicateIgnoresRawStringContent(t *testing.T) {
	rule := NewCrossFileDuplicateRule()
	rule.minBlockSize = 8

	sql := "const query = `\n" +
		"SELECT users.id, users.name, users.email, users.created_at\n" +
		"FROM users\n" +
		"JOIN orders ON orders.user_id = users.id\n" +
		"JOIN payments ON payments.order_id = orders.id\n" +
		"WHERE payments.status = 'settled' AND orders.total > 1000\n" +
		"GROUP BY users.id, users.name, users.email, users.created_at\n" +
		"HAVING COUNT(orders.id) > 10\n" +
		"ORDER BY users.created_at DESC\n" +
		"`\n"

	first := createTestContext(t, "backend/reports.go", "package reports\n\n"+sql)
	second := createTestContext(t, "backend/exports.go", "package exports\n\n"+sql)

	assert.Empty(t, rule.AnalyzeFile(first))
	assert.Empty(t, rule.AnalyzeFile(second),
		"identical raw-string content is not code duplication")
}

func TestCrossFileDuplicateRule_ResetState(t *testing.T) {
	rule := NewCrossFileDuplicateRule()

	// Add some state
	rule.firstSeen[1] = BlockLocation{File: "test.go"}
	rule.reported[1] = true

	rule.ResetState()

	if len(rule.firstSeen) != 0 {
		t.Error("Expected firstSeen to be empty after ResetState")
	}
	if len(rule.reported) != 0 {
		t.Error("Expected reported to be empty after ResetState")
	}
}
