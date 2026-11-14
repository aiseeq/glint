package duplication

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// The library cleans a payment reference; the copies below keep its calls,
// operators and literals.
const libraryReferenceSource = `package lib

import "strings"

func CleanReference(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, " ", "")
	if value == "" {
		return "none"
	}
	if strings.HasPrefix(value, "#") {
		value = "ref" + value
	}
	if strings.HasSuffix(value, "#") {
		value = value + "0"
	}
	return value
}
`

// The library finds the holder of a key by its digest, comparing every
// digest in constant time.
const libraryKeySource = `package lib

import (
	"crypto/sha256"
	"crypto/subtle"
)

func MatchKey(key string, digests [][][]byte) int {
	digest := sha256.Sum256([]byte(key))
	matched := -1
	for i, entry := range digests {
		for _, known := range entry {
			if subtle.ConstantTimeCompare(digest[:], known) == 1 {
				matched = i
			}
		}
	}
	return matched
}
`

// The library tells a six-digit code.
const libraryCodeSource = `package lib

func LooksLikeCode(value string) bool {
	if len(value) != 6 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
`

// The library describes a transfer field by field; no field depends on
// another, so a copy may set them in any order.
const libraryTransferSource = `package lib

import (
	"strconv"
	"strings"
)

func squash(value string) string { return strings.Join(strings.Fields(value), "") }

func DescribeTransfer(from, to string, amount int64) map[string]string {
	out := make(map[string]string)
	out["from"] = squash(from)
	out["to"] = strings.ToUpper(to)
	out["amount"] = strconv.FormatInt(amount, 10)
	out["fee"] = strconv.FormatInt(amount/100, 10)
	out["route"] = from + "->" + to
	return out
}
`

// transferCopy sets the fields of DescribeTransfer in the reverse order and
// keeps a squash of its own.
const transferCopy = `package app

import (
	"strconv"
	"strings"
)

func squash(value string) string { return strings.Join(strings.Fields(value), "") }

func payprovTransfer(from, to string, amount int64) map[string]string {
	out := make(map[string]string)
	out["route"] = from + "->" + to
	out["fee"] = strconv.FormatInt(amount/100, 10)
	out["amount"] = strconv.FormatInt(amount, 10)
	out["to"] = strings.ToUpper(to)
	out["from"] = squash(from)
	return out
}
`

// isolateLibraryCache gives the rule an empty cache of its own. The Go build
// cache stays where it was: under a new XDG_CACHE_HOME the go command would
// build the export data of every imported standard package again, seconds
// per test.
func isolateLibraryCache(t *testing.T) {
	t.Helper()
	if os.Getenv("GOCACHE") == "" {
		base, err := os.UserCacheDir()
		require.NoError(t, err)
		t.Setenv("GOCACHE", filepath.Join(base, "go-build"))
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

func nearLibraryFindings(t *testing.T, libSource, source string) []*core.Violation {
	t.Helper()
	return nearLibraryFilesFindings(t, map[string]string{"lib.go": libSource}, source)
}

func nearLibraryFilesFindings(t *testing.T, libFiles map[string]string, source string) []*core.Violation {
	t.Helper()
	isolateLibraryCache(t)
	ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", source, libFiles, true, "")
	violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
	require.NoError(t, err)
	return violations
}

// A copy that runs the same independent replacements and checks in another
// order is the same function.
func TestDuplicateFuncOfLibraryNearCopyReorderedStatements(t *testing.T) {
	violations := nearLibraryFindings(t, libraryReferenceSource, `package app

import "strings"

func tidyReference(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "-", "")
	if value == "" { return "none" }
	if strings.HasSuffix(value, "#") { value = value + "0" }
	if strings.HasPrefix(value, "#") { value = "ref" + value }
	return value
}
`)
	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Function tidyReference is a near copy")
	assert.Contains(t, violations[0].Message, "call lib.CleanReference instead")
}

// Independent statements moved far apart keep few tokens in sequence but every
// statement of the library function; the copy calls its own copy of a helper
// of the library.
func TestDuplicateFuncOfLibraryNearCopyStatementsInReverseOrder(t *testing.T) {
	violations := nearLibraryFindings(t, libraryTransferSource, transferCopy)
	require.Len(t, violations, 1)
	assert.Equal(t, 10, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Function payprovTransfer is a near copy (100% alike) of function DescribeTransfer")
}

// A library package the project cannot import offers nothing to call
// instead.
func TestDuplicateFuncOfLibraryNearCopySkipsInternalLibraryPackage(t *testing.T) {
	source := strings.Replace(libraryTransferSource, "package lib", "package transfer", 1)
	assert.Empty(t, nearLibraryFilesFindings(t, map[string]string{"lib.go": "package lib\n", "internal/transfer/transfer.go": source}, transferCopy))
}

// lcsLength agrees with the textbook dynamic program on sequences that span
// several words of the bit sets.
func TestNearLCSLengthMatchesDynamicProgramming(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	tokens := func() []string {
		out := make([]string, 1+rng.IntN(300))
		for i := range out {
			out[i] = string(rune('a' + rng.IntN(4)))
		}
		return out
	}
	for range 200 {
		a, b := tokens(), tokens()
		table := make([][]int, len(a)+1)
		for i := range table {
			table[i] = make([]int, len(b)+1)
		}
		for i := 1; i <= len(a); i++ {
			for j := 1; j <= len(b); j++ {
				if a[i-1] == b[j-1] {
					table[i][j] = table[i-1][j-1] + 1
				} else {
					table[i][j] = max(table[i-1][j], table[i][j-1])
				}
			}
		}
		require.Equal(t, table[len(a)][len(b)], lcsLength(newNearCandidate(libraryMatch{}, nearBody{Tokens: a}), b))
	}
}

// A method of a registry runs the body of the library function over its own
// element type: a pointer to the holder for its index, the digests of a field
// for the slice itself.
func TestDuplicateFuncOfLibraryNearCopyMethodOverOtherElementType(t *testing.T) {
	violations := nearLibraryFindings(t, libraryKeySource, `package app

import (
	"crypto/sha256"
	"crypto/subtle"
)

type payprovAccount struct{ keyDigests [][]byte }

type payprovRegistry struct{ accounts []*payprovAccount }

func (r *payprovRegistry) lookup(key string) *payprovAccount {
	digest := sha256.Sum256([]byte(key))
	var matched *payprovAccount
	for _, account := range r.accounts {
		for _, known := range account.keyDigests {
			if subtle.ConstantTimeCompare(digest[:], known) == 1 {
				matched = account
			}
		}
	}
	return matched
}
`)
	require.Len(t, violations, 1)
	assert.Equal(t, 12, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Function payprovRegistry.lookup is a near copy")
	assert.Contains(t, violations[0].Message, "call lib.MatchKey instead")
}

// Functions that look like the library function but do another thing: they
// call another function, compare the other way, carry another value, or do
// more than the library function does.
func TestDuplicateFuncOfLibraryNearCopyKeepsDifferentFunctionsApart(t *testing.T) {
	for name, tc := range map[string]struct{ lib, source string }{
		"other call": {libraryReferenceSource, `package app

import "strings"

func tidyReference(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, " ", "")
	if value == "" { return "none" }
	if strings.HasPrefix(value, "#") { value = "ref" + value }
	if strings.Contains(value, "#") { value = value + "0" }
	return value
}
`},
		"other literal": {libraryReferenceSource, `package app

import "strings"

func tidyReference(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, "_", "")
	if value == "" { return "none" }
	if strings.HasPrefix(value, "#") { value = "ref" + value }
	if strings.HasSuffix(value, "#") { value = value + "0" }
	return value
}
`},
		"other comparison": {libraryKeySource, `package app

import (
	"crypto/sha256"
	"crypto/subtle"
)

type payprovAccount struct{ keyDigests [][]byte }

type payprovRegistry struct{ accounts []*payprovAccount }

func (r *payprovRegistry) lookup(key string) *payprovAccount {
	digest := sha256.Sum256([]byte(key))
	var matched *payprovAccount
	for _, account := range r.accounts {
		for _, known := range account.keyDigests {
			if subtle.ConstantTimeCompare(digest[:], known) != 1 {
				matched = account
			}
		}
	}
	return matched
}
`},
		"own constant for the literal": {libraryCodeSource, `package app

const accountNumberLength = 6

func isAccountNumber(search string) bool {
	if len(search) != accountNumberLength {
		return false
	}
	for _, c := range search {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
`},
		"more work with the same calls": {libraryReferenceSource, `package app

import "strings"

func splitReference(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	value = strings.ReplaceAll(value, "-", "")
	if value == "" { return "none", "" }
	head, tail := value, ""
	for i := range value {
		if strings.HasPrefix(value[i:], "#") {
			head, tail = value[:i], value[i:]
			break
		}
	}
	if strings.HasSuffix(tail, "#") {
		tail = strings.ReplaceAll(tail, " ", "") + "0"
	}
	return "ref" + head, tail
}
`},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, nearLibraryFindings(t, tc.lib, tc.source))
		})
	}
}

const libraryReferenceTS = `export function normalizeReference(raw: string): string {
  let value = raw.trim()
  value = value.replaceAll('-', '')
  value = value.replaceAll(' ', '')
  if (value === '') return 'none'
  if (value.startsWith('#')) value = 'ref' + value
  if (value.endsWith('#')) value = value + '0'
  return value
}
`

const librarySetTS = `export function toggleKey<Key>(values: ReadonlySet<Key>, key: Key): Set<Key> {
  const next = new Set(values)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  return next
}
`

const libraryBoundTS = `export function limitAmounts(values: number[], low: number, high: number): number[] {
  const out: number[] = []
  for (let v of values) {
    if (v < low) v = low
    if (v > high) v = high
    out.push(v)
  }
  return out
}

export function capAmounts(values: number[], low: number, high: number): number[] {
  const out: number[] = []
  for (let v of values) {
    if (v < low) {
      v = low
    }
    if (v > high) {
      v = high
    }
    out.push(v)
  }
  return out
}
`

// The checks of cleanCode hold their statements in braces.
const libraryCodeTS = `export function cleanCode(raw: string): string {
  let value = raw.trim()
  if (value === '') {
    return 'none'
  }
  if (value.startsWith('#')) {
    value = 'ref' + value
  }
  if (value.endsWith('#')) {
    value = value + '0'
  }
  return value
}

export function withMark(s: string, p: string): string {
  s = s.trim()
  p = p.trim()
  if (s === '') return p
  if (s.startsWith(p)) return s
  return p + s
}

export function grade(score: number, name: string): string {
  let label = 'unknown'
  if (score >= 90) {
    label = 'high'
  } else {
    label = 'low'
  }
  if (name === '') name = 'anon'
  return name + ':' + label + ':' + '*'.repeat(score / 10)
}

export function addCounts(a: Map<string, number>, b: Map<string, number>): string[] {
  const added: string[] = []
  for (const [k, v] of b) {
    if (!a.has(k)) added.push(k)
    a.set(k, (a.get(k) ?? 0) + v)
  }
  return added
}

export function limitSpan(values: number[], s: { low: number; high: number }): number[] {
  const out: number[] = []
  for (let v of values) {
    if (v < s.low) v = s.low
    if (v > s.high) v = s.high
    out.push(v)
  }
  return out
}

export function sumUntil(xs: number[]): number {
  let total = 0
  let count = 0
  for (const x of xs) {
    if (x === 0) continue
    if (x < 0) break
    total += x
    count++
  }
  return total * count
}

export function spread(xs: number[], pad: number): [number, number] {
  let lo = xs[0]
  let hi = xs[0]
  for (const x of xs) {
    if (x < lo) lo = x
    if (x > hi) hi = x
  }
  return [lo - pad, hi + pad]
}

export function countKnown(groups: string[][], key: string): number {
  let n = 0
  for (const group of groups) {
    for (const known of group) {
      if (known === key) n++
    }
  }
  return n
}

export function widenRange(values: number[], low: number, high: number): number[] {
  for (const v of values) {
    if (v < low) {
      low = v
    }
    if (high < v) {
      high = v
    }
  }
  return [low, high]
}
`

const libraryAccountTS = `export function buildAccount(accountID: string, label?: string): Account {
  return {
    id: accountID,
    label: label ?? '',
    limits: {},
    region: '',
  }
}
`

const libraryTransferTS = `export function describeTransfer(from: string, to: string, amount: number): Record<string, string> {
  const out: Record<string, string> = {}
  out['from'] = from.trim()
  out['to'] = to.toUpperCase()
  out['amount'] = String(amount)
  out['fee'] = String(Math.floor(amount / 100))
  out['route'] = from + '->' + to
  return out
}
`

const libraryLimitTS = `export function buildLimit(amount: number, currency: string, period: string, owner: string, region: string, source: string): Limit {
  return { amount: amount, currency: currency, period: period, owner: owner, region: region, source: source }
}
`

// The library keeps toCents to itself and ships a dependency under
// node_modules: neither is a function a project imports from it.
const libraryCentsTS = `const toCents = (amount: number): number => {
  const cents = Math.round(amount * 100)
  if (Number.isNaN(cents)) return 0
  return cents
}
`

const libraryDependencyTS = `export function addFee(amount: number): number {
  const fee = Math.ceil(amount / 50)
  if (fee > 10) return amount + 10
  return amount + fee
}
`

// tsLibraryFindings lays out a library module with TypeScript and a project
// whose Go module requires it, the TypeScript at tsPath under the project,
// and runs the rule on the files as the check flow does.
func tsLibraryFindings(t *testing.T, tsPath, goModDir, source string) []*core.Violation {
	t.Helper()
	return tsLibraryFilesFindings(t, map[string]string{
		"lib.go":                     libraryReferenceSource,
		"ts/amount.ts":               libraryReferenceTS,
		"ts/set.ts":                  librarySetTS,
		"ts/bound.ts":                libraryBoundTS,
		"ts/code.ts":                 libraryCodeTS,
		"ts/account.ts":              libraryAccountTS,
		"ts/transfer.ts":             libraryTransferTS,
		"ts/limit.ts":                libraryLimitTS,
		"ts/cents.ts":                libraryCentsTS,
		"node_modules/fees/index.ts": libraryDependencyTS,
		"package.json":               `{"name": "@owner/lib"}`,
	}, tsPath, goModDir, source)
}

// tsLibraryFilesFindings checks a TypeScript file against a library of the
// files given.
func tsLibraryFilesFindings(t *testing.T, libFiles map[string]string, tsPath, goModDir, source string) []*core.Violation {
	t.Helper()
	isolateLibraryCache(t)
	root := t.TempDir()
	writeLibraryTestModule(t, filepath.Join(root, "library"), "example.com/owner/lib", libFiles)
	project := filepath.Join(root, "project")
	moduleDir := filepath.Join(project, goModDir)
	rel, err := filepath.Rel(moduleDir, filepath.Join(root, "library"))
	require.NoError(t, err)
	writeLibraryTestConsumer(t, moduleDir, "example.com/owner/app", "example.com/owner/lib", rel, "package app\n")
	tsFile := filepath.Join(project, tsPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(tsFile), 0o755))
	require.NoError(t, os.WriteFile(tsFile, []byte(source), 0o644))
	goCtx, err := core.NewFileContextChecked(filepath.Join(moduleDir, "amount.go"), project, []byte("package app\n"), core.DefaultConfig())
	require.NoError(t, err)
	tsCtx, err := core.NewFileContextChecked(tsFile, project, []byte(source), core.DefaultConfig())
	require.NoError(t, err)
	rule := NewDuplicateFuncOfLibraryRule()
	rule.ResetState()
	rule.UseProjectFiles([]*core.FileContext{goCtx, tsCtx})
	require.True(t, rule.ReportsOn(tsCtx))
	return rule.AnalyzeFile(tsCtx)
}

// A TypeScript copy of a library function under another name, in the module
// that requires the library or in a frontend next to it.
func TestDuplicateFuncOfLibraryTypeScriptCopyUnderOtherName(t *testing.T) {
	copySource := strings.Replace(libraryReferenceTS, "export function normalizeReference", "function tidyReference", 1)
	for name, layout := range map[string]struct{ tsPath, goModDir string }{
		"in the module":  {"amount.ts", "."},
		"next to it":     {"frontend/src/amount.ts", "backend"},
		"arrow function": {"frontend/src/amount.ts", "backend"},
	} {
		t.Run(name, func(t *testing.T) {
			source := copySource
			if name == "arrow function" {
				source = strings.Replace(libraryReferenceTS, "export function normalizeReference(raw: string): string {", "export const tidyReference = (raw: string): string => {", 1)
			}
			violations := tsLibraryFindings(t, layout.tsPath, layout.goModDir, "// a copy\n"+source)
			require.Len(t, violations, 1)
			assert.Equal(t, 2, violations[0].Line)
			assert.Contains(t, violations[0].Message, "Function tidyReference duplicates function normalizeReference of library example.com/owner/lib (ts/amount.ts)")
			assert.Contains(t, violations[0].Message, "import normalizeReference from @owner/lib instead")
		})
	}
}

// Lines that set independent fields, in the reverse order: a statement ends
// at the line end.
func TestDuplicateFuncOfLibraryTypeScriptStatementsInReverseOrder(t *testing.T) {
	violations := tsLibraryFindings(t, "frontend/transfer.ts", "backend", `function payprovTransfer(from: string, to: string, amount: number): Record<string, string> {
  const out: Record<string, string> = {}
  out['route'] = from + '->' + to
  out['fee'] = String(Math.floor(amount / 100))
  out['amount'] = String(amount)
  out['to'] = to.toUpperCase()
  out['from'] = from.trim()
  return out
}
`)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Function payprovTransfer is a near copy (100% alike) of function describeTransfer")
}

// The keys of an object literal named like the parameters of the library
// function stay keys in a copy whose parameters are named otherwise.
func TestDuplicateFuncOfLibraryTypeScriptObjectKeysNamedLikeParameters(t *testing.T) {
	violations := tsLibraryFindings(t, "frontend/limit.ts", "backend", `function payprovLimit(value: number, code: string, span: string, holder: string, zone: string, origin: string): PayprovLimit {
  return { amount: value, currency: code, period: span, owner: holder, region: zone, source: origin }
}
`)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Function payprovLimit duplicates function buildLimit")
}

// A function the library does not export, or one of its dependencies, is no
// function to import from it.
func TestDuplicateFuncOfLibraryTypeScriptSkipsWhatTheLibraryDoesNotExport(t *testing.T) {
	for name, source := range map[string]string{
		"unexported arrow": strings.Replace(libraryCentsTS, "const toCents", "export const roundCents", 1),
		"dependency":       strings.Replace(libraryDependencyTS, "addFee", "payprovFee", 1),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, tsLibraryFindings(t, "frontend/money.ts", "backend", source))
		})
	}
}

// TypeScript that looks like the library function but calls, compares or
// carries something else.
func TestDuplicateFuncOfLibraryTypeScriptKeepsDifferentFunctionsApart(t *testing.T) {
	for name, source := range map[string]string{
		"other call":     strings.Replace(libraryReferenceTS, "value.endsWith('#')", "value.includes('#')", 1),
		"other literal":  strings.Replace(libraryReferenceTS, "'ref' + value", "'id' + value", 1),
		"other operator": strings.Replace(libraryReferenceTS, "value === ''", "value !== ''", 1),
	} {
		t.Run(name, func(t *testing.T) {
			source = strings.Replace(source, "export function normalizeReference", "function tidyReference", 1)
			assert.Empty(t, tsLibraryFindings(t, "amount.ts", ".", source))
		})
	}
}

// The library's own TypeScript, inside the analyzed root, belongs to the
// library module, which does not require itself: it is no copy of itself.
func TestDuplicateFuncOfLibraryTypeScriptSkipsLibraryFiles(t *testing.T) {
	isolateLibraryCache(t)
	root := t.TempDir()
	library := filepath.Join(root, "library")
	writeLibraryTestModule(t, library, "example.com/owner/lib", map[string]string{"lib.go": libraryReferenceSource, "amount.ts": libraryReferenceTS})
	writeLibraryTestConsumer(t, filepath.Join(root, "app"), "example.com/owner/app", "example.com/owner/lib", "../library", "package app\n")
	goCtx, err := core.NewFileContextChecked(filepath.Join(root, "app", "amount.go"), root, []byte("package app\n"), core.DefaultConfig())
	require.NoError(t, err)
	tsCtx, err := core.NewFileContextChecked(filepath.Join(library, "amount.ts"), root, []byte(libraryReferenceTS), core.DefaultConfig())
	require.NoError(t, err)
	rule := NewDuplicateFuncOfLibraryRule()
	rule.UseProjectFiles([]*core.FileContext{goCtx, tsCtx})
	assert.Empty(t, rule.AnalyzeFile(tsCtx))
}

// A callback that state updates run is a copy too: it is named by the
// function it is written in. An object key named like a parameter of the
// library function is a key, not the parameter.
func TestDuplicateFuncOfLibraryTypeScriptCallbackAndObjectKeys(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"callback": {`const toggleRow = (key: string) => {
  setRows(prev => {
    const next = new Set(prev)
    if (next.has(key)) {
      next.delete(key)
    } else {
      next.add(key)
    }
    return next
  })
}
`, "Anonymous function in toggleRow is a near copy"},
		"object keys": {`function payprovAccount(id: string, accountLabel?: string): PayprovAccount {
  return { id: id, label: accountLabel ?? '', limits: {}, region: '' } as PayprovAccount
}
`, "Function payprovAccount is a near copy"},
	} {
		t.Run(name, func(t *testing.T) {
			violations := tsLibraryFindings(t, "frontend/rows.tsx", "backend", tc.source)
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// Callbacks and object builders that do another thing are no copies.
func TestDuplicateFuncOfLibraryTypeScriptCallbacksKeptApart(t *testing.T) {
	for name, code := range map[string]string{
		"callback that adds only": `const addRow = (key: string) => {
  setRows(prev => {
    const next = new Set(prev)
    if (next.has(key)) return prev
    next.add(key)
    return next
  })
}
`,
		"callback that never deletes": `const keepRow = (key: string) => {
  setRows(prev => {
    const next = new Set(prev)
    if (next.has(key)) {
      next.add(key)
    } else {
      next.add(key)
    }
    return next
  })
}
`,
		"builder with another default": `function payprovAccount(id: string, accountLabel?: string): PayprovAccount {
  return { id: id, label: accountLabel ?? 'none', limits: {}, region: '' } as PayprovAccount
}
`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, tsLibraryFindings(t, "frontend/rows.tsx", "backend", code))
		})
	}
}

// TypeScript in a Go module that does not require the library is compared
// with the libraries of that module only, though another module of the root
// requires it.
func TestDuplicateFuncOfLibraryTypeScriptModuleWithoutTheLibrary(t *testing.T) {
	isolateLibraryCache(t)
	root := t.TempDir()
	writeLibraryTestModule(t, filepath.Join(root, "library"), "example.com/owner/lib", map[string]string{"lib.go": libraryReferenceSource, "ts/amount.ts": libraryReferenceTS})
	writeLibraryTestConsumer(t, filepath.Join(root, "backend"), "example.com/owner/app", "example.com/owner/lib", "../library", "package app\n")
	writeLibraryTestModule(t, filepath.Join(root, "tools"), "example.com/owner/tools", nil)
	goCtx, err := core.NewFileContextChecked(filepath.Join(root, "backend", "amount.go"), root, []byte("package app\n"), core.DefaultConfig())
	require.NoError(t, err)
	source := strings.Replace(libraryReferenceTS, "export function normalizeReference", "function tidyReference", 1)
	tsFile := filepath.Join(root, "tools", "web", "amount.ts")
	require.NoError(t, os.MkdirAll(filepath.Dir(tsFile), 0o755))
	require.NoError(t, os.WriteFile(tsFile, []byte(source), 0o644))
	tsCtx, err := core.NewFileContextChecked(tsFile, root, []byte(source), core.DefaultConfig())
	require.NoError(t, err)
	rule := NewDuplicateFuncOfLibraryRule()
	rule.UseProjectFiles([]*core.FileContext{goCtx, tsCtx})
	assert.Empty(t, rule.AnalyzeFile(tsCtx))
}

// A changed TypeScript source of a local library is read again: the cache
// key of a local library covers its TypeScript too.
func TestDuplicateFuncOfLibraryLocalTypeScriptChangeMissesCache(t *testing.T) {
	isolateLibraryCache(t)
	root := t.TempDir()
	library := filepath.Join(root, "library")
	writeLibraryTestModule(t, library, "example.com/owner/lib", map[string]string{"lib.go": libraryReferenceSource, "ts/set.ts": librarySetTS})
	writeLibraryTestConsumer(t, filepath.Join(root, "app"), "example.com/owner/app", "example.com/owner/lib", "../library", "package app\n")
	goCtx, err := core.NewFileContextChecked(filepath.Join(root, "app", "amount.go"), root, []byte("package app\n"), core.DefaultConfig())
	require.NoError(t, err)
	rule := NewDuplicateFuncOfLibraryRule()
	index := func() {
		rule.ResetState()
		tsCtx, err := core.NewFileContextChecked(filepath.Join(root, "app", "rows.ts"), root, []byte(""), core.DefaultConfig())
		require.NoError(t, err)
		rule.UseProjectFiles([]*core.FileContext{goCtx, tsCtx})
	}
	index()
	first := libraryPackageLoads.Load()
	index()
	assert.Equal(t, first, libraryPackageLoads.Load(), "an unchanged library is read from the cache")
	require.NoError(t, os.WriteFile(filepath.Join(library, "ts", "set.ts"), []byte(strings.Replace(librarySetTS, "toggleKey", "flipKey", 1)), 0o644))
	index()
	assert.Greater(t, libraryPackageLoads.Load(), first, "a changed TypeScript source misses the cache")
}

// The library limits every amount to a range and cuts a window of a list.
const libraryLimitSource = `package lib

func LimitAmounts(amounts []int, floor, ceiling int) []int {
	out := make([]int, 0, len(amounts))
	for _, amount := range amounts {
		if amount < floor {
			amount = floor
		}
		if amount > ceiling {
			amount = ceiling
		}
		out = append(out, amount)
	}
	return out
}

func PageOf(rows []string, start, end int) []string {
	if start < 0 {
		start = 0
	}
	if end > len(rows) {
		end = len(rows)
	}
	if start >= end {
		return nil
	}
	return rows[start:end]
}
`

// A copy may name its variables otherwise, check in another order, write
// the second check as an else branch, run over a field of its receiver or
// repeat a statement of the library function: each variable keeps its role.
func TestDuplicateFuncOfLibraryNearCopyKeepsRolesOfRenamedLocals(t *testing.T) {
	for name, tc := range map[string]struct{ lib, source, subject string }{
		"renamed and reordered": {libraryLimitSource, `package app

func payprovBound(values []int, lo, hi int) []int {
	res := make([]int, 0, len(values))
	for _, v := range values {
		if v > hi {
			v = hi
		}
		if v < lo {
			v = lo
		}
		res = append(res, v)
	}
	return res
}
`, "Function payprovBound is a near copy"},
		"else branch": {libraryLimitSource, `package app

func payprovBound(values []int, lo, hi int) []int {
	res := make([]int, 0, len(values))
	for _, v := range values {
		if v < lo {
			v = lo
		} else if v > hi {
			v = hi
		}
		res = append(res, v)
	}
	return res
}
`, "Function payprovBound is a near copy"},
		"method over a field": {libraryLimitSource, `package app

type payprovScores struct{ list []int }

func (s *payprovScores) bound(lo, hi int) []int {
	res := make([]int, 0, len(s.list))
	for _, v := range s.list {
		if v < lo {
			v = lo
		}
		if v > hi {
			v = hi
		}
		res = append(res, v)
	}
	return res
}
`, "Function payprovScores.bound is a near copy"},
		"repeated statement": {libraryReferenceSource, `package app

import "strings"

func tidyReference(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, " ", "")
	if value == "" { return "none" }
	if strings.HasPrefix(value, "#") { value = "ref" + value }
	if strings.HasSuffix(value, "#") { value = value + "0" }
	value = strings.ReplaceAll(value, " ", "")
	return value
}
`, "Function tidyReference is a near copy"},
	} {
		t.Run(name, func(t *testing.T) {
			violations := nearLibraryFindings(t, tc.lib, tc.source)
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// Variables in other roles make another function of the same tokens: a value
// below the range becomes its upper bound, a check reads another variable, the
// bounds of a slice are swapped.
func TestDuplicateFuncOfLibraryNearCopyLocalsInOtherRoles(t *testing.T) {
	for name, source := range map[string]string{
		"bounds swapped in the assignments": `package app

func payprovBound(values []int, lo, hi int) []int {
	res := make([]int, 0, len(values))
	for _, v := range values {
		if v < lo {
			v = hi
		}
		if v > hi {
			v = lo
		}
		res = append(res, v)
	}
	return res
}
`,
		"check of another variable": `package app

func payprovBound(values []int, lo, hi int) []int {
	res := make([]int, 0, len(values))
	for _, v := range values {
		if hi < lo {
			v = lo
		}
		if v > hi {
			v = hi
		}
		res = append(res, v)
	}
	return res
}
`,
		"slice bounds swapped": `package app

func payprovPage(rows []string, start, end int) []string {
	if start < 0 {
		start = 0
	}
	if end > len(rows) {
		end = len(rows)
	}
	if start >= end {
		return nil
	}
	return rows[end:start]
}
`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, nearLibraryFindings(t, libraryLimitSource, source))
		})
	}
}

// A literal of the library function in another place is another function:
// a separator replaced by another separator, or the arguments of a
// replacement swapped.
func TestDuplicateFuncOfLibraryNearCopyLiteralsInOtherPlaces(t *testing.T) {
	for name, replacement := range map[string]string{
		"other literal of the library": `strings.ReplaceAll(value, "-", "#")`,
		"arguments swapped":            `strings.ReplaceAll(value, "", "-")`,
	} {
		t.Run(name, func(t *testing.T) {
			source := strings.Replace(libraryReferenceSource, "package lib", "package app", 1)
			source = strings.Replace(source, "func CleanReference", "func tidyReference", 1)
			source = strings.Replace(source, `strings.ReplaceAll(value, "-", "")`, replacement, 1)
			assert.Empty(t, nearLibraryFindings(t, libraryReferenceSource, source))
		})
	}
}

// Only a body equal to the library function by the exact key duplicates it:
// a method with the very tokens of the library function is a near copy.
func TestDuplicateFuncOfLibraryNearCopyMethodWithTheSameTokens(t *testing.T) {
	violations := nearLibraryFindings(t, libraryLimitSource, `package app

type payprovLimiter struct{}

func (payprovLimiter) bound(amounts []int, floor, ceiling int) []int {
	out := make([]int, 0, len(amounts))
	for _, amount := range amounts {
		if amount < floor {
			amount = floor
		}
		if amount > ceiling {
			amount = ceiling
		}
		out = append(out, amount)
	}
	return out
}
`)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Function payprovLimiter.bound is a near copy (100% alike) of function LimitAmounts")
}

// TypeScript copies keep the roles of their variables and the places of
// their calls and literals; a renamed copy with reordered checks is one.
func TestDuplicateFuncOfLibraryTypeScriptRolesAndPlaces(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"renamed and reordered": {`function payprovBound(xs: number[], lo: number, hi: number): number[] {
  const res: number[] = []
  for (let x of xs) {
    if (x > hi) x = hi
    if (x < lo) x = lo
    res.push(x)
  }
  return res
}
`, "Function payprovBound is a near copy (100% alike) of function limitAmounts"},
		"renamed": {`function payprovFlip<T>(source: ReadonlySet<T>, item: T): Set<T> {
  const copy = new Set(source)
  if (copy.has(item)) copy.delete(item)
  else copy.add(item)
  return copy
}
`, "Function payprovFlip duplicates function toggleKey"},
		"bounds swapped": {`function payprovBound(values: number[], low: number, high: number): number[] {
  const out: number[] = []
  for (let v of values) {
    if (v < low) v = high
    if (v > high) v = low
    out.push(v)
  }
  return out
}
`, ""},
		"bounds swapped in blocks": {`function payprovBound(values: number[], low: number, high: number): number[] {
  const out: number[] = []
  for (let v of values) {
    if (v < low) {
      v = high
    }
    if (v > high) {
      v = low
    }
    out.push(v)
  }
  return out
}
`, ""},
		"one bound swapped in a block": {`function payprovBound(values: number[], low: number, high: number): number[] {
  const out: number[] = []
  for (let v of values) {
    if (v < low) v = low
    if (v > high) {
      v = low
    }
    out.push(v)
  }
  return out
}
`, ""},
		"argument of another parameter": {`function payprovFlip<T>(source: ReadonlySet<T>, item: T, other: T): Set<T> {
  const copy = new Set(source)
  if (copy.has(item)) copy.delete(item)
  else copy.add(other)
  return copy
}
`, ""},
		"calls swapped": {`function payprovFlip<T>(source: ReadonlySet<T>, item: T): Set<T> {
  const copy = new Set(source)
  if (copy.has(item)) copy.add(item)
  else copy.delete(item)
  return copy
}
`, ""},
		"check of the source": {`function payprovFlip<T>(source: ReadonlySet<T>, item: T): Set<T> {
  const copy = new Set(source)
  if (source.has(item)) copy.delete(item)
  else copy.add(item)
  return copy
}
`, ""},
		"checks trade what they guard": {`function payprovCode(raw: string): string {
  let value = raw.trim()
  if (value === '') {
    return 'none'
  }
  if (value.startsWith('#')) {
    value = value + '0'
  }
  if (value.endsWith('#')) {
    value = 'ref' + value
  }
  return value
}
`, ""},
		"checks of one shape trade what they guard": {`function payprovRange(values: number[], low: number, high: number): number[] {
  for (const v of values) {
    if (v < low) {
      high = v
    }
    if (high < v) {
      low = v
    }
  }
  return [low, high]
}
`, ""},
		"renamed range": {`function payprovRange(xs: number[], lo: number, hi: number): number[] {
  for (const x of xs) {
    if (x < lo) {
      lo = x
    }
    if (hi < x) {
      hi = x
    }
  }
  return [lo, hi]
}
`, "Function payprovRange duplicates function widenRange"},
		"trims swapped": {`function payprovMark(str: string, p: string): string {
  p = p.trim()
  str = str.trim()
  if (str === '') return p
  if (str.startsWith(p)) return str
  return p + str
}
`, "Function payprovMark is a near copy (100% alike) of function withMark"},
		"variable and literal trade places": {`function payprovGrade(score: number, name: string): string {
  let label = 'unknown'
  if (score >= 90) {
    label = 'high'
  } else {
    label = 'low'
  }
  if (name === '') name = 'anon'
  return name + ':' + label + ':' + '*'.repeat(10 / score)
}
`, ""},
		"variable in the place of a literal": {`function payprovGrade(score: number, name: string): string {
  let label = 'unknown'
  if (score >= 90) {
    label = 'high'
  } else {
    label = name
  }
  if (name === '') name = 'anon'
  return name + ':' + label + ':' + '*'.repeat(score / 10)
}
`, ""},
		"statement moved to the other branch": {`function payprovCounts(a: Map<string, number>, b: Map<string, number>): string[] {
  const added: string[] = []
  for (const [k, v] of b) {
    if (!a.has(k)) {
    } else {
      added.push(k)
    }
    a.set(k, (a.get(k) ?? 0) + v)
  }
  return added
}
`, ""},
		"checks on one line": {`function payprovCode(raw: string): string {
  let value = raw.trim()
  if (value === '') return 'none'
  if (value.startsWith('#')) value = 'ref' + value
  if (value.endsWith('#')) value = value + '0'
  return value
}
`, "Function payprovCode is a near copy"},
		"check dropped": {`function payprovGrade(score: number, name: string): string {
  let label = 'unknown'
  if (score >= 90) {
    label = 'high'
  } else {
    label = 'low'
  }
  name = 'anon'
  return name + ':' + label + ':' + '*'.repeat(score / 10)
}
`, ""},
		"statement moved out of its check": {`function payprovGrade(score: number, name: string): string {
  let label = 'unknown'
  if (score >= 90) {
    label = 'high'
  } else {
    label = 'low'
  }
  if (name === '') {
  }
  name = 'anon'
  return name + ':' + label + ':' + '*'.repeat(score / 10)
}
`, ""},
		"statement moved out of its check in a loop": {`function payprovCounts(a: Map<string, number>, b: Map<string, number>): string[] {
  const added: string[] = []
  for (const [k, v] of b) {
    if (!a.has(k)) {
    }
    added.push(k)
    a.set(k, (a.get(k) ?? 0) + v)
  }
  return added
}
`, ""},
		"statement held in braces": {`function payprovCounts(dst: Map<string, number>, src: Map<string, number>): string[] {
  const keys: string[] = []
  for (const [name, n] of src) {
    if (!dst.has(name)) {
      keys.push(name)
    }
    dst.set(name, (dst.get(name) ?? 0) + n)
  }
  return keys
}
`, "Function payprovCounts is a near copy"},
		"span renamed": {`function payprovLimit(xs: number[], r: { low: number; high: number }): number[] {
  const res: number[] = []
  for (let x of xs) {
    if (x < r.low) x = r.low
    if (x > r.high) x = r.high
    res.push(x)
  }
  return res
}
`, "Function payprovLimit "},
		"fields trade places": {`function payprovLimit(values: number[], s: { low: number; high: number }): number[] {
  const out: number[] = []
  for (let v of values) {
    if (v < s.low) v = s.high
    if (v > s.high) v = s.low
    out.push(v)
  }
  return out
}
`, ""},
		"jumps trade places": {`function payprovSum(xs: number[]): number {
  let total = 0
  let count = 0
  for (const x of xs) {
    if (x === 0) break
    if (x < 0) continue
    total += x
    count++
  }
  return total * count
}
`, ""},
		"signs trade places": {`function payprovSpread(xs: number[], pad: number): [number, number] {
  let lo = xs[0]
  let hi = xs[0]
  for (const x of xs) {
    if (x < lo) lo = x
    if (x > hi) hi = x
  }
  return [lo + pad, hi - pad]
}
`, ""},
		"break dropped": {`function payprovSum(xs: number[]): number {
  let total = 0
  let count = 0
  for (const x of xs) {
    if (x === 0) continue
    if (x < 0) {}
    total += x
    count++
  }
  return total * count
}
`, ""},
		"continue dropped": {`function payprovSum(xs: number[]): number {
  let total = 0
  let count = 0
  for (const x of xs) {
    if (x === 0) {}
    if (x < 0) break
    total += x
    count++
  }
  return total * count
}
`, ""},
		"calls trade places": {`function payprovCounts(a: Map<string, number>, b: Map<string, number>): string[] {
  const added: string[] = []
  for (const [k, v] of b) {
    if (!a.get(k)) added.push(k)
    a.set(k, (a.has(k) ?? 0) + v)
  }
  return added
}
`, ""},
		"field of the element": {`function payprovCountKnown(accounts: { keys: string[] }[], key: string): number {
  let n = 0
  for (const account of accounts) {
    for (let known of account.keys) {
      if (known === key) n++
    }
  }
  return n
}
`, "Function payprovCountKnown is a near copy"},
		"extra check of the input": {`function payprovCode(raw: string): string {
  if (raw === '') {
    return 'none'
  }
  let value = raw.trim()
  if (value === '') {
    return 'none'
  }
  if (value.startsWith('#')) {
    value = 'ref' + value
  }
  if (value.endsWith('#')) {
    value = value + '0'
  }
  return value
}
`, "Function payprovCode is a near copy"},
		"literals swapped": {strings.Replace(strings.Replace(libraryReferenceTS, "export function normalizeReference", "function tidyReference", 1), "value.replaceAll('-', '')", "value.replaceAll('', '-')", 1), ""},
	} {
		t.Run(name, func(t *testing.T) {
			violations := tsLibraryFindings(t, "frontend/bound.ts", "backend", tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// The library keys a name by case and tallies values on a counter of its own.
const libraryCallsSource = `package lib

import "strings"

func CaseKey(value string, upper bool) string {
	key := strings.TrimSpace(value)
	if upper {
		key = strings.ToUpper(key)
	} else {
		key = strings.ToLower(key)
	}
	if key == "" {
		return "none"
	}
	return strings.ReplaceAll(key, " ", "_")
}

type Counter struct{ up, down int }

func (c *Counter) Up() { c.up++ }

func (c *Counter) Down() { c.down++ }

func Tally(c *Counter, values []int) int {
	total := 0
	for _, v := range values {
		if v > 0 {
			c.Up()
		} else {
			c.Down()
		}
		total += v
	}
	return total
}

func WidenRange(values []int, low, high int) (int, int) {
	for _, v := range values {
		if v < low {
			low = v
		}
		if high < v {
			high = v
		}
	}
	return low, high
}
`

// The library grades a score with a label and adds the counts of one map to
// another, keeping the keys it adds.
const libraryGradeSource = `package lib

import "strings"

func Grade(score int, name string) string {
	label := "unknown"
	if score >= 90 {
		label = "high"
	} else {
		label = "low"
	}
	if name == "" {
		name = "anon"
	}
	return name + ":" + label + ":" + strings.Repeat("*", score/10)
}

func AddCounts(a, b map[string]int) []string {
	var added []string
	for k, v := range b {
		old, ok := a[k]
		if !ok {
			added = append(added, k)
		}
		a[k] = old + v
	}
	return added
}

func BoundAll(values []int, low, high int) []int {
	out := make([]int, 0, len(values))
	for _, v := range values {
		if v < low {
			v = low
		} else if v > high {
			v = high
		}
		out = append(out, v)
	}
	return out
}
`

// A statement that pairs with no statement of the library function is still
// read in place: a variable and a literal that trade places, a variable in
// the place of a literal, a statement moved from one branch to the other are
// other functions; a copy that moves an independent check is a copy.
func TestDuplicateFuncOfLibraryNearCopyStatementsThatDoNotPair(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"independent check moved": {`package app

import "strings"

func payprovGrade(s int, who string) string {
	if who == "" {
		who = "anon"
	}
	l := "unknown"
	if s >= 90 {
		l = "high"
	} else {
		l = "low"
	}
	return who + ":" + l + ":" + strings.Repeat("*", s/10)
}
`, "Function payprovGrade is a near copy (100% alike) of function Grade"},
		"two checks for an else if": {`package app

func payprovBound(values []int, lo, hi int) []int {
	res := make([]int, 0, len(values))
	for _, x := range values {
		if x < lo {
			x = lo
		}
		if x > hi {
			x = hi
		}
		res = append(res, x)
	}
	return res
}
`, "Function payprovBound is a near copy"},
		"variable and literal trade places": {`package app

import "strings"

func payprovGrade(score int, name string) string {
	label := "unknown"
	if score >= 90 {
		label = "high"
	} else {
		label = "low"
	}
	if name == "" {
		name = "anon"
	}
	return name + ":" + label + ":" + strings.Repeat("*", 10/score)
}
`, ""},
		"variable in the place of a literal": {`package app

import "strings"

func payprovGrade(score int, name string) string {
	label := "unknown"
	if score >= 90 {
		label = "high"
	} else {
		label = name
	}
	if name == "" {
		name = "anon"
	}
	return name + ":" + label + ":" + strings.Repeat("*", score/10)
}
`, ""},
		"statement moved out of its check": {`package app

import "strings"

func payprovGrade(score int, name string) string {
	label := "unknown"
	if score >= 90 {
		label = "high"
	} else {
		label = "low"
	}
	if name == "" {
	}
	name = "anon"
	return name + ":" + label + ":" + strings.Repeat("*", score/10)
}
`, ""},
		"check dropped": {`package app

import "strings"

func payprovGrade(score int, name string) string {
	label := "unknown"
	if score >= 90 {
		label = "high"
	} else {
		label = "low"
	}
	name = "anon"
	return name + ":" + label + ":" + strings.Repeat("*", score/10)
}
`, ""},
		"statement moved to the other branch": {`package app

func payprovCounts(a, b map[string]int) []string {
	var added []string
	for k, v := range b {
		old, ok := a[k]
		if !ok {
		} else {
			added = append(added, k)
		}
		a[k] = old + v
	}
	return added
}
`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			violations := nearLibraryFindings(t, libraryGradeSource, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// The library limits values to a span held in fields, sums values up to the
// first negative and pads the extent of values.
const librarySpanSource = `package lib

type Span struct{ Low, High int }

func Limit(values []int, s Span) []int {
	out := make([]int, 0, len(values))
	for _, v := range values {
		if v < s.Low {
			v = s.Low
		}
		if v > s.High {
			v = s.High
		}
		out = append(out, v)
	}
	return out
}

func SumUntil(xs []int) int {
	total := 0
	count := 0
	for _, x := range xs {
		if x == 0 {
			continue
		}
		if x < 0 {
			break
		}
		total += x
		count++
	}
	return total * count
}

func Spread(xs []int, pad int) (int, int) {
	lo, hi := xs[0], xs[0]
	for _, x := range xs {
		if x < lo {
			lo = x
		}
		if x > hi {
			hi = x
		}
	}
	return lo - pad, hi + pad
}

func Offsets(xs []int, base, step int) []int {
	out := make([]int, 0, len(xs))
	total := 0
	for _, x := range xs {
		total += step
		if x < base {
			out = append(out, -x, base+total)
		} else {
			out = append(out, x, base-total)
		}
	}
	return append(out, total)
}

`

// A field read in the place of another, an operator or a jump in the place
// of another, and a jump dropped make another function; a copy that renames
// the span or checks the bounds in the other order is a copy.
func TestDuplicateFuncOfLibraryNearCopyFieldsOperatorsAndJumps(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"renamed and reordered": {`package app

import "example.com/owner/lib"

func payprovLimit(xs []int, r lib.Span) []int {
	res := make([]int, 0, len(xs))
	for _, x := range xs {
		if x > r.High {
			x = r.High
		}
		if x < r.Low {
			x = r.Low
		}
		res = append(res, x)
	}
	return res
}
`, "Function payprovLimit is a near copy (100% alike) of function Limit"},
		"fields trade places": {`package app

import "example.com/owner/lib"

func payprovLimit(values []int, s lib.Span) []int {
	out := make([]int, 0, len(values))
	for _, v := range values {
		if v < s.Low {
			v = s.High
		}
		if v > s.High {
			v = s.Low
		}
		out = append(out, v)
	}
	return out
}
`, ""},
		"fields trade places in the checks": {`package app

import "example.com/owner/lib"

func payprovLimit(values []int, s lib.Span) []int {
	out := make([]int, 0, len(values))
	for _, v := range values {
		if v < s.High {
			v = s.Low
		}
		if v > s.Low {
			v = s.High
		}
		out = append(out, v)
	}
	return out
}
`, ""},
		"jumps trade places": {`package app

func payprovSum(xs []int) int {
	total := 0
	count := 0
	for _, x := range xs {
		if x == 0 {
			break
		}
		if x < 0 {
			continue
		}
		total += x
		count++
	}
	return total * count
}
`, ""},
		"jump dropped": {`package app

func payprovSum(xs []int) int {
	total := 0
	count := 0
	for _, x := range xs {
		if x == 0 {
			continue
		}
		if x < 0 {
		}
		total += x
		count++
	}
	return total * count
}
`, ""},
		"signs trade places": {`package app

func payprovSpread(xs []int, pad int) (int, int) {
	lo, hi := xs[0], xs[0]
	for _, x := range xs {
		if x < lo {
			lo = x
		}
		if x > hi {
			hi = x
		}
	}
	return lo + pad, hi - pad
}
`, ""},
		"counter runs down": {`package app

func payprovSum(xs []int) int {
	total := 0
	count := 0
	for _, x := range xs {
		if x == 0 {
			continue
		}
		if x < 0 {
			break
		}
		total += x
		count--
	}
	return total * count
}
`, ""},
		"negation moves": {`package app

func payprovOffsets(xs []int, base, step int) []int {
	out := make([]int, 0, len(xs))
	total := 0
	for _, x := range xs {
		total += step
		if x < base {
			out = append(out, x, -base+total)
		} else {
			out = append(out, x, base-total)
		}
	}
	return append(out, total)
}
`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			violations := nearLibraryFindings(t, librarySpanSource, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// Above the bound of its table sameRest compares nothing and so takes the
// two bodies for different: a long function is no copy unchecked.
func TestNearSameRestRejectsWhatItCannotAlign(t *testing.T) {
	long := make([]nearToken, 2100)
	for i := range long {
		long[i] = nearToken{text: "a", vr: -1}
	}
	m := &roleMapping{forward: map[int]int{}, back: map[int]int{}}
	roles := []nearRole{{Parent: -1}}
	assert.False(t, m.sameRest(restSide{tokens: long, roles: roles}, restSide{tokens: long, roles: roles}))
	assert.True(t, m.sameRest(restSide{tokens: long[:100], roles: roles}, restSide{tokens: long[:100], roles: roles}))
}

// A jump of the library function the copy lacks makes another function, even
// when the copy has nothing the library function lacks; a name that reads
// like a jump is no jump.
func TestNearSameRestRejectsADroppedJump(t *testing.T) {
	m := &roleMapping{forward: map[int]int{}, back: map[int]int{}}
	roles := []nearRole{{Parent: -1}}
	jump := []nearToken{{text: "continue", vr: nearAnchor}}
	assert.False(t, m.sameRest(restSide{tokens: jump, roles: roles}, restSide{roles: roles}))
	assert.True(t, m.sameRest(restSide{tokens: []nearToken{{text: "x", vr: -1}}, roles: roles}, restSide{roles: roles}))
	assert.False(t, isNearJump(nearToken{text: "break", vr: -1}))
	assert.True(t, isNearJump(nearToken{text: "break", vr: nearAnchor}))
}

// A field the copy reads where the library function reads the variable is
// that variable on either side; two fields of one variable stay two.
func TestNearKeptApartTakesAFieldForItsVariable(t *testing.T) {
	const root, field, other, lib = 1, 10, 2, 0
	edges := map[[2]int]bool{{root, lib}: true, {field, lib}: true, {field, 5}: true}
	assert.False(t, keptApart(edges, nil, nil, nil, nil))
	assert.True(t, keptApart(edges, nil, nil, nil, map[int]int{field: root}))
	reversed := map[[2]int]bool{{lib, root}: true, {lib, field}: true, {5, field}: true}
	assert.False(t, keptApart(reversed, nil, nil, nil, nil))
	assert.True(t, keptApart(reversed, nil, nil, map[int]int{field: root}, nil))
	assert.False(t, keptApart(edges, nil, nil, nil, map[int]int{field: other}))
}

// A Go body takes a field read of a variable of the function for a variable
// of its own, but not a field of a variable from outside.
func TestGoNearBodyFieldsOfItsVariables(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "app.go", `package app

type span struct{ Low, High int }

var limits span

func payprovClip(v int, s span) int {
	if v < limits.Low {
		v = s.Low
	}
	return v
}
`, 0)
	require.NoError(t, err)
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	_, err = (&types.Config{}).Check("app", fset, []*ast.File{file}, info)
	require.NoError(t, err)
	fd, ok := file.Decls[len(file.Decls)-1].(*ast.FuncDecl)
	require.True(t, ok)
	body := goNearBody(info, fd, true)
	assert.Len(t, body.Roots, 1)
}

// A TypeScript body takes break, continue and return for jumps but a property named
// so, and a field read of a variable for a variable of its own but a method
// called on it, an optional call, and a property of a name of no variable.
func TestTSNearBodyJumpsAndFields(t *testing.T) {
	src := parseTSSource(strings.Split(`function payprovWalk(o: { v: number; break: number; f?: (n: number) => void }, xs: number[]): number {
  let n = o.break
  for (const x of xs) {
    if (x < 0) break
    if (x > o.v) continue
    n += x + Number.EPSILON
  }
  o.f?.(n)
  const flags = { continue: n > 0 }
  console.log(flags)
  return n
}
`, "\n"))
	require.NotEmpty(t, src.funcs)
	body := src.tsNearBody(src.funcs[0], true)
	var jumps []string
	for i, text := range body.Tokens {
		if isNearJump(nearToken{text: text, vr: body.Vars[i]}) {
			jumps = append(jumps, text)
		}
	}
	assert.Equal(t, []string{"break", "continue", "return"}, jumps)
	assert.Len(t, body.Roots, 1)
}

// A call in the place of another is another function, though the copy calls
// the same functions: a check that trades the statements it guards with the
// other check, a function or a method of each branch called in the other.
func TestDuplicateFuncOfLibraryNearCopyCallsInOtherPlaces(t *testing.T) {
	for name, tc := range map[string]struct{ lib, source string }{
		"checks trade what they guard": {libraryReferenceSource, `package app

import "strings"

func tidyReference(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, " ", "")
	if value == "" { return "none" }
	if strings.HasSuffix(value, "#") { value = "ref" + value }
	if strings.HasPrefix(value, "#") { value = value + "0" }
	return value
}
`},
		"functions of the branches swapped": {libraryCallsSource, `package app

import "strings"

func payprovKey(value string, upper bool) string {
	key := strings.TrimSpace(value)
	if upper {
		key = strings.ToLower(key)
	} else {
		key = strings.ToUpper(key)
	}
	if key == "" {
		return "none"
	}
	return strings.ReplaceAll(key, " ", "_")
}
`},
		"checks of one shape trade what they guard": {libraryCallsSource, `package app

func payprovRange(values []int, low, high int) (int, int) {
	for _, v := range values {
		if v < low {
			high = v
		}
		if high < v {
			low = v
		}
	}
	return low, high
}
`},
		"methods of the branches swapped": {libraryCallsSource, `package app

import "example.com/owner/lib"

func payprovTally(c *lib.Counter, values []int) int {
	total := 0
	for _, v := range values {
		if v > 0 {
			c.Down()
		} else {
			c.Up()
		}
		total += v
	}
	return total
}
`},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, nearLibraryFindings(t, tc.lib, tc.source))
		})
	}
}

// A copy that checks its input once more before the library function's own
// check, with a variable of its own in the place of the library one, is
// still a copy: the check that agrees pairs with the library check.
func TestDuplicateFuncOfLibraryNearCopyWithAnExtraCheckOfTheInput(t *testing.T) {
	violations := nearLibraryFindings(t, libraryReferenceSource, `package app

import "strings"

func tidyReference(raw string) string {
	if raw == "" { return "none" }
	value := strings.TrimSpace(raw)
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, " ", "")
	if value == "" { return "none" }
	if strings.HasPrefix(value, "#") { value = "ref" + value }
	if strings.HasSuffix(value, "#") { value = value + "0" }
	return value
}
`)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Function tidyReference is a near copy")
}

// unify leaves the correspondence as it was when a statement does not pair.
func TestNearRoleMappingUnifyChangesNothingOnFailure(t *testing.T) {
	m := &roleMapping{forward: map[int]int{1: 1}, back: map[int]int{1: 1}}
	require.False(t, m.unify(nearRole{Locals: []int{5, 1}}, nearRole{Locals: []int{7, 2}}))
	assert.Equal(t, map[int]int{1: 1}, m.forward)
	assert.Equal(t, map[int]int{1: 1}, m.back)
	require.True(t, m.unify(nearRole{Locals: []int{6, 1}}, nearRole{Locals: []int{7, 1}}))
	assert.Equal(t, map[int]int{1: 1, 6: 7}, m.forward)
}

// sameRest takes a literal, a call or a variable skipped on both sides
// between two matched tokens for one in the place of the other, and so a
// literal or a call skipped on both sides anywhere and a variable skipped on
// both sides with the one it stands for; an anchor dropped in one place and
// another added elsewhere, a plain token in the place of an anchor, or a
// variable of its own in two places is no such place.
func TestNearSameRestReadsAnchorsInPlace(t *testing.T) {
	plain := func(text string) nearToken { return nearToken{text: text, vr: -1} }
	anchor := func(text string) nearToken { return nearToken{text: text, vr: nearAnchor} }
	local := func(vr int) nearToken { return nearToken{text: "$L", vr: vr} }
	for name, tc := range map[string]struct {
		lib, own []nearToken
		same     bool
		paired   bool
	}{
		"variable in the place of an anchor":                 {[]nearToken{plain("a"), anchor("x"), plain("b")}, []nearToken{plain("a"), local(0), plain("b")}, false, false},
		"anchor in the place of a variable":                  {[]nearToken{plain("a"), local(0), plain("b")}, []nearToken{plain("a"), anchor("x"), plain("b")}, false, false},
		"a variable in two places, standing for its partner": {[]nearToken{plain("a"), local(0), plain("b"), plain("c")}, []nearToken{plain("a"), plain("b"), local(0), plain("c")}, false, true},
		"anchor in the place of another":                     {[]nearToken{plain("a"), anchor("x"), plain("b")}, []nearToken{plain("a"), anchor("y"), plain("b")}, false, false},
		"anchors in two places":                              {[]nearToken{plain("a"), anchor("x"), plain("b")}, []nearToken{plain("a"), plain("b"), anchor("y")}, true, false},
		"plain token for an anchor":                          {[]nearToken{plain("a"), plain("p"), plain("b")}, []nearToken{plain("a"), anchor("y"), plain("b")}, true, false},
		"anchor for a plain token":                           {[]nearToken{plain("a"), anchor("x"), plain("b")}, []nearToken{plain("a"), plain("q"), plain("b")}, true, false},
		"anchor and a plain token for an anchor":             {[]nearToken{plain("a"), anchor("x"), plain("p"), plain("b")}, []nearToken{plain("a"), anchor("y"), plain("b")}, false, false},
		"anchor for an anchor and a plain token":             {[]nearToken{plain("a"), anchor("x"), plain("b")}, []nearToken{plain("a"), anchor("y"), plain("q"), plain("b")}, false, false},
		"a variable in two places":                           {[]nearToken{plain("a"), local(0), plain("b"), plain("c")}, []nearToken{plain("a"), plain("b"), local(0), plain("c")}, true, false},
		"one anchor in two places":                           {[]nearToken{plain("a"), anchor("x"), plain("b"), plain("c")}, []nearToken{plain("a"), plain("b"), anchor("x"), plain("c")}, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			m := &roleMapping{forward: map[int]int{}, back: map[int]int{}}
			if tc.paired {
				require.True(t, m.pair(0, 0))
			}
			roles := []nearRole{{Parent: -1}}
			assert.Equal(t, tc.same, m.sameRest(restSide{tokens: tc.lib, roles: roles}, restSide{tokens: tc.own, roles: roles}))
		})
	}
}

// tsHeldStatements prints the statements of the first function of a
// TypeScript source, each with the number of statements that hold it and
// its tokens but braces and semicolons, which tell nothing of what holds it.
func tsHeldStatements(t *testing.T, source string) []string {
	t.Helper()
	src := parseTSSource(strings.Split(source, "\n"))
	require.NotEmpty(t, src.funcs)
	body := src.tsNearBody(src.funcs[0], true)
	texts := make([][]string, len(body.Roles))
	for i, owner := range body.Owners {
		if owner >= 0 && !slices.Contains([]string{"{", "}", ";"}, body.Tokens[i]) {
			texts[owner] = append(texts[owner], body.Tokens[i])
		}
	}
	var out []string
	for i, role := range body.Roles {
		if len(texts[i]) == 0 {
			continue
		}
		depth := 0
		for p := role.Parent; p >= 0; p = body.Roles[p].Parent {
			depth++
		}
		out = append(out, fmt.Sprintf("%d %s", depth, strings.Join(texts[i], " ")))
	}
	return out
}

// A statement a check, a loop or an else holds without braces is held as in
// braces, on the line of the check or the next; the while that ends a do
// loop and the semicolons of a for loop hold nothing.
func TestTSNearBodyHoldsStatementsWithoutBraces(t *testing.T) {
	for name, tc := range map[string]struct{ line, braces string }{
		"check": {`function f(a: boolean, x: number) {
  if (a) x = 1
  return x
}`, `function f(a: boolean, x: number) {
  if (a) {
    x = 1
  }
  return x
}`},
		"check and else": {`function f(a: boolean, x: number) {
  if (a) x = 1
  else x = 2
  return x
}`, `function f(a: boolean, x: number) {
  if (a) {
    x = 1
  } else {
    x = 2
  }
  return x
}`},
		"else if": {`function f(a: boolean, b: boolean, x: number) {
  if (a) x = 1
  else if (b) x = 2
  return x
}`, `function f(a: boolean, b: boolean, x: number) {
  if (a) {
    x = 1
  } else if (b) {
    x = 2
  }
  return x
}`},
		"statement on the next line": {`function f(a: boolean, x: number) {
  if (a)
    x = 1
  return x
}`, `function f(a: boolean, x: number) {
  if (a) {
    x = 1
  }
  return x
}`},
		"loops": {`function f(xs: number[], n: number) {
  const out: number[] = []
  for (const v of xs) out.push(v)
  for (let i = 0; i < n; i++) out.push(i)
  while (n > 0) n--
  return out
}`, `function f(xs: number[], n: number) {
  const out: number[] = []
  for (const v of xs) {
    out.push(v)
  }
  for (let i = 0; i < n; i++) {
    out.push(i)
  }
  while (n > 0) {
    n--
  }
  return out
}`},
		"check in braces closed on its line": {`function f(a: boolean, b: boolean, x: number) {
  if (a) { if (b) x = 1 }
  return x
}`, `function f(a: boolean, b: boolean, x: number) {
  if (a) { if (b) { x = 1 } }
  return x
}`},
		"loop held without braces": {`function f(a: boolean, xs: number[]) {
  const out: number[] = []
  if (a) for (const v of xs) { out.push(v) }
  return out
}`, `function f(a: boolean, xs: number[]) {
  const out: number[] = []
  if (a) { for (const v of xs) { out.push(v) } }
  return out
}`},
		"do loop": {`function f(x: number) {
  do {
    x++
  } while (x < 3)
  return x
}`, `function f(x: number) {
  do {
    x++
  } while (x < 3);
  return x
}`},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tsHeldStatements(t, tc.braces), tsHeldStatements(t, tc.line))
		})
	}
}

// The header of a for loop is one statement, its semicolons and all.
func TestTSNearBodyKeepsTheHeaderOfALoop(t *testing.T) {
	assert.Equal(t, []string{"0 for ( let $L = 0 $L < $L $L ++ )", "1 $L += $L", "0 return $L"}, tsHeldStatements(t, `function f(n: number, s: number) {
  for (let i = 0; i < n; i++) s += i
  return s
}`))
}
