package duplication

import (
	"math/rand/v2"
	"os"
	"path/filepath"
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

func nearLibraryFindings(t *testing.T, libSource, source string) []*core.Violation {
	t.Helper()
	return nearLibraryFilesFindings(t, map[string]string{"lib.go": libSource}, source)
}

func nearLibraryFilesFindings(t *testing.T, libFiles map[string]string, source string) []*core.Violation {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
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
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	writeLibraryTestModule(t, filepath.Join(root, "library"), "example.com/owner/lib", map[string]string{
		"lib.go":                     libraryReferenceSource,
		"ts/amount.ts":               libraryReferenceTS,
		"ts/set.ts":                  librarySetTS,
		"ts/account.ts":              libraryAccountTS,
		"ts/transfer.ts":             libraryTransferTS,
		"ts/limit.ts":                libraryLimitTS,
		"ts/cents.ts":                libraryCentsTS,
		"node_modules/fees/index.ts": libraryDependencyTS,
		"package.json":               `{"name": "@owner/lib"}`,
	})
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
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
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
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
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
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
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
